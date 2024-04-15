"""Folder lock operation."""

import asyncio
import base64
import os
import secrets
import typing

import aiohttp
import click
import crypt4gh.header
import nacl.bindings
import nacl.public

import sd_lock_utility.client
import sd_lock_utility.common
import sd_lock_utility.exceptions
import sd_lock_utility.os_client
import sd_lock_utility.types


async def process_file_lock(
    session: sd_lock_utility.types.SDAPISession,
    opts: sd_lock_utility.types.SDLockOptions,
    enfile: sd_lock_utility.types.SDUtilFile,
    size: int,
    bar: typing.Any,
) -> int:
    """Process file lock encryption with optional uploading."""
    # Skip uploading if requested
    if opts["no_content_upload"]:
        with open(enfile["localpath"], "rb") as f:
            with open(f"{enfile['localpath']}.c4gh", "wb") as out_f:
                while chunk := f.read(65536):
                    nonce = os.urandom(12)
                    segment = nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
                        chunk,
                        None,
                        nonce,
                        enfile["session_key"],
                    )
                    out_f.write(nonce)
                    out_f.write(segment)
                    if bar:
                        bar.update(len(chunk))
        return 0

    # Alternatively encrypt and upload the file in a single operation
    segments_uuid: str = secrets.token_urlsafe(32)
    total_segments = -(-size // 5366415360)
    sd_lock_utility.common.conditional_echo_debug(
        opts, f"Uploading the file in {total_segments} segments"
    )
    for object_segment in range(0, total_segments):
        await sd_lock_utility.os_client.openstack_upload_encrypted_segment(
            opts,
            session,
            enfile,
            object_segment,
            segments_uuid,
            bar,
        )

    sd_lock_utility.common.conditional_echo_debug(
        opts, f"Generating a DLO manifest for {enfile['path']}"
    )
    await sd_lock_utility.os_client.openstack_create_manifest(
        session, enfile, segments_uuid
    )

    return 0


async def lock(
    opts: sd_lock_utility.types.SDLockOptions, session: sd_lock_utility.types.SDAPISession
) -> int:
    """Lock an unencrypted folder."""
    # Get the public key used in uploading
    sd_lock_utility.common.conditional_echo_debug(
        opts, "Fetching public key for the upload operation"
    )
    pubkey_str = await sd_lock_utility.client.get_public_key(session)
    if not pubkey_str:
        raise sd_lock_utility.exceptions.NoKey
    pubkey = base64.urlsafe_b64decode(pubkey_str)

    # Get all files in the path
    sd_lock_utility.common.conditional_echo_verbose(opts, "Gathering a list of files...")
    enfiles: list[sd_lock_utility.types.SDUtilFile] = []
    for root, _, files in (
        os.walk(opts["path"])
        if not os.path.isfile(opts["path"])
        else [("", [], [opts["path"]])]
    ):
        for file in files:
            # Create an ephemeral keypair
            session_key = os.urandom(32)
            priv_key_eph = nacl.public.PrivateKey.generate()
            header_content = crypt4gh.header.make_packet_data_enc(0, session_key)
            header_packets = crypt4gh.header.encrypt(
                header_content, [(0, priv_key_eph.encode(), pubkey)]
            )
            header_bytes: bytes = crypt4gh.header.serialize(header_packets)

            to_add: sd_lock_utility.types.SDUtilFile = {
                "path": opts["prefix"] + ((root + "/" + file) if root else file),
                "localpath": (root + "/" + file) if root else file,
                "session_key": session_key,
            }

            sd_lock_utility.common.conditional_echo_debug(
                opts, f"Adding file {to_add} for encryption."
            )

            # Upload the file header
            sd_lock_utility.common.conditional_echo_debug(
                opts, f"Uploading header for {to_add['localpath']} to {to_add['path']}"
            )
            await sd_lock_utility.client.push_header(
                session,
                header_bytes,
                to_add["path"] + ".c4gh",
            )

            enfiles.append(to_add)

    # Pre-fetch the token to make the object storage API endpoint defined
    if not opts["no_content_upload"]:
        sd_lock_utility.common.conditional_echo_debug(
            opts, "Authenticating with Openstack."
        )
        await sd_lock_utility.os_client.openstack_get_token(session)

    for enfile in enfiles:
        size: int = os.stat(enfile["localpath"]).st_size
        # Print progress by default
        if opts["progress"]:
            # Can't annotate progress bar without using click internal vars
            with click.progressbar(  # type: ignore
                length=size, label=f"Processing {enfile['localpath']}"
            ) as bar:
                await process_file_lock(session, opts, enfile, size, bar)
        else:
            await process_file_lock(session, opts, enfile, size, None)

    # Remove original files if required
    if opts["no_preserve_original"]:
        for enfile in enfiles:
            confirm = click.prompt(
                "Original file removal was cheduled after encryption. Do you want to continue with the removal?",
                default="n",
                type=click.Choice(choices=["y", "n"], case_sensitive=False),
                show_default=True,
                show_choices=True,
            )
            if confirm == "y":
                sd_lock_utility.common.conditional_echo_verbose(
                    opts, f"Deleting original file {enfile['localpath']}"
                )
                os.remove(enfile["localpath"])

    return 0


async def wrap_lock_exceptions(opts: sd_lock_utility.types.SDLockOptions) -> int:
    """Wrap the lock operation with required exception handling."""
    try:
        session = await sd_lock_utility.client.open_session(
            container=opts["container"],
            address=opts["sd_connect_address"],
            project_id=opts["project_id"],
            project_name=opts["project_name"],
            token=opts["sd_api_token"],
            os_auth_url=opts["openstack_auth_url"],
            no_check_certificate=opts["no_check_certificate"],
        )
    except sd_lock_utility.exceptions.NoToken:
        click.echo("No API access token was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoAddress:
        click.echo("No API address was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoProject:
        click.echo("No Openstack project information was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoContainer:
        click.echo("No container was provided for uploads.", err=True)
        return 3

    exc: typing.Any = None
    ret = 0
    try:
        async with aiohttp.ClientSession(
            raise_for_status=True,
        ) as cs:
            session["client"] = cs
            ret = await lock(opts, session)
    except asyncio.CancelledError:
        click.echo("Received a keyboard interrupt, aborting...", err=True)
        click.echo("Files that were already uploaded will not be removed.", err=True)
        return 0
    except sd_lock_utility.exceptions.NoKey:
        click.echo("Could not access project public key for encryption.", err=True)
        click.echo("Check that you're using the correct project.", err=True)
    except aiohttp.ClientResponseError as cex:
        if cex.status == 401 and not opts["debug"]:
            click.echo("Authentication was not successful.", err=True)
            click.echo(
                "Check that your SD Connect token is still valid and Openstack credentials are correct.",
                err=True,
            )
        else:
            exc = cex
    except sd_lock_utility.exceptions.ContainerCreationFailed:
        click.echo("Could not create container/bucket for upload.", err=True)
    except Exception as e:
        ret = 42
        exc = e
    finally:
        # Log unhandled exceptions, but don't let them bubble
        if exc is not None:
            click.echo("Program encountered an unhandled exception.", err=True)
            click.echo(
                "If you think there's a mistake, copy this message and lines after it, and include it in your support request for diagnostic purposes.",
                err=True,
            )
            click.echo(
                "If possible, include instructions on how to replicate the issue (what you did in order to make this happen)",
                err=True,
            )
            click.echo("Exception details:", err=True)
            click.echo(
                "-------------------------- BEGIN EXCEPTION TRACEBACK --------------------------"
            )
            raise exc

    return ret


async def get_pubkey(opts: sd_lock_utility.types.SDCommandBaseOptions):
    """Fetch and display the project public key."""
    try:
        session = await sd_lock_utility.client.open_session(
            container=opts["container"],
            address=opts["sd_connect_address"],
            project_id=opts["project_id"],
            project_name=opts["project_name"],
            token=opts["sd_api_token"],
            os_auth_url=opts["openstack_auth_url"],
            no_check_certificate=opts["no_check_certificate"],
        )
    except sd_lock_utility.exceptions.NoToken:
        click.echo("No API access token was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoAddress:
        click.echo("No API address was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoProject:
        click.echo("No Openstack project information was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoContainer:
        click.echo("No container was provided for uploads.", err=True)
        return 3

    exc: typing.Any = None
    ret = 0
    try:
        async with aiohttp.ClientSession(raise_for_status=True) as cs:
            session["client"] = cs
            pubkey = await sd_lock_utility.client.get_public_key(session)
        await asyncio.sleep(0.250)
    except asyncio.CancelledError:
        click.echo("Received a keyboard interrupt, aborting...", err=True)
        return 0
    except aiohttp.ClientResponseError as cex:
        if cex.status == 401 and not opts["debug"]:
            click.echo("Authentication was not successful.", err=True)
            click.echo(
                "Check that your SD Connect token is still valid and Openstack credentials are correct.",
                err=True,
            )
        else:
            exc = cex
    except Exception as e:
        exc = e
    finally:
        if exc is not None:
            click.echo("Program encountered an unhandled exception.", err=True)
            click.echo(
                "If you think there's a mistake, copy this message and lines after it, and include it in your support request for diagnostic purposes.",
                err=True,
            )
            click.echo(
                "If possible, include instructions on how to replicate the issue (what you did in order to make this happen)",
                err=True,
            )
            click.echo("Exception details:", err=True)
            click.echo(
                "-------------------------- BEGIN EXCEPTION TRACEBACK --------------------------"
            )
            raise exc

    click.echo("-----BEGIN CRYPT4GH PUBLIC KEY-----")
    click.echo(pubkey)
    click.echo("-----END CRYPT4GH PUBLIC KEY-----")

    return ret
