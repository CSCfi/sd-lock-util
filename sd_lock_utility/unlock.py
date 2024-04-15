"""Folder lock operation."""

import asyncio
import io
import os
import pathlib
import typing

import aiohttp
import click
import crypt4gh.header
import crypt4gh.lib
import nacl.bindings
import nacl.exceptions
import nacl.public

import sd_lock_utility.client
import sd_lock_utility.common
import sd_lock_utility.os_client
import sd_lock_utility.types


async def process_file_unlock(
    session: sd_lock_utility.types.SDAPISession,
    opts: sd_lock_utility.types.SDUnlockOptions,
    enfile: sd_lock_utility.types.SDUtilFile,
    bar: typing.Any,
) -> int:
    """Process file unlock decryption."""
    sd_lock_utility.common.conditional_echo_debug(
        opts, f"Decrypting file contents for file and saving to {enfile['localpath']}"
    )
    with open(f"{enfile['localpath']}.c4gh", "rb") as f, open(
        enfile["localpath"], "wb"
    ) as out_f:
        while chunk := f.read(65564):
            nonce = chunk[:12]
            content = chunk[12:]

            try:
                out_f.write(
                    nacl.bindings.crypto_aead_chacha20poly1305_ietf_decrypt(
                        content,
                        None,
                        nonce,
                        enfile["session_key"],
                    )
                )
                if bar:
                    bar.update(len(chunk))
            except nacl.exceptions.CryptoError:
                click.echo(f"Could not decrypt {enfile['localpath']}", err=True)
                break

    return 0


async def unlock(
    opts: sd_lock_utility.types.SDUnlockOptions,
    session: sd_lock_utility.types.SDAPISession,
):
    """Unlock an encrypted folder."""
    # Generate an ephemeral keypair
    privkey = nacl.public.PrivateKey.generate()
    sd_lock_utility.common.conditional_echo_verbose(
        opts, "Temporarily whitelisting a public key for decryption..."
    )
    await sd_lock_utility.client.whitelist_key(session, privkey.public_key.encode())  # type: ignore

    # Pre-fetch the token to make the object storage API endpoint defined
    if not opts["no_content_download"]:
        sd_lock_utility.common.conditional_echo_debug(
            opts, "Authenticating with Openstack."
        )
        await sd_lock_utility.os_client.openstack_get_token(session)

    # Get all files in the path
    sd_lock_utility.common.conditional_echo_verbose(opts, "Gathering a list of files...")
    enfiles: list[sd_lock_utility.types.SDUtilFile] = []

    files_to_decrypt: list[tuple[str, list[str], list[str]]] = []
    if not opts["no_content_download"] and not opts["path"]:
        sd_lock_utility.common.conditional_echo_verbose(
            opts, "Fetching a file listing from object storage..."
        )
        files_to_decrypt = await sd_lock_utility.os_client.get_container_objects(
            session,
            opts["prefix"],
        )
    elif os.path.isfile(opts["path"]) or (
        not opts["no_content_download"] and opts["path"]
    ):
        sd_lock_utility.common.conditional_echo_debug(
            opts, "Creating a dummy list for single file download..."
        )
        files_to_decrypt = [("", [], [opts["path"]])]
    else:
        sd_lock_utility.common.conditional_echo_debug(
            opts, "Walking through the path to get a list of files..."
        )
        files_to_decrypt = list(os.walk(opts["path"]))

    sd_lock_utility.common.conditional_echo_debug(
        opts, "Fetching encapsulated decryption keys for file listing."
    )
    try:
        for root, _, files in files_to_decrypt:
            for file in files:
                # Fetch and parse the file header
                if root:
                    path: str = root + "/" + file
                else:
                    path = file
                if ".c4gh" not in file:
                    sd_lock_utility.common.conditional_echo_verbose(
                        opts,
                        f"Skipping file {path} due to it not being an encrypted file.",
                    )
                    continue
                # If not downloading content, and got a prefix, use prefix when
                # fetching the header
                if opts["prefix"] and opts["no_content_download"]:
                    path = opts["prefix"] + path

                sd_lock_utility.common.conditional_echo_debug(
                    opts, f"Fetching a re-encrypted header for {path}."
                )
                header = await sd_lock_utility.client.get_header(session, path)

                if not header:
                    click.echo(f"Found no header for {path}.", err=True)
                    continue

                header_file = io.BytesIO(header)
                session_keys, _ = crypt4gh.header.deconstruct(
                    header_file, [(0, privkey.encode(), None)]
                )

                sd_lock_utility.common.conditional_echo_debug(
                    opts, f"Available session keys for {path}: {len(session_keys)}"
                )

                # We'll have to create the prefix separately even though os.walkdir
                # gives it for us, due to openstack return missing precalculated
                # prefixes
                # Ensure necessary directories exist
                prefix: str = path.replace(path.split("/")[-1], "").rstrip("/")
                # Don't create the preceding folders if using a pseudofolder
                if opts["prefix"]:
                    prefix = prefix.replace(opts["prefix"].rstrip("/"), "")
                pathlib.Path(prefix).mkdir(parents=True, exist_ok=True)

                to_add: sd_lock_utility.types.SDUtilFile = {
                    "path": path.replace(".c4gh", ""),
                    "localpath": path.replace(".c4gh", "").replace(opts["prefix"], ""),
                    "session_key": session_keys[0],
                }

                sd_lock_utility.common.conditional_echo_debug(
                    opts, f"Adding file {to_add} for decryption."
                )

                enfiles.append(to_add)
    finally:
        # Pop the temporary key from whitelist
        sd_lock_utility.common.conditional_echo_verbose(
            opts, "Removing temporary download key from whitelist."
        )
        await sd_lock_utility.client.unlist_key(session)

    for enfile in enfiles:
        if opts["no_content_download"]:
            size: int = os.stat(f"{enfile['localpath']}.c4gh").st_size
            if opts["progress"]:
                # Can't annotate progress bar without using click internal vars
                with click.progressbar(  # type: ignore
                    length=size, label=f"Decrypting {enfile['localpath']}.c4gh"
                ) as bar:
                    await process_file_unlock(session, opts, enfile, bar)
            else:
                await process_file_unlock(session, opts, enfile, None)
        else:
            try:
                await sd_lock_utility.os_client.openstack_download_decrypted_object_wrap_progress(
                    opts, session, enfile
                )
            except nacl.exceptions.CryptoError:
                click.echo(f"Could not decrypt {enfile['localpath']}", err=True)
        sd_lock_utility.common.conditional_echo_verbose(
            opts, f"Decrypted {enfile['localpath']}"
        )

    # Remove originals if required
    if opts["no_preserve_original"] and not opts["no_content_download"]:
        confirm = click.prompt(
            "Original file removal was scheduled after decryption. Do you want to continue with the removal?",
            default="n",
            type=click.Choice(choices=["y", "n"], case_sensitive=False),
            show_default=True,
            show_choices=True,
        )
        if confirm == "y":
            for enfile in enfiles:
                sd_lock_utility.common.conditional_echo_verbose(
                    opts, f"Deleting original file {enfile['localpath']}.c4gh"
                )
                os.remove(enfile["localpath"] + ".c4gh")

    return 0


async def wrap_unlock_exceptions(opts: sd_lock_utility.types.SDUnlockOptions) -> int:
    """Wrap the unlock operation with required exception handling."""
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
            ret = await unlock(opts, session)
        await asyncio.sleep(0.250)
    except asyncio.CancelledError:
        click.echo("Received a keyboard interrupt, aborting...", err=True)
        click.echo("Files that were already downloaded will not be removed.", err=True)
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
        # Log unhandled exceptions but don't let them bubble
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
