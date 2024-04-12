"""Folder lock operation."""

import base64
import os
import secrets
import typing

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
    for object_segment in range(0, -(-size // 5366415360)):
        await sd_lock_utility.os_client.openstack_upload_encrypted_segment(
            opts,
            session,
            enfile,
            object_segment,
            segments_uuid,
            bar,
        )

    await sd_lock_utility.os_client.openstack_create_manifest(
        session, enfile, segments_uuid
    )

    return 0


async def lock(opts: sd_lock_utility.types.SDLockOptions) -> int:
    """Lock an unencrypted folder."""
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

    # Get the public key used in uploading
    pubkey_str = await sd_lock_utility.client.get_public_key(session)
    if not pubkey_str:
        click.echo("Could not access project public key for encryption.", err=True)
        return await sd_lock_utility.client.kill_session(session, 5)
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
            sd_lock_utility.common.conditional_echo_verbose(
                opts, f"Removing {enfile['localpath']}"
            )
            os.remove(enfile["localpath"])

    return await sd_lock_utility.client.kill_session(session, 0)


async def get_pubkey(opts: sd_lock_utility.types.SDCommandBaseOptions):
    """Fetch and display the project public key."""
    session = await sd_lock_utility.client.open_session(
        container=opts["container"],
        address=opts["sd_connect_address"],
        project_id=opts["project_id"],
        project_name=opts["project_name"],
        token=opts["sd_api_token"],
        os_auth_url=opts["openstack_auth_url"],
        no_check_certificate=opts["no_check_certificate"],
    )

    pubkey = await sd_lock_utility.client.get_public_key(session)
    click.echo("-----BEGIN CRYPT4GH PUBLIC KEY-----")
    click.echo(pubkey)
    click.echo("-----END CRYPT4GH PUBLIC KEY-----")

    return await sd_lock_utility.client.kill_session(session, 0)
