"""Folder lock operation."""

import base64
import logging
import os
import secrets

import crypt4gh.header
import nacl.bindings
import nacl.public

import sd_lock_utility.client
import sd_lock_utility.os_client
import sd_lock_utility.types

LOGGER = logging.getLogger("sd-lock-util")


async def lock(opts: sd_lock_utility.types.SDLockOptions) -> int:
    """Lock an unencrypted folder."""
    session = await sd_lock_utility.client.open_session(
        container=opts["container"],
        address=opts["sd_connect_address"],
        project_id=opts["project_id"],
        project_name=opts["project_name"],
        token=opts["sd_api_token"],
        os_auth_url=opts["openstack_auth_url"],
        no_check_certificate=opts["no_check_certificate"],
    )

    # Get the public key used in uploading
    pubkey_str = await sd_lock_utility.client.get_public_key(session)
    if not pubkey_str:
        LOGGER.error("Could not access project public key for encryption.")
        return await sd_lock_utility.client.kill_session(session, 5)
    pubkey = base64.urlsafe_b64decode(pubkey_str)

    # Get all files in the path
    LOGGER.info("Gathering a list of files...")
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

            LOGGER.debug(f"Adding file {to_add} for encryption.")

            # Upload the file header
            LOGGER.debug(
                f"Uploading header for ${to_add['localpath']} to {to_add['path']}"
            )
            await sd_lock_utility.client.push_header(
                session,
                header_bytes,
                to_add["path"] + ".c4gh",
            )

            enfiles.append(to_add)

    # Pre-fetch the token to make the object storage API endpoint defined
    if not opts["no_content_upload"]:
        LOGGER.debug("Authenticating with Openstack.")
        await sd_lock_utility.os_client.openstack_get_token(session)

    for enfile in enfiles:
        size: int = os.stat(enfile["localpath"]).st_size
        # Only encrypt if requested
        if opts["no_content_upload"]:
            for enfile in enfiles:
                done: int = 0
                with open(enfile["localpath"], "rb") as f:
                    with open(f"{enfile['localpath']}.c4gh", "wb") as out_f:
                        while chunk := f.read(65536):
                            if opts["progress"]:
                                print(
                                    f"{enfile['localpath']}        {done}/{size}",
                                    end="\r",
                                )

                            nonce = os.urandom(12)
                            segment = (
                                nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
                                    chunk,
                                    None,
                                    nonce,
                                    enfile["session_key"],
                                )
                            )
                            out_f.write(nonce)
                            out_f.write(segment)
                            done += len(chunk)
                LOGGER.info(f"Encrypted {enfile['localpath']}")
        # Otherwise upload the contents to object storage
        else:
            # 5366415360 is the largest size that can fit to 5GiB after encryption overhead
            # Start counting segment numbers from 1 for backwards compatibility
            segments_uuid: str = secrets.token_urlsafe(32)
            for object_segment in range(0, -(-size // 5366415360)):
                await sd_lock_utility.os_client.openstack_upload_encrypted_segment(
                    opts, session, enfile, object_segment, segments_uuid
                )

            await sd_lock_utility.os_client.openstack_create_manifest(
                session, enfile, segments_uuid
            )
            LOGGER.info(f"Encrypted and uploaded {enfile['localpath']}")

    # Remove original files if required
    if opts["no_preserve_original"]:
        for enfile in enfiles:
            LOGGER.info(f"Removing {enfile['localpath']}")
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
    print("-----BEGIN CRYPT4GH PUBLIC KEY-----")
    print(pubkey)
    print("-----END CRYPT4GH PUBLIC KEY-----")

    return await sd_lock_utility.client.kill_session(session, 0)
