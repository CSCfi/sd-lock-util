"""Folder lock operation."""


import os
import io
import logging

import nacl.bindings
import nacl.public
import nacl.exceptions

import crypt4gh.header
import crypt4gh.lib

import sd_lock_utility.client
import sd_lock_utility.types


LOGGER = logging.getLogger("sd-lock-util")


async def unlock(opts: sd_lock_utility.types.SDUnlockOptions):
    """Unlock an encrypted folder."""
    session = await sd_lock_utility.client.open_session(
        container=opts["container"],
        address=opts["sd_connect_address"],
        project_id=opts["project_id"],
        project_name=opts["project_name"],
        token=opts["sd_api_token"],
        os_auth_url=opts["openstack_auth_url"],
        no_check_certificate=opts["no_check_certificate"],
    )

    if os.path.isfile(opts["path"]):
        LOGGER.error("Operations on single files not yet supported.")
        return await sd_lock_utility.client.kill_session(session, 2)

    # Generate an ephemeral keypair
    privkey = nacl.public.PrivateKey.generate()
    LOGGER.info("Whitelisting public key temporarily for decryption...")
    await sd_lock_utility.client.whitelist_key(session, privkey.public_key.encode())  # type: ignore

    if not opts["no_content_download"]:
        LOGGER.error("Direct download is not yet supported.")
        return await sd_lock_utility.client.kill_session(session, 3)

    # Get all files in the path
    LOGGER.info("Gathering a list of files...")
    enfiles: list[sd_lock_utility.types.SDUtilFile] = []
    for root, _, files in os.walk(opts["path"]):
        for file in files:
            # Fetch and parse the file header
            path: str = root + "/" + file
            if ".c4gh" not in file:
                LOGGER.info(f"Skipping file {path} due to not being an encrypted file.")
                continue
            LOGGER.debug(f"Fetching a re-encrypted header for {path}.")
            header = await sd_lock_utility.client.get_header(session, path)

            if not header:
                LOGGER.error(f"Got no header for {path}.")
                continue

            LOGGER.debug(f"Using following header for {path}: {header!r}")
            header_file = io.BytesIO(header)
            session_keys, _ = crypt4gh.header.deconstruct(
                header_file, [(0, privkey.encode(), None)]
            )

            LOGGER.debug(f"Session keys for {path}: {session_keys}")

            to_add: sd_lock_utility.types.SDUtilFile = {
                "filename": file.replace(".c4gh", ""),
                "prefix": root,
                "path": path.replace(".c4gh", ""),
                "session_key": session_keys[0],
            }

            LOGGER.debug(f"Adding file {to_add} for decryption.")
            LOGGER.debug(f"Using {to_add['session_key']!r} as the session key.")

            enfiles.append(to_add)

    # Pop the temporary key from whitelist
    LOGGER.info("Removing temporary download key from whitelist.")
    await sd_lock_utility.client.unlist_key(session)

    if opts["no_content_download"]:
        for enfile in enfiles:
            size: int = os.stat(enfile["path"] + ".c4gh").st_size
            done: int = 0
            with open(enfile["path"] + ".c4gh", "rb") as f:
                with open(enfile["path"], "wb") as out_f:
                    while chunk := f.read(65564):
                        if opts["progress"]:
                            print(f"{enfile['path']}        {done}/{size}", end="\r")

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
                        except nacl.exceptions.CryptoError:
                            LOGGER.error(f"Could not decrypt {enfile['path']}")
                            break
                        done += len(chunk)
            LOGGER.info(f"Decrypted {enfile['path']}")
    else:
        # TODO: implement direct download
        return await sd_lock_utility.client.kill_session(session, 3)

    # Remove originals if required
    if opts["no_preserve_original"]:
        for enfile in enfiles:
            os.remove(enfile["path"] + ".c4gh")

    return await sd_lock_utility.client.kill_session(session, 0)
