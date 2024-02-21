"""Folder lock operation."""


import io
import logging
import os
import pathlib

import crypt4gh.header
import crypt4gh.lib
import nacl.bindings
import nacl.exceptions
import nacl.public

import sd_lock_utility.client
import sd_lock_utility.os_client
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

    # Generate an ephemeral keypair
    privkey = nacl.public.PrivateKey.generate()
    LOGGER.info("Whitelisting public key temporarily for decryption...")
    await sd_lock_utility.client.whitelist_key(session, privkey.public_key.encode())  # type: ignore

    # Pre-fetch the token to make the object storage API endpoint defined
    if not opts["no_content_download"]:
        LOGGER.debug("Authenticating with Openstack.")
        await sd_lock_utility.os_client.openstack_get_token(session)

    # Get all files in the path
    LOGGER.info("Gathering a list of files...")
    enfiles: list[sd_lock_utility.types.SDUtilFile] = []

    files_to_decrypt: list[tuple[str, list[str], list[str]]] = []
    if not opts["no_content_download"] and not opts["path"]:
        LOGGER.info("Fetching file listing from object storage...")
        files_to_decrypt = await sd_lock_utility.os_client.get_container_objects(
            session,
            opts["prefix"],
        )
    elif os.path.isfile(opts["path"]) or (
        not opts["no_content_download"] and opts["path"]
    ):
        LOGGER.debug("Creating a dummylist with the single provided file.")
        files_to_decrypt = [("", [], [opts["path"]])]
    else:
        LOGGER.debug("Walking through the path to get a list of files.")
        files_to_decrypt = list(os.walk(opts["path"]))

    for root, _, files in files_to_decrypt:
        for file in files:
            # Fetch and parse the file header
            if root:
                path: str = root + "/" + file
            else:
                path = file
            if ".c4gh" not in file:
                LOGGER.info(f"Skipping file {path} due to not being an encrypted file.")
                continue
            # If not downloading content, and got a prefix, use prefix when
            # fetching the header
            if opts["prefix"] and opts["no_content_download"]:
                path = opts["prefix"] + path

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

            LOGGER.debug(f"Adding file {to_add} for decryption.")
            LOGGER.debug(f"Using {to_add['session_key']!r} as the session key.")

            enfiles.append(to_add)

    # Pop the temporary key from whitelist
    LOGGER.info("Removing temporary download key from whitelist.")
    await sd_lock_utility.client.unlist_key(session)

    for enfile in enfiles:
        if opts["no_content_download"]:
            size: int = os.stat(enfile["localpath"] + ".c4gh").st_size
            done: int = 0
            with open(enfile["localpath"] + ".c4gh", "rb") as f:
                with open(enfile["localpath"], "wb") as out_f:
                    while chunk := f.read(65564):
                        if opts["progress"]:
                            print(f"{enfile['localpath']}        {done}/{size}", end="\r")

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
                            LOGGER.error(f"Could not decrypt {enfile['localpath']}")
                            break
                        done += len(chunk)
        else:
            try:
                await sd_lock_utility.os_client.openstack_download_decrypted_object(
                    opts, session, enfile
                )
            except nacl.exceptions.CryptoError:
                LOGGER.error(f"Could not decrypt {enfile['localpath']}")
        LOGGER.info(f"Decrypted {enfile['localpath']}")

    # Remove originals if required
    if opts["no_preserve_original"] and not opts["no_content_download"]:
        for enfile in enfiles:
            os.remove(enfile["localpath"] + ".c4gh")

    return await sd_lock_utility.client.kill_session(session, 0)
