"""Folder lock operation."""


import os

import sd_lock_utility.client


async def unlock(path: str, container: str):
    """."""
    session = await sd_lock_utility.client.open_session(container=container)

    pubkey, privkey = None  # Create ephemeral keypair
    await sd_lock_utility.client.whitelist_key(session, pubkey)

    if os.path.isfile(path):
        print("Operations on single files not yet supported.")
        return 2

    # Get all files in the path
    files = []
    for root, dir, files in os.walk(path):
        [files.append({
            "path": (root + file).replace(".c4gh", ""),
        }) for file in files]

    # Get headers for all files in the path and decrypt
    for file in files:
        file["header"] = await sd_lock_utility.client.get_header(session, f"{file["path"]}.c4gh")

        file["session_key"] = "parse_header" # TODO: parse the header from vault with c4gh

        # TODO: DECRYPT the file body with crypt4gh here, save to path
        os.unlink(f'{file["path"]}.c4gh')  # remove the original

    return
