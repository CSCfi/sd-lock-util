"""Folder lock operation."""


import os

import sd_lock_utility.client


async def lock(path: str, container: str):
    """."""
    session = await sd_lock_utility.client.open_session(container=container)
    pubkey = await sd_lock_utility.client.get_public_key(session)

    if os.path.isfile(path):
        print("Operations on single files not yet supported.")
        return 2

    # Get all files in the path
    files = []
    for root, dir, files in os.walk(path):
        [files.append({
            "path": root + file,
            "session_key": None,  # Generate crypt4gh session key here
            "private_key": None,  # ephemeral private key here
            "public_key": pubkey,
        }) for file in files]

    # Upload headers for all files in the path
    for file in files:
        await sd_lock_utility.client.push_header(
            session, "header", f'{file["path"]}.c4gh',  # Build header with crypt4gh library
        )
        # TODO: encrypt the file body with crypt4gh here, save to name + .c4gh
        os.unlink(file["path"])  # remove the original

    return
