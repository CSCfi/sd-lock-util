"""Functions for accessing openstack."""

import asyncio
import logging
import os
import time
import typing

import aiofiles
import nacl.bindings
import nacl.exceptions

import sd_lock_utility.exceptions
import sd_lock_utility.types

LOGGER = logging.getLogger("sd-lock-util")


async def openstack_get_token(session: sd_lock_utility.types.SDAPISession) -> str:
    """Fetch a valid token for accessing Openstack."""
    if (
        not session["openstack_token"]
        or session["openstack_token_valid_until"] < time.time()
    ):
        LOGGER.debug("Token does not exist or is expired, refreshing...")

        # The token will be valid for 8 hours (28800 seconds)
        session["openstack_token_valid_until"] = time.time() + 28800
        async with session["client"].post(
            f"{session['openstack_auth_url']}/auth/tokens",
            json={
                "auth": {
                    "identity": {
                        "methods": [
                            "password",
                        ],
                        "password": {
                            "user": {
                                "name": session["openstack_username"],
                                "domain": {
                                    "name": session["openstack_user_domain"],
                                },
                                "password": session["openstack_password"],
                            },
                        },
                    },
                    "scope": {
                        "project": {
                            "id": session["openstack_project_id"],
                        },
                    },
                },
            },
        ) as resp:
            session["openstack_token"] = resp.headers["X-Subject-Token"]

            # Cache the endpoint information from the token
            token_meta = await resp.json()
            session["openstack_object_storage_endpoint"] = [
                list(filter(lambda i: i["interface"] == "public", i["endpoints"]))[0]
                for i in filter(
                    lambda i: i["type"] == "object-store", token_meta["token"]["catalog"]
                )
            ][0]["url"]
            LOGGER.debug(
                f"Using {session['openstack_object_storage_endpoint']} as the object storage endpoint."
            )

    return session["openstack_token"]


async def slice_encrypted_segment(
    opts: sd_lock_utility.types.SDLockOptions,
    file: sd_lock_utility.types.SDUtilFile,
    order: int,
) -> typing.AsyncGenerator[bytes, None]:
    """Slice a file into an async generator of encrypted chunks."""
    size: int = os.stat(file["localpath"]).st_size
    done: int = 5366415360 * order
    async with aiofiles.open(file["localpath"], "rb") as f:
        await f.seek(done)
        for _ in range(0, 81885):
            chunk = await f.read(65536)
            if not chunk:
                return
            if opts["progress"]:
                print(f"{file['localpath']}        {done}/{size}", end="\r")
            nonce = os.urandom(12)
            segment = nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
                chunk,
                None,
                nonce,
                file["session_key"],
            )
            done += len(chunk)
            yield nonce + segment


async def openstack_check_container(
    session: sd_lock_utility.types.SDAPISession, container: str
) -> None:
    """Check the container can be accessed."""
    async with session["client"].head(
        f"{session['openstack_object_storage_endpoint']}/{container}",
        headers={
            "Content-Length": "0",
            "X-Auth-Token": await openstack_get_token(session),
        },
        raise_for_status=False,
    ) as resp:
        if resp.status != 204:
            raise sd_lock_utility.exceptions.NoContainerAccess


async def openstack_create_container(session: sd_lock_utility.types.SDAPISession) -> None:
    """Ensure the upload container exists."""
    for container in {session["container"], f"{session['container']}_segments"}:
        try:
            await openstack_check_container(session, container)
        except sd_lock_utility.exceptions.NoContainerAccess:
            async with session["client"].put(
                f"{session['openstack_object_storage_endpoint']}/{container}",
                headers={
                    "Content-Length": "0",
                    "X-Auth-Token": await openstack_get_token(session),
                },
            ) as resp_put:
                if resp_put.status not in {201, 202}:
                    raise sd_lock_utility.exceptions.ContainerCreationFailed


async def openstack_upload_encrypted_segment(
    opts: sd_lock_utility.types.SDLockOptions,
    session: sd_lock_utility.types.SDAPISession,
    file: sd_lock_utility.types.SDUtilFile,
    order: int,
    uuid: str,
) -> None:
    """Encrypt and upload a segment to object storage."""
    await openstack_create_container(session)

    async with session["client"].put(
        f"{session['openstack_object_storage_endpoint']}/{session['container']}_segments/{file['path']}.c4gh/{uuid}/{(order + 1):08d}",
        data=slice_encrypted_segment(opts, file, order),
        headers={
            "X-Auth-Token": await openstack_get_token(session),
        },
    ) as resp:
        LOGGER.debug(f"File {file['path']} segment {order} return was {resp}")


async def openstack_create_manifest(
    session: sd_lock_utility.types.SDAPISession,
    file: sd_lock_utility.types.SDUtilFile,
    uuid: str,
) -> None:
    """Create encrypted file manifest."""
    async with session["client"].put(
        f"{session['openstack_object_storage_endpoint']}/{session['container']}/{file['path']}.c4gh",
        data=b"",
        headers={
            "X-Auth-Token": await openstack_get_token(session),
            "X-Object-Manifest": f"{session['container']}_segments/{file['path']}.c4gh/{uuid}/",
            "Content-Length": "0",
        },
    ) as _:
        pass


async def get_container_objects_page(
    session: sd_lock_utility.types.SDAPISession,
    marker: str = "",
    prefix: str = "",
) -> list[str]:
    """Get a single page of the container object listing."""
    params = {
        "format": "json",
    }
    if marker:
        params["marker"] = marker
    if prefix:
        params["prefix"] = prefix

    async with session["client"].get(
        f"{session['openstack_object_storage_endpoint']}/{session['container']}",
        headers={
            "X-Auth-Token": await openstack_get_token(session),
        },
        params=params,
    ) as resp:
        objects: list[sd_lock_utility.types.OpenstackObjectListingItem] = (
            await resp.json()
        )
        return [obj["name"] for obj in objects]


async def get_container_objects(
    session: sd_lock_utility.types.SDAPISession,
    prefix: str = "",
) -> list[tuple[str, list[str], list[str]]]:
    """Get the contents of a container in object storage."""
    ret: list[str] = []

    page = await get_container_objects_page(session, prefix=prefix)
    while len(page):
        ret = ret + page
        page = await get_container_objects_page(session, marker=page[-1], prefix=prefix)

    LOGGER.debug(f"Object listing in container {session['container']}: {ret}")

    return [("", [], ret)]


async def openstack_download_decrypted_object(
    opts: sd_lock_utility.types.SDUnlockOptions,
    session: sd_lock_utility.types.SDAPISession,
    file: sd_lock_utility.types.SDUtilFile,
) -> None:
    """Download and decrypt a segment from object storage."""
    async with session["client"].get(
        f"{session['openstack_object_storage_endpoint']}/{session['container']}/{file['path']}.c4gh",
        headers={
            "X-Auth-Token": await openstack_get_token(session),
        },
    ) as resp:
        size: int = int(resp.headers["Content-Length"])
        done: int = 0
        async with aiofiles.open(file["localpath"], "wb") as out_f:
            while True:
                if opts["progress"]:
                    print(f"{file['localpath']}        {done}/{size}", end="\r")

                try:
                    chunk = await resp.content.readexactly(65564)
                except asyncio.IncompleteReadError as incomplete:
                    chunk = incomplete.partial

                if not chunk:
                    return

                nonce = chunk[:12]
                content = chunk[12:]

                await out_f.write(
                    nacl.bindings.crypto_aead_chacha20poly1305_ietf_decrypt(
                        content,
                        None,
                        nonce,
                        file["session_key"],
                    )
                )
                done += len(chunk)
