"""SD Connect vault proxy API client."""


import os
import typing
import base64

import aiohttp

import swift_browser_ui.common.signature

import sd_lock_utility.exceptions


class SDAPISession(typing.TypedDict):
    """Type definition for session variables."""

    client: aiohttp.ClientSession
    token: str
    address: str
    project: str
    container: str


class SDAPISignature(typing.TypedDict, total=False):
    """Type definition for SD API signature."""

    valid: int
    signature: str
    nosession: str
    flavor: str


async def open_session(
    token: str = "",
    address: str = "",
    project: str = "",
    container: str = "",
) -> SDAPISession:
    """Open a new session for accessing SD API."""
    ret: SDAPISession = {
        "client": aiohttp.ClientSession(),
        "token": token
        if token
        else os.environ.get(
            "SWIFT_API_TOKEN",
            "",
        ),
        "address": address
        if address
        else os.environ.get(
            "SWIFT_API_ADDRESS",
            "",
        ),
        "project": project
        if project
        else os.environ.get(
            "OS_PROJECT_ID",
            "",
        ),
        "container": container
        if container
        else os.environ.get(
            "UPLOAD_CONTAINER",
            "",
        ),
    }

    if not ret["token"]:
        raise sd_lock_utility.exceptions.NoToken

    if not ret["address"]:
        raise sd_lock_utility.exceptions.NoAddress

    if not ret["project"]:
        raise sd_lock_utility.exceptions.NoProject

    return ret


async def get_signature(
    session: SDAPISession,
    path: str,
    duration: int = 3600,
) -> SDAPISignature:
    """Sign an API request."""
    ret: SDAPISignature = swift_browser_ui.common.signature.sign_api_request(
        path,
        duration,
        session["token"],
    )

    return ret


async def whitelist_key(session: SDAPISession, key: bytes):
    """Whitelist a public key for bucket."""
    path: str = f"/cryptic/{session['project']}/whitelist"
    signature: SDAPISignature = await get_signature(session, path)

    signature.update(
        {
            "flavor": "crypt4gh",
        }
    )

    async with session["client"].put(
        f"{session['address']}{path}",
        query=signature,
        data=key,
    ) as resp:
        if resp.status not in {200, 201, 204}:
            raise sd_lock_utility.exceptions.NoWhitelistAccess


async def unlist_key(session: SDAPISession):
    """Remove a public key from bucket whitelist."""
    path: str = f"/cryptic/{session['project']}/whitelist"
    signature: SDAPISignature = await get_signature(session, path)

    async with session["client"].delete(
        f"{session['address']}{path}",
        query=signature,
    ) as resp:
        if resp.status not in {200, 201, 204}:
            raise sd_lock_utility.exceptions.NoWhitelistAccess


async def get_public_key(session: SDAPISession) -> bytes:
    """Get project public key from SD API for encryption."""
    path: str = f"/cryptic/{session['project']}/keys"
    signature: SDAPISignature = await get_signature(session, path)

    ret = b""

    async with session["client"].get(
        f"{session['address']}{path}",
        query=signature,
    ) as resp:
        if resp.status not in {200, 201, 204}:
            raise sd_lock_utility.exceptions.NoKey
        ret = base64.urlsafe_b64decode(await resp.text())

    if not ret:
        raise sd_lock_utility.exceptions.NoKey

    return ret


async def push_header(session: SDAPISession, header: bytes, filepath: str):
    """Push a file header to SD API."""
    path: str = f"/cryptic/{session['project']}/files/{session['container']}/{filepath}"
    signature: SDAPISignature = await get_signature(session, path)
    signature.update(
        {
            "nosession": "True",
        }
    )

    async with session["client"].put(
        f"{session['address']}{path}",
        query=signature,
        data=header,
    ) as resp:
        if resp.status not in {200, 201, 204}:
            raise sd_lock_utility.exceptions.NoHeaderPushAccess


async def get_header(session: SDAPISession, filepath: str) -> bytes:
    """Get a file header from SD API."""
    path: str = f"/cryptic/{session['project']}/files/{session['container']}/{filepath}"
    signature: SDAPISignature = await get_signature(session, path)

    ret: bytes = b""

    async with session["client"].get(
        f"{session['address']}{path}",
        query=signature,
    ) as resp:
        if resp.status != 200:
            raise sd_lock_utility.exceptions.NoFileHeader
        ret = base64.urlsafe_b64decode(await resp.text())

    return ret
