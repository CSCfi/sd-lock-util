"""SD Connect vault proxy API client."""

import base64
import hmac
import json
import os
import pathlib
import time
import typing

import aiohttp

import sd_lock_utility.exceptions
import sd_lock_utility.types


def _sign_api_request(
    path: str, valid_for: int = 3600, key: bytes = b""
) -> sd_lock_utility.types.SDAPISignature:
    """Handle authentication with a signature."""
    valid_until = int(time.time() + valid_for)
    to_sign = (str(valid_until) + path).encode("utf-8")

    digest = hmac.new(
        key=key,
        msg=to_sign,
        digestmod="sha256",
    ).hexdigest()

    return {
        "valid": valid_until,
        "signature": digest,
    }


async def open_session(
    token: str = "",
    address: str = "",
    project_id: str = "",
    project_name: str = "",
    container: str = "",
    os_auth_url: str = "",
    owner: str = "",
    owner_name: str = "",
    no_check_certificate: bool = False,
) -> sd_lock_utility.types.SDAPISession:
    """Open a new session for accessing SD API."""
    # Use a default timeout of 28800 to match the token lifetime.
    aiohttp.ClientTimeout(
        total=1,
        connect=240,
        sock_connect=60,
        sock_read=600,
    )

    ret: sd_lock_utility.types.SDAPISession = {
        "client": None,
        "token": (
            token.encode("utf-8")
            if token
            else os.environ.get(
                "SD_CONNECT_API_TOKEN",
                "",
            ).encode("utf-8")
        ),
        "owner": (
            owner
            if owner
            else os.environ.get(
                "SD_BUCKET_OWNER",
                "",
            )
        ),
        "owner_name": (
            owner_name
            if owner_name
            else os.environ.get(
                "SD_BUCKET_OWNER_NAME",
                "",
            )
        ),
        "address": (
            address
            if address
            else os.environ.get(
                "SD_CONNECT_API_ADDRESS",
                "",
            )
        ),
        "openstack_project_id": (
            project_id
            if project_id
            else os.environ.get(
                "OS_PROJECT_ID",
                "",
            )
        ),
        "openstack_project_name": (
            project_name
            if project_name
            else os.environ.get(
                "OS_PROJECT_NAME",
                "",
            )
        ),
        "openstack_auth_url": (
            os_auth_url
            if os_auth_url
            else os.environ.get(
                "OS_AUTH_URL",
                "",
            )
        ),
        "container": (
            container
            if container
            else os.environ.get(
                "UPLOAD_CONTAINER",
                "",
            )
        ),
        "openstack_password": os.environ.get("OS_PASSWORD", ""),
        "openstack_user_domain": os.environ.get(
            "OS_USER_DOMAIN_NAME",
            "Default",
        ),
        "openstack_username": os.environ.get(
            "OS_USERNAME",
            "",
        ),
        "openstack_region_name": os.environ.get(
            "OS_REGION_NAME",
            "",
        ),
        "openstack_token": os.environ.get(
            "OS_AUTH_TOKEN",
            "",
        ),
        "openstack_object_storage_endpoint": os.environ.get(
            "ALLAS_ENDPOINT",
            "",
        ),
        "no_check_certificate": no_check_certificate,
        "openstack_token_valid_until": 0.0,
    }

    if not ret["token"]:
        raise sd_lock_utility.exceptions.NoToken

    if not ret["address"]:
        raise sd_lock_utility.exceptions.NoAddress

    if not ret["openstack_project_name"]:
        raise sd_lock_utility.exceptions.NoProject

    if not ret["container"]:
        raise sd_lock_utility.exceptions.NoContainer

    return ret


async def signed_fetch(
    session: sd_lock_utility.types.SDAPISession,
    path: str,
    prefix: str = "",
    method: str = "GET",
    params: None | typing.Dict[str, typing.Any] = None,
    json_data: None | typing.Dict[str, typing.Any] = None,
    data: bytes | str | None = None,
    timeout: int = 60,
    duration: int = 3600,
) -> str | None:
    """Wrap fetching with integrated error handling."""
    url = session["address"] + prefix + path
    signature: sd_lock_utility.types.SDAPISignature = _sign_api_request(
        path,
        duration,
        session["token"],
    )

    if params is not None:
        signature.update(params)  # type: ignore

    async with session["client"].request(  # type: ignore
        method=method,
        url=url,
        params=signature,
        json=json_data,
        data=data,
        timeout=aiohttp.client.ClientTimeout(total=timeout),
        ssl=False if session["no_check_certificate"] else None,
    ) as resp:
        if resp.status == 200:
            return await resp.text()

    return None


async def whitelist_key(session: sd_lock_utility.types.SDAPISession, key: bytes) -> None:
    """Whitelist a public key for bucket."""
    await signed_fetch(
        session,
        f"/cryptic/{session['openstack_project_name']}/whitelist",
        prefix="/runner",
        method="PUT",
        params={
            "flavor": "crypt4gh",
        },
        data=key,
    )


async def unlist_key(session: sd_lock_utility.types.SDAPISession) -> None:
    """Remove a public key from bucket whitelist."""
    await signed_fetch(
        session,
        f"/cryptic/{session['openstack_project_name']}/whitelist",
        prefix="/runner",
        method="DELETE",
    )


async def get_public_key(session: sd_lock_utility.types.SDAPISession) -> str:
    """Get project public key from SD API for encryption."""
    await get_shared_ids(session)
    if session["owner_name"]:
        ret = await signed_fetch(
            session,
            f"/cryptic/{session['owner_name']}/keys",
            params={
                "for": session["openstack_project_name"],
            },
            prefix="/runner",
        )
    else:
        ret = await signed_fetch(
            session,
            f"/cryptic/{session['openstack_project_name']}/keys",
            prefix="/runner",
        )

    if ret is not None:
        return ret
    return ""


async def push_header(
    session: sd_lock_utility.types.SDAPISession, header: bytes, filepath: pathlib.Path
) -> None:
    """Push a file header to SD API."""
    await get_shared_ids(session)
    await signed_fetch(
        session,
        f"/header/{session['openstack_project_name']}/{session['container']}/{filepath}",
        params=(
            {
                "owner": session["owner_name"],
            }
            if session["owner_name"]
            else None
        ),
        prefix="/runner",
        method="PUT",
        data=header,
    )


async def get_header(
    session: sd_lock_utility.types.SDAPISession, filepath: pathlib.Path
) -> bytes:
    """Get a file header from SD API."""
    await get_shared_ids(session)
    ret = await signed_fetch(
        session,
        f"/header/{session['openstack_project_name']}/{session['container']}/{filepath}",
        params=(
            {
                "owner": session["owner_name"],
            }
            if session["owner_name"]
            else None
        ),
        prefix="/runner",
    )
    if ret is not None:
        return base64.urlsafe_b64decode(ret)
    raise sd_lock_utility.exceptions.NoFileHeader


async def check_shared_status(
    session: sd_lock_utility.types.SDAPISession,
):
    """Check container share status and return prossible owner."""
    if session["owner"]:
        return

    ret = await signed_fetch(
        session,
        f"/access/{session['openstack_project_id']}",
        prefix="/sharing",
    )

    if ret is not None:
        try:
            parsed_access: list[sd_lock_utility.types.SharedBucketListingEntry] = (
                json.loads(ret)
            )
            for access in parsed_access:
                if access["container"] == session["container"]:
                    session["owner"] = access["owner"]
        except Exception:
            session["owner"] = ""


async def get_shared_ids(
    session: sd_lock_utility.types.SDAPISession,
) -> sd_lock_utility.types.SharedProjectId:
    """Check container owner project name."""
    ret: sd_lock_utility.types.SharedProjectId = {
        "id": "",
        "name": "",
    }

    if session["owner_name"]:
        return ret

    if not session["owner"]:
        return ret

    ids = await signed_fetch(
        session,
        f"/ids/{session['owner']}",
        prefix="/sharing",
    )

    if ids is not None:
        try:
            ret = json.loads(ids)
            session["owner_name"] = ret["name"]
        except Exception:
            session["owner_name"] = ""

    return ret


async def share_folder_to_project(
    session: sd_lock_utility.types.SDAPISession,
):
    """Share a folder to the receiver project."""
    await get_shared_ids(session)

    if not session["owner_name"]:
        raise sd_lock_utility.exceptions.NoOwner

    await signed_fetch(
        session,
        f"/cryptic/{session['openstack_project_name']}/{session['container']}",
        json_data={
            "name": session["owner_name"],
            "id": session["owner"],
        },
        prefix="/runner",
    )
