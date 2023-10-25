"""SD Connect vault proxy API client."""


import os
import base64
import typing
import time
import logging

import aiohttp

import swift_browser_ui.common.signature

import sd_lock_utility.exceptions
import sd_lock_utility.types


LOGGER = logging.getLogger("sd-lock-util")


async def open_session(
    token: str = "",
    address: str = "",
    project_id: str = "",
    project_name: str = "",
    container: str = "",
    os_auth_url: str = "",
    no_check_certificate: bool = False,
) -> sd_lock_utility.types.SDAPISession:
    """Open a new session for accessing SD API."""
    ret: sd_lock_utility.types.SDAPISession = {
        "client": aiohttp.ClientSession(
            raise_for_status=True,
        ),
        "token": token.encode("utf-8")
        if token
        else os.environ.get(
            "SD_CONNECT_API_TOKEN",
            "",
        ).encode("utf-8"),
        "address": address
        if address
        else os.environ.get(
            "SD_CONNECT_API_ADDRESS",
            "",
        ),
        "openstack_project_id": project_id
        if project_id
        else os.environ.get(
            "OS_PROJECT_ID",
            "",
        ),
        "openstack_project_name": project_name
        if project_name
        else os.environ.get(
            "OS_PROJECT_NAME",
            "",
        ),
        "openstack_auth_url": os_auth_url
        if os_auth_url
        else os.environ.get(
            "OS_AUTH_URL",
            "",
        ),
        "container": container
        if container
        else os.environ.get(
            "UPLOAD_CONTAINER",
            "",
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

    LOGGER.debug(f"SD Connect client session: {ret}")

    return ret


async def kill_session(session: sd_lock_utility.types.SDAPISession, ret: int) -> int:
    """Gracefully close the session."""

    LOGGER.debug("Gracefully closing the SD Connect client session.")

    await session["client"].close()
    return ret


async def get_signature(
    session: sd_lock_utility.types.SDAPISession,
    path: str,
    duration: int = 3600,
) -> sd_lock_utility.types.SDAPISignature:
    """Sign an API request."""
    ret: sd_lock_utility.types.SDAPISignature = (
        swift_browser_ui.common.signature.sign_api_request(
            path,
            duration,
            session["token"],
        )
    )

    return ret


async def signed_fetch(
    session: sd_lock_utility.types.SDAPISession,
    path: str,
    method: str = "GET",
    params: None | typing.Dict[str, typing.Any] = None,
    json_data: None | typing.Dict[str, typing.Any] = None,
    data: bytes | str | None = None,
    timeout: int = 60,
    duration: int = 3600,
) -> str | None:
    """Wrap fetching with integrated error handling."""
    url = session["address"] + path
    signature: sd_lock_utility.types.SDAPISignature = await get_signature(
        session, path, duration=duration
    )

    if params is not None:
        signature.update(params)  # type: ignore

    try:
        async with session["client"].request(
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
    except aiohttp.client.InvalidURL:
        print("Invalid URL")

    return None


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
            ][0]
            LOGGER.debug(
                f"Using {session['openstack_object_storage_endpoint']} as the object storage endpoint."
            )

    return session["openstack_token"]


async def whitelist_key(session: sd_lock_utility.types.SDAPISession, key: bytes) -> None:
    """Whitelist a public key for bucket."""
    await signed_fetch(
        session,
        f"/cryptic/{session['openstack_project_name']}/whitelist",
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
        method="DELETE",
    )


async def get_public_key(session: sd_lock_utility.types.SDAPISession) -> str:
    """Get project public key from SD API for encryption."""
    ret = await signed_fetch(
        session, f"/cryptic/{session['openstack_project_name']}/keys"
    )
    if ret is not None:
        return ret
    return ""


async def push_header(
    session: sd_lock_utility.types.SDAPISession, header: bytes, filepath: str
) -> None:
    """Push a file header to SD API."""
    await signed_fetch(
        session,
        f"/header/{session['openstack_project_name']}/{session['container']}/{filepath}",
        method="PUT",
        data=header,
    )


async def get_header(session: sd_lock_utility.types.SDAPISession, filepath: str) -> bytes:
    """Get a file header from SD API."""
    ret = await signed_fetch(
        session,
        f"/header/{session['openstack_project_name']}/{session['container']}/{filepath}",
    )
    if ret is not None:
        return base64.urlsafe_b64decode(ret)
    raise sd_lock_utility.exceptions.NoFileHeader
