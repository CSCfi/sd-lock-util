"""Common types for SD folder lock/unlock tool."""


import typing

import aiohttp


class SDAPISession(typing.TypedDict):
    """Type definition for session variables."""

    client: aiohttp.ClientSession
    token: bytes
    address: str
    project_id: str
    project_name: str
    openstack_auth_url: str
    container: str
    no_check_certificate: bool


class SDAPISignature(typing.TypedDict, total=False):
    """Type definition for SD API signature."""

    valid: int
    signature: str
    nosession: str
    flavor: str


class SDCommandBaseOptions(typing.TypedDict):
    """Type definitions for command options."""

    container: str
    project_id: str
    project_name: str
    owner: str
    openstack_auth_url: str
    sd_connect_address: str
    sd_api_token: str
    path: str
    no_preserve_original: bool
    no_check_certificate: bool
    progress: bool


class SDLockOptions(SDCommandBaseOptions):
    """Additional type definitions for lock command options."""

    no_content_upload: bool


class SDUnlockOptions(SDCommandBaseOptions):
    """Additional type definitions for unlock command options."""

    no_content_download: bool


class SDUtilFile(typing.TypedDict):
    """Type definitions for a file object in SD Lock Utility."""

    # Note that the filename and path always point to the plain-text file,
    # so the encrypted file identifier needs to be added separately.
    filename: str
    prefix: str
    path: str
    session_key: bytes
