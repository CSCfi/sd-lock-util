"""Common types for SD folder lock/unlock tool."""

import os
import pathlib
import typing

import aiohttp
import types_aiobotocore_s3

# SD lock/unlock utility constants

# MAX_SIMULTANEOUS_UPLOADS can be used to set a suitable maximum amount of
# upload tasks running at once. The default 4 should be fine for most
# situations.
MAX_SIMULTANEOUS_UPLOADS: int = int(
    os.environ.get("SD_LOCK_UTIL_MAX_SIMULTANEOUS_UPLOADS", 4)
)


class SDAPISession(typing.TypedDict):
    """Type definition for session variables."""

    client: aiohttp.client.ClientSession | None
    s3_client: types_aiobotocore_s3.Client | None
    token: bytes
    owner: str
    owner_name: str
    address: str
    openstack_project_id: str
    openstack_project_name: str
    openstack_auth_url: str
    openstack_password: str
    openstack_user_domain: str
    openstack_username: str
    openstack_region_name: str
    openstack_token: str
    openstack_object_storage_endpoint: str
    openstack_token_valid_until: float
    container: str
    no_check_certificate: bool
    use_s3: bool
    ec2_access_key: str
    ec2_secret_key: str
    s3_endpoint_url: str


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
    owner_name: str
    openstack_auth_url: str
    sd_connect_address: str
    sd_api_token: str
    prefix: str
    path: pathlib.Path
    no_preserve_original: bool
    no_check_certificate: bool
    progress: bool
    debug: bool
    verbose: bool
    use_s3: bool
    ec2_access_key: str
    ec2_secret_key: str
    s3_endpoint_url: str


class SDLockOptions(SDCommandBaseOptions):
    """Additional type definitions for lock command options."""

    no_content_upload: bool


class SDUnlockOptions(SDCommandBaseOptions):
    """Additional type definitions for unlock command options."""

    no_content_download: bool
    no_path: bool


class SDUtilFile(typing.TypedDict):
    """Type definitions for a file object in SD Lock Utility."""

    # Note that the filename and path always point to the plain-text file,
    # so the encrypted file identifier needs to be added separately.
    path: pathlib.Path
    localpath: pathlib.Path
    session_key: bytes


class OpenstackObjectListingItem(typing.TypedDict):
    """Type definitions for Openstack Object Storage API file item."""

    hash: str
    last_modified: str
    bytes: int
    name: str
    content_type: str


class SharedBucketListingEntry(typing.TypedDict):
    """Type definitions for shared bucket entry."""

    container: str
    owner: str
    sharingdate: str


class SharedProjectId(typing.TypedDict):
    """Type definitions for a shared project id mapping."""

    id: str
    name: str
