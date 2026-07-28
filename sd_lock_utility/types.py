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
    openstack_user_id: str
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
    isolated: bool
    pubkey: str


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
    isolated: bool
    pubkey: str


class SDUnlockOptions(SDCommandBaseOptions):
    """Additional type definitions for unlock command options."""

    no_content_download: bool
    no_path: bool


class SDHeaderMigrate(SDCommandBaseOptions):
    """Additional type definitions for header migrate command options."""

    to_bucket: str


class SDUtilFile(typing.TypedDict):
    """Type definitions for a file object in SD Lock Utility."""

    # Note that the filename and path always point to the plain-text file,
    # so the encrypted file identifier needs to be added separately.
    path: pathlib.Path
    localpath: pathlib.Path
    session_key: bytes


class OpenstackContainerListingItem(typing.TypedDict):
    """Type definitions for Openstack Object Storage API container item."""

    count: int
    bytes: int
    name: str
    last_modified: str


class OpenstackObjectListingItem(typing.TypedDict):
    """Type definitions for Openstack Object Storage API file item."""

    hash: str
    last_modified: str
    bytes: int
    name: str
    content_type: str
    manifest: typing.NotRequired[str]


class SharedBucketListingEntry(typing.TypedDict):
    """Type definitions for shared bucket entry."""

    container: str
    owner: str
    sharingdate: str


class SharedProjectId(typing.TypedDict):
    """Type definitions for a shared project id mapping."""

    id: str
    name: str


class VaultSharedProjectId(typing.TypedDict):
    """Type definitions for the vault side shared project id mapping."""

    id: str
    idkeystone: str


class ProjectACLWhitelist(typing.TypedDict):
    """Type definitions for a bucket sharing."""

    project: str
    read: bool
    write: bool


class AWSStatementPrincipal(typing.TypedDict):
    """Type definitions for AWS S3 bucket policy principal."""

    AWS: str


class AWSBucketPolicyStatement(typing.TypedDict):
    """Type definitions for AWS S3 bucket policy statement."""

    Sid: str
    Principal: dict[str, str]
    Effect: str
    Action: list[str]
    Resource: list[str]


class AWSBucketPolicy(typing.TypedDict):
    """Type definitions for AWS S3 bucket policy."""

    Version: str
    Statement: list[AWSBucketPolicyStatement]


class OpenstackProjectListItem(typing.TypedDict):
    """Type definitions for an Openstack project scope list entry."""

    domain_id: str
    enabled: bool
    id: str
    links: dict
    name: str


class OpenstackProjectList(typing.TypedDict):
    """Type definitions for an Openstack project scope list."""

    projects: list[OpenstackObjectListingItem]
    links: dict


class HeaderListItem(typing.TypedDict):
    """Type definition for single header item."""

    key: str  # the name of the object
    header: str  # the header contents in base64, in order to support the JSON file format


class HeaderList(typing.TypedDict):
    """Type definition for list of header items."""

    bucket: str  # the bucket where the object resides
    owner: str  # the openstack project id of the project that owns the bucket
    owner_name: (
        str  # the openstack project name / MyCSC id of the project that owns the bucket
    )
    headers: list[HeaderListItem]
