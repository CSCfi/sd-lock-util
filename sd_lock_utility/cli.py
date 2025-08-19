"""CLI for locking and unlocking files with SD Connect upload API."""

import asyncio
import pathlib
import sys

import click

import sd_lock_utility.lock
import sd_lock_utility.sharing
import sd_lock_utility.types
import sd_lock_utility.unlock


@click.command()
@click.option(
    "--container", default="", help="Container where the files will be uploaded."
)
@click.option(
    "--project-id", default="", help="Project id of the project used in uploading."
)
@click.option(
    "--project-name", default="", help="Project name of the project used in uploading."
)
@click.option("--owner", default="", help="Owner of the shared container.")
@click.option("--owner-name", default="", help="Owner name of the shared container.")
@click.option("--os-auth-url", default="", help="Openstack authentication backend URL.")
@click.option(
    "--sd-connect-address", default="", help="Address used when connecting to SD Connect."
)
@click.option(
    "--sd-api-token", default="", help="Token to use for authentication with SD Connect."
)
@click.option(
    "--prefix",
    default="",
    help="Prefix to prepend to paths when uploading (used for uploading to subfolders).",
)
@click.option(
    "--no-content-upload",
    is_flag=True,
    help="Upload headers and encrypt in place. User will provide the upload script afterwards.",
)
@click.option(
    "--no-preserve-original", is_flag=True, help="Remove original files after encrypting."
)
@click.option(
    "--no-check-certificate",
    is_flag=True,
    help="Don't check TLS certificate for authenticity. (develompent use only)",
)
@click.option(
    "--s3",
    is_flag=True,
    help="Use s3 instead of swift.",
)
@click.option("--ec2-key", default="", help="EC2 key.")
@click.option("--ec2-secret", default="", help="EC2 secret.")
@click.option("--s3-endpoint-url", default="", help="S3 endpoint url.")
@click.option(
    "--verbose",
    is_flag=True,
    help="Print more information.",
)
@click.option("--debug", is_flag=True, help="Print debug information.")
@click.option(
    "--progress/--no-progress", default=True, help="Display file progress information."
)
@click.argument("path")
def lock(
    path: str,
    container: str,
    project_id: str,
    project_name: str,
    owner: str,
    owner_name: str,
    os_auth_url: str,
    sd_connect_address: str,
    sd_api_token: str,
    prefix: str,
    no_content_upload: bool,
    no_preserve_original: bool,
    no_check_certificate: bool,
    verbose: bool,
    s3: bool,
    ec2_key: str,
    ec2_secret: str,
    s3_endpoint_url: str,
    debug: bool,
    progress: bool,
) -> None:
    """Lock a file or folder."""
    plpath = pathlib.Path(path)
    if not plpath.exists():
        click.echo("Could not access the provided path.", err=True)
        sys.exit(3)

    if progress and debug:
        click.echo("Progress can't be reliably printed with debug information.", err=True)
        click.echo("Progress will not be displayed while debug mode is used.", err=True)

    opts: sd_lock_utility.types.SDLockOptions = {
        "path": plpath,
        "container": container,
        "project_id": project_id,
        "project_name": project_name,
        "owner": owner,
        "owner_name": owner_name,
        "openstack_auth_url": os_auth_url,
        "sd_connect_address": sd_connect_address,
        "no_content_upload": no_content_upload,
        "no_preserve_original": no_preserve_original,
        "sd_api_token": sd_api_token,
        "prefix": prefix,
        "no_check_certificate": no_check_certificate,
        "progress": progress if not debug else False,
        "debug": debug,
        "verbose": verbose,
        "use_s3": s3,
        "ec2_access_key": ec2_key,
        "ec2_secret_key": ec2_secret,
        "s3_endpoint_url": s3_endpoint_url,
    }

    ret = 0
    try:
        ret = asyncio.run(sd_lock_utility.lock.wrap_lock_exceptions(opts))
    except KeyboardInterrupt:
        ret = 0
    sys.exit(ret)


@click.command()
@click.option(
    "--project-id", default="", help="Project id of the project used in uploading."
)
@click.option(
    "--project-name", default="", help="Project name of the project used in uploading."
)
@click.option("--owner", default="", help="Owner of the shared container.")
@click.option("--owner-name", default="", help="Owner name of the shared container.")
@click.option(
    "--sd-connect-address", default="", help="Address used when connecting to SD Connect."
)
@click.option(
    "--sd-api-token", default="", help="Token to use for authentication with SD Connect."
)
@click.option(
    "--no-check-certificate",
    is_flag=True,
    help="Don't check TLS certificate for authenticity. (development use only)",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Print more information.",
)
@click.option("--debug", is_flag=True, help="Print debug information.")
def pubkey(
    project_id: str,
    project_name: str,
    owner: str,
    owner_name: str,
    sd_connect_address: str,
    sd_api_token: str,
    no_check_certificate: bool,
    verbose: bool,
    debug: bool,
) -> None:
    """Fetch and display the project public key."""
    opts: sd_lock_utility.types.SDCommandBaseOptions = {
        "container": "placeholder",
        "project_id": project_id,
        "project_name": project_name,
        "owner": owner,
        "owner_name": owner_name,
        "openstack_auth_url": "",
        "sd_connect_address": sd_connect_address,
        "sd_api_token": sd_api_token,
        "prefix": "",
        "path": pathlib.Path("."),
        "no_preserve_original": False,
        "no_check_certificate": no_check_certificate,
        "progress": False,
        "debug": debug,
        "verbose": verbose,
        "use_s3": False,
        "ec2_access_key": "",
        "ec2_secret_key": "",
        "s3_endpoint_url": "",
    }

    ret = 0
    try:
        ret = asyncio.run(sd_lock_utility.lock.get_pubkey(opts))
    except KeyboardInterrupt:
        ret = 0

    sys.exit(ret)


@click.command()
@click.option(
    "--project-id", default="", help="Project id of the project used in uploading."
)
@click.option(
    "--project-name", default="", help="Project name of the project used in uploading."
)
@click.option(
    "--sd-connect-address", default="", help="Address used when connecting to SD Connect."
)
@click.option(
    "--sd-api-token", default="", help="Token to use for authentication with SD Connect."
)
@click.option(
    "--no-check-certificate",
    is_flag=True,
    help="Don't check TLS certificate for authenticity. (development use only)",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Print more information.",
)
@click.option("--debug", is_flag=True, help="Print debug information.")
@click.argument("id")
def idcheck(
    id: str,
    project_id: str,
    project_name: str,
    sd_connect_address: str,
    sd_api_token: str,
    no_check_certificate: bool,
    verbose: bool,
    debug: bool,
) -> None:
    """Fetch the project ID information from either share id or name."""
    opts: sd_lock_utility.types.SDCommandBaseOptions = {
        "container": "placeholder",
        "project_id": project_id,
        "project_name": project_name,
        "owner": id,
        "owner_name": "",
        "openstack_auth_url": "",
        "sd_connect_address": sd_connect_address,
        "sd_api_token": sd_api_token,
        "prefix": "",
        "path": pathlib.Path("."),
        "no_preserve_original": False,
        "no_check_certificate": no_check_certificate,
        "progress": False,
        "debug": debug,
        "verbose": verbose,
        "use_s3": False,
        "ec2_access_key": "",
        "ec2_secret_key": "",
        "s3_endpoint_url": "",
    }

    ret = 0
    try:
        ret = asyncio.run(sd_lock_utility.lock.get_id(opts))
    except KeyboardInterrupt:
        ret = 0

    sys.exit(ret)


@click.command()
@click.option(
    "--container", default="", help="Container where the files were downloaded from."
)
@click.option(
    "--project-id", default="", help="Project id of the project used in downloading."
)
@click.option(
    "--project-name", default="", help="Project name of the project used in downloading."
)
@click.option("--owner", default="", help="Owner of the shared container.")
@click.option("--owner-name", default="", help="Owner name of the shared container.")
@click.option("--os-auth-url", default="", help="Openstack authentication backend URL.")
@click.option(
    "--sd-connect-address", default="", help="Address used when connecting to SD Connect."
)
@click.option(
    "--sd-api-token", default="", help="Token to use for authentication with SD Connect."
)
@click.option(
    "--prefix",
    default="",
    help="Prefix to use with paths when downloading (used for downloading from subfolders).",
)
@click.option(
    "--path",
    default="",
    help="Path where the downloaded files are. If used together with --no-content-download signifies a single file download.",
)
@click.option(
    "--no-content-download",
    is_flag=True,
    help="Download headers and decrypt in place. User will provide the files to decrypt.",
)
@click.option(
    "--no-preserve-original", is_flag=True, help="Remove original files after decrypting."
)
@click.option(
    "--no-check-certificate",
    is_flag=True,
    help="Don't check TLS certificate for authenticity. (develompent use only)",
)
@click.option(
    "--s3",
    is_flag=True,
    help="Use s3 instead of swift.",
)
@click.option("--ec2-key", default="", help="EC2 key.")
@click.option("--ec2-secret", default="", help="EC2 secret.")
@click.option("--s3-endpoint-url", default="", help="S3 endpoint url.")
@click.option(
    "--verbose",
    is_flag=True,
    help="Print more information.",
)
@click.option("--debug", is_flag=True, help="Print debug information.")
@click.option(
    "--progress/--no-progress", default=True, help="Display file progress information."
)
def unlock(
    path: str,
    container: str,
    project_id: str,
    project_name: str,
    owner: str,
    owner_name: str,
    os_auth_url: str,
    sd_connect_address: str,
    sd_api_token: str,
    prefix: str,
    no_content_download: bool,
    no_preserve_original: bool,
    no_check_certificate: bool,
    s3: bool,
    ec2_key: str,
    ec2_secret: str,
    s3_endpoint_url: str,
    verbose: bool,
    debug: bool,
    progress: bool,
):
    """Unlock a file or folder."""
    plpath = pathlib.Path(path)
    if path and not plpath.exists():
        click.echo("Could not access the provided path.", err=True)
        sys.exit(3)

    if progress and debug:
        click.echo("Progress can't be reliably printed with debug information.", err=True)
        click.echo("Progress will not be displayed while debug mode is used.", err=True)

    opts: sd_lock_utility.types.SDUnlockOptions = {
        "path": plpath,
        "no_path": True if not path else False,
        "container": container,
        "project_id": project_id,
        "project_name": project_name,
        "owner": owner,
        "owner_name": owner_name,
        "openstack_auth_url": os_auth_url,
        "sd_connect_address": sd_connect_address,
        "no_content_download": no_content_download,
        "no_preserve_original": no_preserve_original,
        "sd_api_token": sd_api_token,
        "prefix": prefix,
        "no_check_certificate": no_check_certificate,
        "progress": progress if not debug else False,
        "debug": debug,
        "verbose": verbose,
        "use_s3": s3,
        "ec2_access_key": ec2_key,
        "ec2_secret_key": ec2_secret,
        "s3_endpoint_url": s3_endpoint_url,
    }

    ret = 0
    try:
        ret = asyncio.run(sd_lock_utility.unlock.wrap_unlock_exceptions(opts))
    except KeyboardInterrupt:
        ret = 0
    sys.exit(ret)


@click.command()
@click.option(
    "--container", default="", help="Container where the encrypted contents are."
)
@click.option(
    "--project-id",
    default="",
    help="Project id of the project used when uploading the files.",
)
@click.option(
    "--project-name",
    default="",
    help="Project name of the project used when uploading the files.",
)
@click.option("--owner", default="", help="Owner of the shared container.")
@click.option("--owner-name", default="", help="Owner name of the shared container.")
@click.option("--os-auth-url", default="", help="Openstack authentication backend URL.")
@click.option(
    "--sd-connect-address", default="", help="Address used when connecting to SD Connect."
)
@click.option(
    "--sd-api-token", default="", help="Token to use for authentication with SD Connect."
)
@click.option(
    "--prefix",
    default="",
    help="Prefix to use with paths when downloading (used for downloading from subfolders).",
)
@click.option(
    "--no-check-certificate",
    is_flag=True,
    help="Don't check TLS certificate for authenticity. (develompent use only)",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Print more information.",
)
@click.option("--debug", is_flag=True, help="Print debug information.")
def fix_header_permissions(
    container: str,
    project_id: str,
    project_name: str,
    owner: str,
    owner_name: str,
    os_auth_url: str,
    sd_connect_address: str,
    sd_api_token: str,
    prefix: str,
    no_check_certificate: bool,
    verbose: bool,
    debug: bool,
):
    """Grant the actual owner project access to the headers."""
    opts: sd_lock_utility.types.SDUnlockOptions = {
        "path": pathlib.Path("."),
        "no_path": True,
        "container": container,
        "project_id": project_id,
        "project_name": project_name,
        "owner": owner,
        "owner_name": owner_name,
        "openstack_auth_url": os_auth_url,
        "sd_connect_address": sd_connect_address,
        "no_content_download": False,
        "no_preserve_original": False,
        "sd_api_token": sd_api_token,
        "prefix": prefix,
        "no_check_certificate": no_check_certificate,
        "progress": False,
        "debug": debug,
        "verbose": verbose,
        "use_s3": False,
        "ec2_access_key": "",
        "ec2_secret_key": "",
        "s3_endpoint_url": "",
    }

    ret = 0
    try:
        ret = asyncio.run(sd_lock_utility.sharing.fix_header_permissions_uploader(opts))
    except KeyboardInterrupt:
        ret = 0
    sys.exit(ret)


@click.command()
@click.option(
    "--container", default="", help="Container where the encrypted contents are."
)
@click.option(
    "--project-id",
    default="",
    help="Project id of the project that should own the encrypted files.",
)
@click.option(
    "--project-name",
    default="",
    help="Project name of the project that should own the encrypted files.",
)
@click.option(
    "--owner",
    default="",
    help="Sharing ID of the original uploader of the encrypted files.",
)
@click.option(
    "--owner-name",
    default="",
    help="Project name of the original uploader of the encrpyted files.",
)
@click.option("--os-auth-url", default="", help="Openstack authentication backend URL.")
@click.option(
    "--sd-connect-address", default="", help="Address used when connecting to SD Connect."
)
@click.option(
    "--sd-api-token", default="", help="Token to use for authentication with SD Connect."
)
@click.option(
    "--prefix",
    default="",
    help="Prefix to use with paths when downloading (used for downloading from subfolders).",
)
@click.option(
    "--no-check-certificate",
    is_flag=True,
    help="Don't check TLS certificate for authenticity. (develompent use only)",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Print more information.",
)
@click.option("--debug", is_flag=True, help="Print debug information.")
def fix_missing_headers(
    container: str,
    project_id: str,
    project_name: str,
    owner: str,
    owner_name: str,
    os_auth_url: str,
    sd_connect_address: str,
    sd_api_token: str,
    prefix: str,
    no_check_certificate: bool,
    verbose: bool,
    debug: bool,
):
    """Retrieve the missing file headers from the uploading project."""
    opts: sd_lock_utility.types.SDUnlockOptions = {
        "path": pathlib.Path("."),
        "no_path": True,
        "container": container,
        "project_id": project_id,
        "project_name": project_name,
        "owner": owner,
        "owner_name": owner_name,
        "openstack_auth_url": os_auth_url,
        "sd_connect_address": sd_connect_address,
        "no_content_download": False,
        "no_preserve_original": False,
        "sd_api_token": sd_api_token,
        "prefix": prefix,
        "no_check_certificate": no_check_certificate,
        "progress": False,
        "debug": debug,
        "verbose": verbose,
        "use_s3": False,
        "ec2_access_key": "",
        "ec2_secret_key": "",
        "s3_endpoint_url": "",
    }

    ret = 0
    try:
        ret = asyncio.run(sd_lock_utility.sharing.fix_header_permissions_owner(opts))
    except KeyboardInterrupt:
        ret = 0
    sys.exit(ret)


@click.group()
def wrap():
    """Group CLI functions into a single tool to simplify using pyinstaller."""
    pass


wrap.add_command(lock)
wrap.add_command(unlock)
wrap.add_command(pubkey)
wrap.add_command(idcheck)
wrap.add_command(fix_header_permissions)
wrap.add_command(fix_missing_headers)


if __name__ == "__main__":
    wrap()
