"""CLI for locking and unlocking files with SD Connect upload API."""

import asyncio
import os
import sys

import click

import sd_lock_utility.exceptions
import sd_lock_utility.lock
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
    os_auth_url: str,
    sd_connect_address: str,
    sd_api_token: str,
    prefix: str,
    no_content_upload: bool,
    no_preserve_original: bool,
    no_check_certificate: bool,
    verbose: bool,
    debug: bool,
    progress: bool,
) -> None:
    """Lock a file or folder."""
    if not os.path.exists(path):
        click.echo("Could not access the provided path.", err=True)
        sys.exit(3)

    if progress and debug:
        click.echo("Progress can't be reliably printed with debug information.", err=True)
        click.echo("Progress will not be displayed while debug mode is used.", err=True)

    opts: sd_lock_utility.types.SDLockOptions = {
        "path": path.rstrip("/"),
        "container": container,
        "project_id": project_id,
        "project_name": project_name,
        "owner": owner,
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
    }

    ret = asyncio.run(sd_lock_utility.lock.lock(opts))
    sys.exit(ret)


@click.command()
@click.option(
    "--project-id", default="", help="Project id of the project used in uploading."
)
@click.option(
    "--project-name", default="", help="Project name of the project used in uploading."
)
@click.option("--owner", default="", help="Owner of the shared container.")
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
        "openstack_auth_url": "",
        "sd_connect_address": sd_connect_address,
        "sd_api_token": sd_api_token,
        "prefix": "",
        "path": "",
        "no_preserve_original": False,
        "no_check_certificate": no_check_certificate,
        "progress": False,
        "debug": debug,
        "verbose": verbose,
    }

    ret = asyncio.run(sd_lock_utility.lock.get_pubkey(opts))

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
    os_auth_url: str,
    sd_connect_address: str,
    sd_api_token: str,
    prefix: str,
    no_content_download: bool,
    no_preserve_original: bool,
    no_check_certificate: bool,
    verbose: bool,
    debug: bool,
    progress: bool,
):
    """Unlock a file or folder."""
    if path and not os.path.exists(path):
        click.echo("Could not access the provided path.", err=True)
        sys.exit(3)

    if progress and debug:
        click.echo("Progress can't be reliably printed with debug information.", err=True)
        click.echo("Progress will not be displayed while debug mode is used.", err=True)

    opts: sd_lock_utility.types.SDUnlockOptions = {
        "path": path.rstrip("/"),
        "container": container,
        "project_id": project_id,
        "project_name": project_name,
        "owner": owner,
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
    }

    ret = asyncio.run(sd_lock_utility.unlock.unlock(opts))
    sys.exit(ret)


@click.group()
def wrap():
    """Group CLI functions into a single tool to simplify using pyinstaller."""
    pass


wrap.add_command(lock)
wrap.add_command(unlock)
wrap.add_command(pubkey)


if __name__ == "__main__":
    wrap()
