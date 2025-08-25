"""Common miscellaneous functions for lock-util."""

import click

import sd_lock_utility.types


def conditional_echo_verbose(
    opts: sd_lock_utility.types.SDCommandBaseOptions, message: str
) -> None:
    """Echo verbose messages if verbose level is configured."""
    if opts["verbose"]:
        click.echo(message)


def conditional_echo_debug(
    opts: sd_lock_utility.types.SDCommandBaseOptions, message: str
) -> None:
    """Echo debug messages if debug level is configured."""
    if opts["debug"]:
        click.echo(message)


def get_upload_project_scoped_endpoint(
    session: sd_lock_utility.types.SDAPISession,
) -> str:
    """Get the correct endpoint for uploading."""
    if session["owner"]:
        return session["openstack_object_storage_endpoint"].replace(
            session["openstack_project_id"],
            session["owner"],
        )
    return session["openstack_object_storage_endpoint"]
