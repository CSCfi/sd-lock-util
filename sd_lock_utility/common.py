"""Common miscellaneous functions for lock-util."""

import asyncio
import ssl
import typing

import aiofiles
import aiohttp
import certifi
import click
import nacl.bindings
import nacl.exceptions

import sd_lock_utility.types


def get_ssl_context(
    session: sd_lock_utility.types.SDAPISession,
) -> ssl.SSLContext:
    """Create and return a certificate matching requested verification."""
    ssl_context = ssl.create_default_context()
    ssl_context.load_verify_locations(certifi.where())

    # If no verification is requested, flag cert none
    if session["no_check_certificate"]:
        ssl_context.verify_mode = ssl.CERT_NONE

    return ssl_context


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


async def decrypt_object_get_stream(
    body: aiohttp.StreamReader,
    opts: sd_lock_utility.types.SDUnlockOptions,
    session: sd_lock_utility.types.SDAPISession,
    file: sd_lock_utility.types.SDUtilFile,
    bar: typing.Any,
) -> None:
    """Consume and decrypt a segment from object storage."""
    async with aiofiles.open(file["localpath"], "wb") as out_f:
        while True:
            try:
                chunk = await body.readexactly(65564)
            except asyncio.IncompleteReadError as incomplete:
                chunk = incomplete.partial

            if not chunk:
                break

            nonce = chunk[:12]
            content = chunk[12:]

            try:
                await out_f.write(
                    nacl.bindings.crypto_aead_chacha20poly1305_ietf_decrypt(
                        content,
                        None,
                        nonce,
                        file["session_key"],
                    )
                )
            except nacl.exceptions.CryptoError:
                click.echo(f"Could not decrypt {file['path']}.c4gh", err=True)
                break

            if bar:
                bar.update(len(chunk))
