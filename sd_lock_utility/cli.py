"""CLI for locking and unlocking files with SD Connect upload API."""


import typing
import os
import asyncio

import click

import crypt4gh

import sd_lock_utility.lock
import sd_lock_utility.unlock
import sd_lock_utility.exceptions


@click.command()
@click.option("--container", default="", help="Container where the files will be uploaded.")
@click.argument("path")
def lock(path: str, container: str):
    """Lock a file or folder."""
    if not os.path.exists(path):
        print("Couldn't access the provided path.")

    return asyncio.run(sd_lock_utility.lock.lock(path, container))


@click.command()
@click.option("--container", default="", help="Container where the files were downloaded from.")
@click.argument("path")
def unlock(path: str, container: str):
    """Unlock a file or folder."""
    if not os.path.exists(path):
        print("Couldn't access the provided path.")

    return asyncio.run(sd_lock_utility.unlock.unlock(path, container))
