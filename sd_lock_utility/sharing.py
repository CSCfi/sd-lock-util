"""Bucket sharing operations."""

import asyncio
import base64
import io
import pathlib
import typing

import aioboto3
import aiohttp
import click
import crypt4gh.header
import nacl.public

import sd_lock_utility.client
import sd_lock_utility.common
import sd_lock_utility.exceptions
import sd_lock_utility.os_client
import sd_lock_utility.s3_client
import sd_lock_utility.types


async def fix_header_permissions_uploader(
    opts: sd_lock_utility.types.SDCommandBaseOptions,
):
    """Share the incorrectly created header bucket to the owner project."""
    try:
        session: sd_lock_utility.types.SDAPISession = (
            await sd_lock_utility.client.open_session(
                container=opts["container"],
                address=opts["sd_connect_address"],
                project_id=opts["project_id"],
                project_name=opts["project_name"],
                owner=opts["owner"],
                owner_name=opts["owner_name"],
                token=opts["sd_api_token"],
                os_auth_url=opts["openstack_auth_url"],
                no_check_certificate=opts["no_check_certificate"],
            )
        )
    except sd_lock_utility.exceptions.NoToken:
        click.echo("No API access token was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoAddress:
        click.echo("No API address was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoProjectName:
        click.echo("No Openstack project information was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoContainer:
        click.echo("No container was provided for uploads.", err=True)
        return 3

    exc: typing.Any = None
    ret = 0
    try:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                ssl=sd_lock_utility.common.get_ssl_context(session),
            ),
            raise_for_status=True,
        ) as cs:
            session["client"] = cs
            await sd_lock_utility.client.share_folder_to_project(session)
        await asyncio.sleep(0.250)
    except asyncio.CancelledError:
        click.echo("Received a keyboard interrupt, aborting...", err=True)
        return 0
    except aiohttp.ClientResponseError as cex:
        if cex.status == 401 and not opts["debug"]:
            click.echo("Authentication was not successful.", err=True)
            click.echo(
                "Check that your SD Connect token is still valid and Openstack credentials are correct.",
                err=True,
            )
        else:
            exc = cex
    except sd_lock_utility.exceptions.NoOwner:
        click.echo("The owner id does not exist in cache.", err=True)
        click.echo("Ensure the owner is configured.")
        click.echo("The project may not have yet logged in to SD Connect.", err=True)
    finally:
        if exc is not None:
            sd_lock_utility.common.print_traceback()
            raise exc

    return ret


async def fix_header_location(
    opts: sd_lock_utility.types.SDCommandBaseOptions,
    session: sd_lock_utility.types.SDAPISession,
):
    """Fix the folder permissions by using the original uploader's headers."""
    # Create an ephemeral keypair
    privkey = nacl.public.PrivateKey.generate()
    sd_lock_utility.common.conditional_echo_verbose(
        opts, "Temporarily whitelisting a public key for decryption..."
    )
    await sd_lock_utility.client.whitelist_key(session, privkey.public_key.encode())

    # Fetch all files in the path
    await sd_lock_utility.os_client.openstack_get_token(session)
    objects = await sd_lock_utility.os_client.get_container_objects(
        session, opts["prefix"]
    )

    headers: list[sd_lock_utility.types.SDUtilFile] = []

    total: int = 0

    # Retrieve and open the file headers
    try:
        for root, _, files in objects:  # type: ignore
            for file in files:
                path: pathlib.Path = root / file  # type: ignore

                # Fetch the old header
                sd_lock_utility.common.conditional_echo_debug(
                    opts,
                    f"Fetching the original header from the uploader project for {path}.",
                )
                uploader_header = await sd_lock_utility.client.get_header(session, path)
                if not uploader_header:
                    click.echo(f"Found no header for {path}.", err=True)
                uploader_header_file = io.BytesIO(uploader_header)
                session_keys, _ = crypt4gh.header.deconstruct(
                    uploader_header_file, [(0, privkey.encode(), None)]
                )

                if not session_keys:
                    click.echo(f"No session key available for {path}", err=True)

                sd_lock_utility.common.conditional_echo_debug(
                    opts, f"Available session keys for {path}: {len(session_keys)}"
                )

                # Add the unwrapped session key to the listing
                headers.append(
                    {
                        "path": path,
                        "localpath": path,
                        "session_key": session_keys[0],
                    }
                )

    finally:
        # Revoke the temporary key from whitelist
        sd_lock_utility.common.conditional_echo_verbose(
            opts, "Removing temporary download key from decryption whitelist."
        )
        await sd_lock_utility.client.unlist_key(session)

    sd_lock_utility.common.conditional_echo_debug(
        opts, "Dropping the owner parameters from session..."
    )
    session["owner"] = ""
    session["owner_name"] = ""

    sd_lock_utility.common.conditional_echo_debug(
        opts, "Retrieving the owner project public key."
    )
    pubkey_str = await sd_lock_utility.client.get_public_key(session)
    if not pubkey_str:
        raise sd_lock_utility.exceptions.NoKey
    pubkey = base64.urlsafe_b64decode(pubkey_str)

    # Rewrap the headers using the project public key, and push to Vault
    for header in headers:
        private_key_eph = nacl.public.PrivateKey.generate()
        header_content = crypt4gh.header.make_packet_data_enc(0, header["session_key"])
        header_packets = crypt4gh.header.encrypt(
            header_content, [(0, private_key_eph.encode(), pubkey)]
        )
        header_bytes: bytes = crypt4gh.header.serialize(header_packets)

        sd_lock_utility.common.conditional_echo_debug(
            opts, f"Uploading header {header['path']} to Vault."
        )
        await sd_lock_utility.client.push_header(
            session,
            header_bytes,
            header["path"],
        )

        sd_lock_utility.common.conditional_echo_verbose(
            opts, f"Added header for {header['path']}."
        )
        total += 1

    return total


async def fix_header_permissions_owner(opts: sd_lock_utility.types.SDCommandBaseOptions):
    """Copy over the incorrectly created headers from the uploader project."""
    try:
        session: sd_lock_utility.types.SDAPISession = (
            await sd_lock_utility.client.open_session(
                container=opts["container"],
                address=opts["sd_connect_address"],
                project_id=opts["project_id"],
                project_name=opts["project_name"],
                owner=opts["owner"],
                owner_name=opts["owner_name"],
                token=opts["sd_api_token"],
                os_auth_url=opts["openstack_auth_url"],
                no_check_certificate=opts["no_check_certificate"],
            )
        )
    except sd_lock_utility.exceptions.NoToken:
        click.echo("No API access token was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoAddress:
        click.echo("No API address was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoProjectName:
        click.echo("No Openstack project information was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoContainer:
        click.echo("No container was provided for uploads.", err=True)
        return 3

    exc: typing.Any = None
    ret = 0
    try:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                ssl=sd_lock_utility.common.get_ssl_context(session),
            ),
            raise_for_status=True,
        ) as cs:
            session["client"] = cs
            total = await fix_header_location(opts, session)
            if total == 0:
                click.echo("No new headers were added to storage.")
            elif total == 1:
                click.echo(f"Added {total} header to storage.")
            else:
                click.echo(f"Added {total} headers to storage.")
        await asyncio.sleep(0.250)
    except asyncio.CancelledError:
        click.echo("Received a keyboard interrupt, aborting...", err=True)
        return 0
    except sd_lock_utility.exceptions.NoOpenstackCredentials:
        click.echo("No Openstack username and/or password provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoAuthenticationURL:
        click.echo("No Openstack authentication URL provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoProjectId:
        click.echo("Openstack project id was not provided.", err=True)
        return 3
    except aiohttp.ClientResponseError as cex:
        if cex.status == 401 and not opts["debug"]:
            click.echo("Authentication was not successful.", err=True)
            click.echo(
                "Check that your SD Connect token is still valid and Openstack credentials are correct.",
                err=True,
            )
        elif cex.status == 404 and not opts["debug"]:
            click.echo("The queried project does not exist in cache.", err=True)
            click.echo(
                "The project might not yet have logged in to SD Connect.", err=True
            )
        else:
            exc = cex
    finally:
        if exc is not None:
            sd_lock_utility.common.print_traceback()
            raise exc

    return ret


async def fix_owner_bucket_permission(
    opts: sd_lock_utility.types.SDCommandBaseOptions,
) -> int:
    """Add the owner access preservation policy to the provided bucket."""
    try:
        session: sd_lock_utility.types.SDAPISession = (
            await sd_lock_utility.client.open_session(
                container=opts["container"],
                address=opts["sd_connect_address"],
                project_id=opts["project_id"],
                project_name="placeholder",
                owner=opts["owner"],
                owner_name=opts["owner_name"],
                token=opts["sd_api_token"],
                os_auth_url=opts["openstack_auth_url"],
                no_check_certificate=opts["no_check_certificate"],
                use_s3=True,
                ec2_access_key=opts["ec2_access_key"],
                ec2_secret_key=opts["ec2_secret_key"],
                s3_endpoint_url=opts["s3_endpoint_url"],
                isolated=True,
            )
        )
    except sd_lock_utility.exceptions.NoToken:
        click.echo("No API access token was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoAddress:
        click.echo("No API address was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoProjectName:
        click.echo("Openstack project name was not provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoContainer:
        click.echo("No bucket was provided as a source for the headers.", err=True)
        return 3

    exc: typing.Any = None
    ret = 0
    try:
        async with aiohttp.ClientSession(raise_for_status=True) as cs:
            session["client"] = cs

            # Check that s3 is available
            if not sd_lock_utility.client.check_session_s3_params(session):
                try:
                    # If  we're using token auth, retrieving s3 creds requires uid to be present
                    if session["openstack_token"] and not session["openstack_user_id"]:
                        click.echo("Openstack user id is required if token auth is used.")
                        return 3
                    if not session["openstack_token"] or not session["openstack_user_id"]:
                        # Init openstack token for retrieval if necessary
                        await sd_lock_utility.os_client.openstack_get_token(session)
                    await sd_lock_utility.os_client.init_s3_credentials(session)
                except sd_lock_utility.exceptions.NoS3Access:
                    click.echo(
                        "Using S3, but could not initialize credentials.",
                        err=True,
                    )
                    click.echo(
                        "Provide S3 credentials using the command line or environment.",
                        err=True,
                    )
                    click.echo(
                        "Alternatively provide Openstack auth information for automatic S3 configuration.",
                        err=True,
                    )
                    return 3
                except sd_lock_utility.exceptions.NoProjectId:
                    click.echo("Openstack project id was not provided.", err=True)
                    return 3

            async with aioboto3.Session().client(
                service_name="s3",
                endpoint_url=session["s3_endpoint_url"],
                aws_access_key_id=session["ec2_access_key"],
                aws_secret_access_key=session["ec2_secret_key"],
            ) as s3:
                session["s3_client"] = s3

                # Retrieve the old policy
                policy: sd_lock_utility.types.AWSBucketPolicy = (
                    await sd_lock_utility.s3_client.s3_get_bucket_policy(
                        opts, session, opts["container"]
                    )
                )
                sd_lock_utility.common.conditional_echo_debug(
                    opts, f"Old policy: {policy}"
                )

                # Check if the old policy already contains the access preservation
                for statement in policy["Statement"]:
                    if statement["Sid"] == "GrantSDConnectPreserveOwnerAccess":
                        click.echo("Owner access preservation policy already exists.")
                        return 0

                # Append the preservation statement to the policy, and update
                policy["Statement"].append(
                    {
                        "Sid": "GrantSDConnectPreserveOwnerAccess",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": f"arn:aws:iam::{session['openstack_project_id']}:root",
                        },
                        "Action": [
                            "s3:*",
                        ],
                        "Resource": [
                            f"arn:aws:s3:::{session['container']}",
                            f"arn:aws:s3:::{session['container']}/*",
                        ],
                    }
                )
                ret = await sd_lock_utility.s3_client.s3_add_bucket_policy(
                    opts, session, opts["container"], policy
                )
    except asyncio.CancelledError:
        click.echo("Received a keyboard interrupt, aborting...", err=True)
        return 0
    except sd_lock_utility.exceptions.NoOpenstackCredentials:
        click.echo("No Openstack username and/or password provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoAuthenticationURL:
        click.echo("No Openstack authentication URL provided.", err=True)
        return 3
    except aiohttp.ClientResponseError as cex:
        if cex.status == 401 and not opts["debug"]:
            click.echo("Authentication was not successful.", err=True)
            click.echo(
                "Check that your SD Connect token is still valid and Openstack credentials are correct.",
                err=True,
            )
        elif cex.status == 404 and not opts["debug"]:
            click.echo("The queried project does not exist in cache.", err=True)
            click.echo(
                "The project might not yet have logged in to SD Connect.", err=True
            )
        else:
            exc = cex
    finally:
        if exc is not None:
            sd_lock_utility.common.print_traceback()
            raise exc

    return ret
