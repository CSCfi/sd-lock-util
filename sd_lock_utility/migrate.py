"""Bucket header migration scripts."""

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


async def bucket_copy_headers(
    opts: sd_lock_utility.types.SDHeaderMigrate,
    session: sd_lock_utility.types.SDAPISession,
):
    """Migrate headers from one bucket to anohter."""
    # Create an ephemeral keypair
    privkey = nacl.public.PrivateKey.generate()
    sd_lock_utility.common.conditional_echo_verbose(
        opts, "Temporary whitelisting a public key for decryption..."
    )
    await sd_lock_utility.client.whitelist_key(session, privkey.public_key.encode())

    await sd_lock_utility.os_client.openstack_get_token(session)
    keys: list[tuple[pathlib.Path, list[str], list[str]]] = (
        await sd_lock_utility.os_client.get_container_objects(session)
    )

    headers: list[sd_lock_utility.types.SDUtilFile] = []

    total: int = 0

    # Retrieve and open the file headers
    try:
        for root, _, files in keys:
            for file in files:
                path: pathlib.Path = root / file

                # Fetch the old header
                sd_lock_utility.common.conditional_echo_debug(
                    opts,
                    f"Fetching the old header from the swift style bucket for {path} from bucket {session['container']}",
                )
                og_header = await sd_lock_utility.client.get_header(session, path)
                if not og_header:
                    click.echo(f"Found no header for {path}, skipping file.", err=True)
                    continue
                og_header_file = io.BytesIO(og_header)
                session_keys, _ = crypt4gh.header.deconstruct(
                    og_header_file, [(0, privkey.encode(), None)]
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
        opts, "Retrieving the most recent project public key."
    )
    pubkey_str = await sd_lock_utility.client.get_public_key(session)
    if not pubkey_str:
        raise sd_lock_utility.exceptions.NoKey
    pubkey = base64.urlsafe_b64decode(pubkey_str)

    # Override source bucket with the new bucket
    session["container"] = opts["to_bucket"]
    # Rewrap the headers using latest project public key and push to the new bucket
    for header in headers:
        private_key_eph = nacl.public.PrivateKey.generate()
        header_content = crypt4gh.header.make_packet_data_enc(0, header["session_key"])
        header_packets = crypt4gh.header.encrypt(
            header_content, [(0, private_key_eph.encode(), pubkey)]
        )
        header_bytes: bytes = crypt4gh.header.serialize(header_packets)

        sd_lock_utility.common.conditional_echo_debug(
            opts,
            f"Uploading header {header['path']} to Vault for bucket {session['container']}",
        )
        await sd_lock_utility.client.push_header(
            session,
            header_bytes,
            header["path"],
        )

        sd_lock_utility.common.conditional_echo_verbose(
            opts,
            f"Added header for {header['path']} in new bucket {session['container']}",
        )
        total += 1

    return total


async def copy_bucket_shared_access(
    opts: sd_lock_utility.types.SDHeaderMigrate,
    session: sd_lock_utility.types.SDAPISession,
    receiver: str,
):
    """Copy over SD Connect additional sharing entry from old bucket."""
    # Retrieve the previous vault sharing for the project (i.e. check if it exists)
    vault_sharing: sd_lock_utility.types.VaultSharedProjectId | None = (
        await sd_lock_utility.client.check_folder_share_whitelist(
            session,
            opts["container"],
            receiver,
        )
    )

    if vault_sharing is None:
        sd_lock_utility.common.conditional_echo_debug(
            opts, "Skipping vault sharing migration due to empty response"
        )
        return

    sd_lock_utility.common.conditional_echo_debug(
        opts, f"Got following vault sharing response: {vault_sharing}"
    )

    await sd_lock_utility.client.share_folder_to_project(
        session,
        receiver_id=vault_sharing["idkeystone"],
        receiver_name=vault_sharing["id"],
        container=opts["to_bucket"],
    )

    sd_lock_utility.common.conditional_echo_debug(opts, "Copied vault side sharing")


async def convert_bucket_acl(
    opts: sd_lock_utility.types.SDHeaderMigrate,
    session: sd_lock_utility.types.SDAPISession,
):
    """Convert old bucket Swift ACL to the new bucket s3 bucket policy."""
    # Retrieve the old sharing information of the bucket
    acl: list[sd_lock_utility.types.ProjectACLWhitelist] = (
        await sd_lock_utility.os_client.openstack_get_container_acl(
            session,
            opts["container"],
        )
    )

    sd_lock_utility.common.conditional_echo_debug(
        opts, f"Migrating following ACLs: {acl}"
    )

    statements: list[sd_lock_utility.types.AWSBucketPolicyStatement] = []

    for share in acl:
        new_statement: sd_lock_utility.types.AWSBucketPolicyStatement = {
            "Sid": "GrantSDConnectSharedAccessToProject",
            "Effect": "Allow",
            "Principal": {
                "AWS": f"arn:aws:iam::{share['project']}:root",
            },
            "Action": [
                "s3:GetObject",
                "s3:ListBucket",
                "s3:GetObjectTagging",
                "s3:GetObjectVersion",
            ],
            "Resource": [
                f"arn:aws:s3:::{opts['to_bucket']}",
                f"arn:aws:s3:::{opts['to_bucket']}/*",
            ],
        }

        # Add requirements for write rights if the write grant exists
        if share["write"]:
            new_statement["Action"].extend(
                [
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:AbortMultipartUpload",
                    "s3:ListMultipartUploadParts",
                    "s3:ListBucketMultipartUploads",
                ]
            )

        # If the bucket name has changed, copy over vault sharing.
        # (no need to migrate vault sharing if we're just converting the shares)
        if opts["container"] != opts["to_bucket"]:
            await copy_bucket_shared_access(opts, session, share["project"])

        statements.append(new_statement)

    policy: sd_lock_utility.types.AWSBucketPolicy = {
        "Version": "2012-10-17",
        "Statement": statements,
    }

    # Add the new bucket policy to the new bucket
    await sd_lock_utility.s3_client.s3_add_bucket_policy(
        opts,
        session,
        opts["to_bucket"],
        policy,
    )


async def migrate_headers(opts: sd_lock_utility.types.SDHeaderMigrate):
    """Copy over the headers from a bucket after naming convention change."""
    if "to_bucket" not in opts:
        click.echo("No destination bucket was provided for the headers.", err=True)
        return 3

    try:
        session: sd_lock_utility.types.SDAPISession = (
            await sd_lock_utility.client.open_session(
                container=opts["container"],
                address=opts["sd_connect_address"],
                project_id=opts["project_id"],
                project_name=opts["project_name"],
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
    except sd_lock_utility.exceptions.NoProject:
        click.echo("No Openstack project information was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoContainer:
        click.echo("No bucket was provided as a source for the headers.")

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
            total = await bucket_copy_headers(opts, session)
            if total == 0:
                click.echo(
                    f"No headers were migrated to the new bucket {opts['to_bucket']}."
                )
            if total == 1:
                click.echo(f"Migrated one header to the new bucket {opts['to_bucket']}.")
            else:
                click.echo(
                    f"Migrated {total} headers to the new bucket {opts['to_bucket']}"
                )
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
        elif cex.status == 404 and not opts["debug"]:
            click.echo("The queried project does not exist in cache.", err=True)
            click.echo(
                "The project might not yet have logged in to SD Connect.", err=True
            )
        else:
            exc = cex
    finally:
        if exc is not None:
            click.echo("Program encountered an unhandled exception.", err=True)
            click.echo(
                "If you think there's a mistake, copy this message and lines after it, and include it in your support request for diagnostic purposes.",
                err=True,
            )
            click.echo(
                "If possible, include instructions on how to replicate the issue (what you did in order to make this happen)",
                err=True,
            )
            click.echo("Exception details:", err=True)
            click.echo(
                "-------------------------- BEGIN EXCEPTION TRACEBACK --------------------------"
            )
            raise exc

    return ret


async def migrate_bucket_sharing(opts: sd_lock_utility.types.SDHeaderMigrate):
    """Copy the shared access between buckets."""
    if "to_bucket" not in opts:
        click.echo("No destination bucket was provided sharing.", err=True)
        return 3

    try:
        session: sd_lock_utility.types.SDAPISession = (
            await sd_lock_utility.client.open_session(
                container=opts["container"],
                address=opts["sd_connect_address"],
                project_id=opts["project_id"],
                project_name=opts["project_name"],
                token=opts["sd_api_token"],
                os_auth_url=opts["openstack_auth_url"],
                no_check_certificate=opts["no_check_certificate"],
                # No --s3 flag needed, as the ACL migration is always from swift -> s3
                use_s3=True,
                ec2_access_key=opts["ec2_access_key"],
                ec2_secret_key=opts["ec2_secret_key"],
                s3_endpoint_url=opts["s3_endpoint_url"],
            )
        )

    except sd_lock_utility.exceptions.NoToken:
        click.echo("No API access token was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoAddress:
        click.echo("No API address was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoProject:
        click.echo("No Openstack project information was provided.", err=True)
        return 3
    except sd_lock_utility.exceptions.NoContainer:
        click.echo("No bucket was provided as a source for the headers.")

    exc: typing.Any = None
    ret = 0
    try:
        async with aiohttp.ClientSession(
            raise_for_status=True,
        ) as cs:
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
                    click.echo("Using S3, but could not initialize credentials.")
                    click.echo(
                        "Provide S3 credentials using the command line or environment."
                    )
                    click.echo(
                        "Alternatively provide Openstack auth information for automatic S3 configuration."
                    )
                    return 3

            async with aioboto3.Session().client(
                service_name="s3",
                endpoint_url=session["s3_endpoint_url"],
                aws_access_key_id=session["ec2_access_key"],
                aws_secret_access_key=session["ec2_secret_key"],
            ) as s3:
                session["s3_client"] = s3
                await convert_bucket_acl(opts, session)
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
        elif cex.status == 404 and not opts["debug"]:
            click.echo("The queried project does not exist in cache.", err=True)
            click.echo(
                "The project might not yet have logged in to SD Connect.", err=True
            )
        else:
            exc = cex
    finally:
        if exc is not None:
            click.echo("Program encountered an unhandled exception.", err=True)
            click.echo(
                "If you think there's a mistake, copy this message and lines after it, and include it in your support request for diagnostic purposes.",
                err=True,
            )
            click.echo(
                "If possible, include instructions on how to replicate the issue (what you did in order to make this happen)",
                err=True,
            )
            click.echo("Exception details:", err=True)
            click.echo(
                "-------------------------- BEGIN EXCEPTION TRACEBACK --------------------------"
            )
            raise exc

    return ret
