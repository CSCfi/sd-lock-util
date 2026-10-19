"""Functions for accessing s3."""

import asyncio
import json
import pathlib
import typing

import aiobotocore.response
import aiofiles
import click
import nacl.bindings
import nacl.exceptions
from botocore.exceptions import ClientError
from types_aiobotocore_s3.type_defs import CompletedPartTypeDef

import sd_lock_utility.client
import sd_lock_utility.common
import sd_lock_utility.exceptions
import sd_lock_utility.os_client
import sd_lock_utility.types

# Size of ciperthext of encrypted c4gh chunk
C4GH_CIPHERTEXT_SIZE: int = 65536
# Ciphertext + nonce + tag
C4GH_CHUNK_SIZE: int = C4GH_CIPHERTEXT_SIZE + 12 + 16
CHUNKS_PER_PART: int = 5000


async def s3_check_container(
    session: sd_lock_utility.types.SDAPISession,
    opts: sd_lock_utility.types.SDCommandBaseOptions,
    container: str,
) -> None:
    """Check the container can be accessed."""
    if session["s3_client"] is None:
        raise sd_lock_utility.exceptions.NoS3Client

    try:
        await session["s3_client"].head_bucket(Bucket=container)
    except ClientError as e:
        if e.response["ResponseMetadata"]["HTTPStatusCode"] == 400:
            raise sd_lock_utility.exceptions.S3IncompatibleBucketName
        if e.response["ResponseMetadata"]["HTTPStatusCode"] == 403:
            raise sd_lock_utility.exceptions.NoContainerAccess
        if e.response["ResponseMetadata"]["HTTPStatusCode"] == 404:
            raise sd_lock_utility.exceptions.ContainerNotFound


async def s3_create_container(
    session: sd_lock_utility.types.SDAPISession,
    opts: sd_lock_utility.types.SDCommandBaseOptions,
) -> None:
    """Ensure the upload container exists."""
    if session["s3_client"] is None:
        raise sd_lock_utility.exceptions.NoS3Client

    await sd_lock_utility.client.check_shared_status(session)
    if session["owner"]:
        sd_lock_utility.common.conditional_echo_debug(
            opts, "Uploading to a shared container, skipping container creation."
        )
        return

    container = session["container"]
    try:
        sd_lock_utility.common.conditional_echo_debug(
            opts, f"Checking access to container {container}"
        )
        await s3_check_container(session, opts, container)
    except sd_lock_utility.exceptions.ContainerNotFound:
        sd_lock_utility.common.conditional_echo_debug(
            opts, f"Container {container} not found, trying to create"
        )
        try:
            await session["s3_client"].create_bucket(Bucket=container)
        except ClientError:
            raise sd_lock_utility.exceptions.ContainerCreationFailed
    except Exception as e:
        sd_lock_utility.common.conditional_echo_debug(
            opts, f"Unhandled exception when creating container: {e}"
        )
        raise sd_lock_utility.exceptions.ContainerCreationFailed


async def s3_upload_encrypted_part(
    opts: sd_lock_utility.types.SDLockOptions,
    session: sd_lock_utility.types.SDAPISession,
    key: str,
    order_number: int,
    length: int,
    file: sd_lock_utility.types.SDUtilFile,
    upload_id: str,
    bar: typing.Any,
) -> CompletedPartTypeDef:
    """Upload a sliced encrypted segment to s3 using multipart upload."""
    if session["s3_client"]:
        part_url: str = await session["s3_client"].generate_presigned_url(
            ClientMethod="upload_part",
            Params={
                "Bucket": session["container"],
                "Key": key,
                "PartNumber": order_number + 1,
                "UploadId": upload_id,
                # "ChecksumMD5": migration_object_part["ETag"],
            },
            ExpiresIn=(3600 * 4),  # Expire the URL in 4 hours
        )
    else:
        raise sd_lock_utility.exceptions.NoS3Client

    checksum: sd_lock_utility.types.LockUtilChecksum = {"md5": ""}
    sd_lock_utility.common.conditional_echo_debug(
        opts,
        f"Attempting presigned part upload for {key}, part {order_number}, size {length}.",
    )

    if not session["client"]:
        raise sd_lock_utility.exceptions.NoClient

    async with session["client"].put(
        part_url,
        headers={
            "Content-Length": str(length),
        },
        data=sd_lock_utility.os_client.slice_encrypted_segment(
            opts, session, file, order_number, bar, CHUNKS_PER_PART, checksum
        ),
    ) as resp:
        if not checksum["md5"]:
            sd_lock_utility.common.conditional_echo_verbose(
                opts, "Got no ETag from slicer."
            )
        elif checksum["md5"] != resp.headers["Etag"].replace('"', ""):
            sd_lock_utility.common.conditional_echo_verbose(
                opts,
                f"Calculated ETag {checksum['md5']} and response ETag {resp.headers['Etag']} mismatch.",  # nosec  # noqa: S324
            )
        else:
            sd_lock_utility.common.conditional_echo_debug(
                opts,
                f"Calculated ETag {checksum['md5']} and response ETag {resp.headers['Etag']} match.",  # nosec  # noqa: S324
            )

        return {
            "PartNumber": order_number + 1,
            "ETag": checksum["md5"],
        }


def get_last_segment_size(
    size: int,
) -> int:
    """Calculate the size of the last segment."""
    last_ciphertext_size = size % (C4GH_CIPHERTEXT_SIZE * CHUNKS_PER_PART)
    last_chunk_size = last_ciphertext_size // C4GH_CIPHERTEXT_SIZE * C4GH_CHUNK_SIZE
    if last_ciphertext_size % C4GH_CIPHERTEXT_SIZE > 0:
        last_chunk_size += last_ciphertext_size % C4GH_CIPHERTEXT_SIZE + 12 + 16

    return last_chunk_size


async def s3_upload_encrypted_file(
    opts: sd_lock_utility.types.SDLockOptions,
    session: sd_lock_utility.types.SDAPISession,
    file: sd_lock_utility.types.SDUtilFile,
    size: int,
    bar: typing.Any,
) -> None:
    """Upload an encrypted file using s3."""
    if session["s3_client"] is None:
        raise sd_lock_utility.exceptions.NoS3Client

    bucket: str = session["container"]
    key: str = f"{str(file['path'])}.c4gh"
    await s3_create_container(session, opts)
    sd_lock_utility.common.conditional_echo_debug(
        opts, f"Starting multipart upload for {bucket}/{key}"
    )

    try:
        mpu = await session["s3_client"].create_multipart_upload(Bucket=bucket, Key=key)
        upload_id = mpu["UploadId"]
        parts: list[CompletedPartTypeDef] = []

        total_parts = -(-size // (CHUNKS_PER_PART * C4GH_CIPHERTEXT_SIZE))
        for order_number in range(0, total_parts):
            new_part: CompletedPartTypeDef = await s3_upload_encrypted_part(
                opts,
                session,
                key,
                order_number,
                (
                    C4GH_CHUNK_SIZE * CHUNKS_PER_PART
                    if order_number < total_parts - 1
                    else get_last_segment_size(size)
                ),
                file,
                upload_id,
                bar,
            )
            parts.append(new_part)

        sd_lock_utility.common.conditional_echo_debug(
            opts, f"Attempting to complete multipart upload for {key}"
        )
        # Complete upload
        await session["s3_client"].complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )
        sd_lock_utility.common.conditional_echo_debug(opts, f"Upload complete for {key}")
    except ClientError as e:
        if e.response["ResponseMetadata"]["HTTPStatusCode"] in [403, 404]:
            raise sd_lock_utility.exceptions.NoContainerAccess
    except (asyncio.CancelledError, Exception) as e:
        # multipart upload exists only if upload_id exists
        sd_lock_utility.common.conditional_echo_debug(
            opts, f"Encountered an exception: {e}"
        )
        if "upload_id" in locals():
            await session["s3_client"].abort_multipart_upload(
                Bucket=bucket, Key=key, UploadId=upload_id
            )
            sd_lock_utility.common.conditional_echo_debug(
                opts, f"Multipart upload aborted for {key}"
            )


async def s3_download_decrypted_object(
    body: aiobotocore.response.StreamingBody,
    opts: sd_lock_utility.types.SDUnlockOptions,
    session: sd_lock_utility.types.SDAPISession,
    file: sd_lock_utility.types.SDUtilFile,
    bar: typing.Any,
) -> None:
    """Download and decrypt object from object storage."""
    async with aiofiles.open(file["localpath"], "wb") as out_f:
        while True:
            try:
                chunk = await body.readexactly(C4GH_CHUNK_SIZE)
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
                click.echo(f"Could not decrypt{file['path']}.c4gh", err=True)
                break

            if bar:
                bar.update(len(chunk))


async def s3_download_decrypted_object_wrap_progress(
    opts: sd_lock_utility.types.SDUnlockOptions,
    session: sd_lock_utility.types.SDAPISession,
    file: sd_lock_utility.types.SDUtilFile,
) -> int:
    """Download and decrypt an object from storage with optional progress bar."""
    if session["s3_client"] is None:
        raise sd_lock_utility.exceptions.NoS3Client

    sd_lock_utility.common.conditional_echo_debug(
        opts, f"Downloading and decrypting file {file['path']}"
    )

    # Use a presigned URL to be able to use bare aiohttp as client
    # This allows for increased performance as the client is chunk size aware
    object_url: str = await session["s3_client"].generate_presigned_url(
        "get_object",
        Params={
            "Bucket": session["container"],
            "Key": str(file["path"]) + ".c4gh",
        },
        ExpiresIn=24 * 3600,
    )
    sd_lock_utility.common.conditional_echo_debug(opts, f"{object_url}")

    if session["client"] is None:
        return 1

    async with session["client"].get(object_url) as resp:
        size: int = int(resp.headers["Content-Length"])

        if opts["progress"]:
            # Can't annotate progress bar without using click internal vars
            with click.progressbar(  # type: ignore
                length=size, label=f"Downloading and decrypting {file['path']}.c4gh"
            ) as bar:
                await sd_lock_utility.common.decrypt_object_get_stream(
                    resp.content, opts, session, file, bar
                )
        else:
            await sd_lock_utility.common.decrypt_object_get_stream(
                resp.content, opts, session, file, None
            )

    return 0


async def s3_get_container_objects(
    session: sd_lock_utility.types.SDAPISession,
    prefix: str = "",
) -> list[tuple[pathlib.Path, list[str], list[str]]]:
    """Get the contents of a container in object storage."""
    if session["s3_client"] is None:
        raise sd_lock_utility.exceptions.NoS3Client

    ret: list[str] = []
    paginator = session["s3_client"].get_paginator("list_objects_v2")
    async for page in paginator.paginate(Bucket=session["container"], Prefix=prefix):
        for obj in page.get("Contents", []):
            ret.append(obj["Key"])

    return [(pathlib.Path("."), [], ret)]


async def s3_get_bucket_policy(
    opts: sd_lock_utility.types.SDCommandBaseOptions,
    session: sd_lock_utility.types.SDAPISession,
    bucket: str,
) -> sd_lock_utility.types.AWSBucketPolicy:
    """Get the current bucket policy of a bucket."""
    if session["s3_client"] is None:
        raise sd_lock_utility.exceptions.NoS3Client

    sd_lock_utility.common.conditional_echo_debug(
        opts, f"Fetching bucket policy for bucket {bucket}"
    )

    try:
        resp = await session["s3_client"].get_bucket_policy(Bucket=bucket)
        if resp["Policy"]:
            try:
                return json.loads(resp["Policy"])
            except json.JSONDecodeError:
                # Log incorrectly formatted json to debug, continue to empty return
                sd_lock_utility.common.conditional_echo_debug(
                    opts, f"Failed to decode policy {resp['Policy']}"
                )
                # Let execution continue, assume policy is empty or can be overridden
    except ClientError as e:
        if e.response["ResponseMetadata"]["HTTPStatusCode"] == 403:
            raise sd_lock_utility.exceptions.NoContainerAccess
        elif e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            # Let code proceed to returning empty policy if policy doesn't exists
            pass
        else:
            # Includes NoSuchBucket
            raise e

    return {
        "Version": "2012-10-17",
        "Statement": [],
    }


async def s3_add_bucket_policy(
    opts: sd_lock_utility.types.SDCommandBaseOptions,
    session: sd_lock_utility.types.SDAPISession,
    bucket: str,
    policy: sd_lock_utility.types.AWSBucketPolicy,
):
    """Add a bucket policy to a bucket."""
    if session["s3_client"] is None:
        raise sd_lock_utility.exceptions.NoS3Client

    sd_lock_utility.common.conditional_echo_debug(
        opts,
        f"Adding bucket policy: {policy}",
    )

    pol_json = json.dumps(policy)

    sd_lock_utility.common.conditional_echo_debug(opts, f"Jsonified policy: {pol_json}")

    try:
        await session["s3_client"].put_bucket_policy(
            Bucket=bucket,
            Policy=pol_json,
        )
    except ClientError as e:
        if e.response["ResponseMetadata"]["HTTPStatusCode"] in [403, 404]:
            raise sd_lock_utility.exceptions.NoContainerAccess
        raise e
