import asyncio
import hashlib
from io import BytesIO
import pathlib
import secrets
import typing

import aiofiles
import click
import nacl.bindings
import nacl.exceptions
import sd_lock_utility.types
import sd_lock_utility.client
import sd_lock_utility.exceptions
import sd_lock_utility.common
import aiobotocore.response
from botocore.exceptions import ClientError
from types_aiobotocore_s3.type_defs import CompletedPartTypeDef


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
    except ClientError:
        raise sd_lock_utility.exceptions.NoContainerAccess
    except Exception as e:
        sd_lock_utility.common.conditional_echo_debug(
            opts, f"Unhandled exception when checking container: {e}"
        )  # FIXME


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
    except sd_lock_utility.exceptions.NoContainerAccess:
        sd_lock_utility.common.conditional_echo_debug(
            opts, f"Could not access container {container}, trying to create"
        )
        try:
            await session["s3_client"].create_bucket(Bucket=container)
        except ClientError:
            raise sd_lock_utility.exceptions.ContainerCreationFailed
    except Exception as e:
        sd_lock_utility.common.conditional_echo_debug(
            opts, f"Unhandled exception when creating container: {e}"
        )  # FIXME


async def encrypt_and_slice_file(
    opts: sd_lock_utility.types.SDLockOptions,
    session: sd_lock_utility.types.SDAPISession,
    file: sd_lock_utility.types.SDUtilFile,
    bar: typing.Any,
) -> typing.AsyncGenerator[bytes, None]:
    """Slice a file into an async generator of encrypted chunks ready for multipart upload."""
    multipart_upload_size: int = (65536 + 12 + 16) * 1000
    multipart_chunk: bytes = b""
    try:
        async with aiofiles.open(file["localpath"], "rb") as f:
            while True:
                chunk = await f.read(65536)
                if not chunk:
                    yield multipart_chunk

                    return

                nonce = secrets.token_bytes(12)
                segment = nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
                    chunk,
                    None,
                    nonce,
                    file["session_key"],
                )
                if bar:
                    bar.update(len(chunk))

                multipart_chunk += nonce + segment
                if len(multipart_chunk) >= multipart_upload_size:
                    yield multipart_chunk
                    multipart_chunk = b""

    except Exception as e:
        sd_lock_utility.common.conditional_echo_debug(opts, f"Error slicing: {e}")


async def s3_upload_encrypted_segment(
    opts: sd_lock_utility.types.SDLockOptions,
    session: sd_lock_utility.types.SDAPISession,
    file: sd_lock_utility.types.SDUtilFile,
    bar: typing.Any,
) -> None:
    """Upload a sliced encrypted segment to S3 using multipart upload."""
    if session["s3_client"] is None:
        raise sd_lock_utility.exceptions.NoS3Client

    bucket: str = session["container"]
    key: str = f"{str(file["path"])}.c4gh"
    await s3_create_container(session, opts)
    sd_lock_utility.common.conditional_echo_debug(
        opts, f"Starting multipart upload for {bucket}/{key}"
    )

    try:
        mpu = await session["s3_client"].create_multipart_upload(Bucket=bucket, Key=key)
        upload_id = mpu["UploadId"]
        parts: list[CompletedPartTypeDef] = []

        part_number: int = 1
        async for chunk in encrypt_and_slice_file(opts, session, file, bar):
            if not chunk:
                break
            sd_lock_utility.common.conditional_echo_debug(
                opts, f"Uploading a chunk of size {len(chunk)}"
            )
            resp = await session["s3_client"].upload_part(
                ContentLength=len(chunk),
                Bucket=bucket,
                Key=key,
                PartNumber=part_number,
                UploadId=upload_id,
                Body=BytesIO(chunk),
            )
            if hashlib.md5(chunk).hexdigest() not in resp["ETag"]:  # nosec
                sd_lock_utility.common.conditional_echo_debug(
                    opts,
                    f"Calculated ETag {hashlib.md5(chunk).hexdigest()} and response ETag {resp["ETag"]} mismatch",  # nosec
                )
            parts.append({"PartNumber": part_number, "ETag": str(resp["ETag"])})
            part_number += 1

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


async def s3_buffered_reader(
    body: aiobotocore.response.StreamingBody,
) -> typing.AsyncGenerator[bytes, None]:
    """Helper function to construct chunks from ClientResponse stream"""
    CHUNKSIZE: int = 65564
    buffer = bytearray()
    # Using chunk size doesn't really do anything here, since function will return anything between 0 and chunksize
    async for chunk in body.content.iter_chunked(CHUNKSIZE):
        buffer.extend(chunk)

        while len(buffer) >= CHUNKSIZE:
            yield bytes(buffer[:CHUNKSIZE])
            buffer = buffer[CHUNKSIZE:]

    if buffer:
        yield bytes(buffer)


async def s3_download_decrypted_object(
    body: aiobotocore.response.StreamingBody,
    opts: sd_lock_utility.types.SDUnlockOptions,
    session: sd_lock_utility.types.SDAPISession,
    file: sd_lock_utility.types.SDUtilFile,
    bar: typing.Any,
) -> None:
    """Download and decrypt object from object storage."""
    async with aiofiles.open(file["localpath"], "wb") as out_f:

        async for chunk in s3_buffered_reader(body):
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
                return

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
    resp = await session["s3_client"].get_object(
        Bucket=session["container"], Key=str(file["path"]) + ".c4gh"
    )
    size: int = resp["ContentLength"]

    sd_lock_utility.common.conditional_echo_debug(opts, f"{resp}")

    async with resp["Body"] as body:
        if opts["progress"]:
            # Can't annotate progress bar without using click internal vars
            with click.progressbar(  # type: ignore
                length=int(size), label=f"Downloading and decrypting {file['path']}.c4gh"
            ) as bar:
                await s3_download_decrypted_object(body, opts, session, file, bar)
        else:
            await s3_download_decrypted_object(body, opts, session, file, None)

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
