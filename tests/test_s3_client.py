"""Test functions in the s3_client module."""

import types
import unittest
import unittest.mock

import sd_lock_utility.s3_client

import tests.mockups

from botocore.exceptions import ClientError


class TestS3Client(tests.mockups.SDLockUtilTestBase):
    """Class for testing s3 client."""

    async def test_s3_create_container_no_access(self):
        session = self.test_session
        session["s3_client"] = unittest.mock.AsyncMock()
        opts = {"debug": False}

        error_response = {
            "Error": {"Code": "NoSuchBucket"},
            "ResponseMetadata": {"HTTPStatusCode": 404},
        }
        session["s3_client"].head_bucket.side_effect = ClientError(
            error_response, "HeadBucket"
        )

        with unittest.mock.patch(
            "sd_lock_utility.client.check_shared_status",
            new_callable=unittest.mock.AsyncMock,
        ):

            await sd_lock_utility.s3_client.s3_create_container(session, opts)

        session["s3_client"].create_bucket.assert_awaited_once_with(
            Bucket=session["container"]
        )

    async def test_s3_upload_encrypted_part_success(self):
        """Test s3_upload_encrypted_part function."""
        session = self.test_session
        session["s3_client"] = unittest.mock.AsyncMock()
        opts = {"debug": False, "verbose": False}

        session["s3_client"].generate_presigned_url.return_value = "https://test-url"

        self.mock_response.headers["Etag"] = "exampleETag"

        async def fake_generator(**kwargs):
            yield b"chunkdata1"
            yield b"chunkadat2"

            if "checksum" in kwargs:
                kwargs["checksum"]["md5"] = "exampleETag"

        mock_slice_segment = unittest.mock.Mock(return_value=fake_generator())
        patch_slice_segment = unittest.mock.patch(
            "sd_lock_utility.s3_client.sd_lock_utility.os_client.slice_encrypted_segment",
            mock_slice_segment,
        )

        with patch_slice_segment:
            ret_part = await sd_lock_utility.s3_client.s3_upload_encrypted_part(
                opts,
                session,
                "test-key",
                0,
                15000,
                {"path": "test/path"},
                "test-upload-id",
                None,
            )

        mock_slice_segment.assert_called_once()
        self.assertEqual("exampleETag", ret_part["ETag"])
        self.assertEqual(1, ret_part["PartNumber"])
        session["s3_client"].generate_presigned_url.assert_awaited()

    async def test_s3_upload_encrypted_file_success(self):
        """Test uploading encrypted file of 2 parts"""
        session = self.test_session
        session["s3_client"] = unittest.mock.AsyncMock()
        opts = {"debug": False, "verbose": False}

        session["s3_client"].create_multipart_upload.return_value = {"UploadId": "123"}

        parts = [
            {"PartNumber": 1, "ETag": '"6368756e6b6461746131"'},
            {"PartNumber": 2, "ETag": '"6368756e6b6461746132"'},
        ]
        side_effect_parts = parts.copy()

        mock_upload_encrypted_part = unittest.mock.AsyncMock(
            side_effect=side_effect_parts
        )
        patch_upload_encrypted_part = unittest.mock.patch(
            "sd_lock_utility.s3_client.s3_upload_encrypted_part",
            mock_upload_encrypted_part,
        )

        mock_create_container = unittest.mock.AsyncMock()
        patch_create_container = unittest.mock.patch(
            "sd_lock_utility.s3_client.s3_create_container", mock_create_container
        )

        with patch_upload_encrypted_part, patch_create_container:
            await sd_lock_utility.s3_client.s3_upload_encrypted_file(
                opts, session, {"path": "test/path"}, 536870912, None
            )

        mock_create_container.assert_awaited_once_with(session, opts)
        session["s3_client"].create_multipart_upload.assert_awaited_once()
        mock_upload_encrypted_part.assert_awaited()
        session["s3_client"].complete_multipart_upload.assert_awaited_once_with(
            Bucket=session["container"],
            Key="test/path.c4gh",
            UploadId="123",
            MultipartUpload={"Parts": parts},
        )
