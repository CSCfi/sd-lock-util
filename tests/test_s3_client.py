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

        error_response = {"Error": {"Code": "404"}}
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

    async def test_encrypt_and_slice_file(self):
        """Test slice_encrypted_segment should open and slice a file."""
        mock_file_content = [b"", b"1", b"2"]

        async def mock_file_read(len: int) -> bytes:
            return mock_file_content.pop()

        mock_file = types.SimpleNamespace(
            **{
                "read": mock_file_read,
            }
        )

        mock_aiofiles = unittest.mock.Mock(return_value=self.mock_handler(mock_file))
        patch_aiofiles = unittest.mock.patch(
            "sd_lock_utility.s3_client.aiofiles.open", mock_aiofiles
        )

        mock_urandom = unittest.mock.Mock(return_value=b"123456789012")
        patch_urandom = unittest.mock.patch(
            "sd_lock_utility.s3_client.secrets.token_bytes", mock_urandom
        )

        mock_encrypt = unittest.mock.Mock(return_value=b"test-encrypted")
        patch_encrypt = unittest.mock.patch(
            "sd_lock_utility.s3_client.nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt",
            mock_encrypt,
        )

        ret = []
        with patch_aiofiles, patch_urandom, patch_encrypt:
            async for seg in sd_lock_utility.s3_client.encrypt_and_slice_file(
                {"progress": True},
                self.test_session,
                {
                    "path": "test-path",
                    "localpath": "test-path",
                    "session_key": "test-key",
                },
                None,
            ):
                ret.append(seg)

        mock_urandom.assert_called_with(12)
        mock_encrypt.assert_called()
        self.assertIn(b"123456789012test-encrypted123456789012test-encrypted", ret)

    async def test_s3_upload_encrypted_file_success(self):
        """Test uploading encrypted file of 2 parts"""
        session = self.test_session
        session["s3_client"] = unittest.mock.AsyncMock()
        opts = {"debug": False}

        session["s3_client"].create_multipart_upload.return_value = {"UploadId": "123"}

        async def upload_part(**kwargs):
            return {"ETag": f"\"{kwargs['Body'].getvalue().hex()}\""}

        session["s3_client"].upload_part.side_effect = upload_part

        async def fake_generator():
            yield b"chunkdata1"
            yield b"chunkdata2"

        mock_slice_segment = unittest.mock.Mock(return_value=fake_generator())
        patch_slice_segment = unittest.mock.patch(
            "sd_lock_utility.s3_client.encrypt_and_slice_file", mock_slice_segment
        )

        mock_create_container = unittest.mock.AsyncMock()
        patch_create_container = unittest.mock.patch(
            "sd_lock_utility.s3_client.s3_create_container", mock_create_container
        )

        with patch_slice_segment, patch_create_container:
            await sd_lock_utility.s3_client.s3_upload_encrypted_file(
                opts, session, {"path": "test/path"}, None
            )

        parts = [
            {"PartNumber": 1, "ETag": '"6368756e6b6461746131"'},
            {"PartNumber": 2, "ETag": '"6368756e6b6461746132"'},
        ]

        mock_create_container.assert_awaited_once_with(session, opts)
        session["s3_client"].create_multipart_upload.assert_awaited_once()
        session["s3_client"].upload_part.assert_awaited()
        session["s3_client"].complete_multipart_upload.assert_awaited_once_with(
            Bucket=session["container"],
            Key="test/path.c4gh",
            UploadId="123",
            MultipartUpload={"Parts": parts},
        )
