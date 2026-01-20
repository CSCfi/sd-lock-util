"""Test functions for common module."""

import types

import unittest
import unittest.mock

import sd_lock_utility.common

import tests.mockups


class TestOSClient(tests.mockups.SDLockUtilTestBase):
    """Class for testing the common functions."""

    def setUp(self):
        """."""
        super().setUp()

    async def test_openstack_download_decrypted_object(self):
        """Test correctly downloading an decrypted object."""
        mock_file = types.SimpleNamespace(
            **{
                "write": unittest.mock.AsyncMock(),
            }
        )
        mock_aiofiles = unittest.mock.Mock(return_value=self.mock_handler(mock_file))
        patch_aiofiles = unittest.mock.patch(
            "sd_lock_utility.common.aiofiles.open", mock_aiofiles
        )

        mock_reads = [b"123456789012a", b"123456789012b", b"123456789012c"]

        async def mock_readexactly(_):
            if mock_reads:
                return mock_reads.pop()
            return []

        self.mock_response.content.readexactly = mock_readexactly
        self.mock_response.headers["Content-Length"] = 3

        mock_encrypt = unittest.mock.Mock(return_value=b"a")
        patch_encrypt = unittest.mock.patch(
            "sd_lock_utility.common.nacl.bindings.crypto_aead_chacha20poly1305_ietf_decrypt",
            mock_encrypt,
        )

        with patch_aiofiles, patch_encrypt:
            await sd_lock_utility.common.decrypt_object_get_stream(
                self.mock_response.content,
                {"progress": False},
                self.test_session,
                {
                    "path": "test/file",
                    "localpath": "test/file",
                    "session_key": "test-key",
                },
                None,
            )

        mock_encrypt.assert_any_call(b"a", None, b"123456789012", "test-key")
        mock_encrypt.assert_any_call(b"b", None, b"123456789012", "test-key")
        mock_encrypt.assert_any_call(b"c", None, b"123456789012", "test-key")
        mock_file.write.assert_any_call(b"a")
