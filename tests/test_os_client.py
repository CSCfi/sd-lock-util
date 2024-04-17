"""Test functions in the os_client module."""

import types
import unittest
import unittest.mock

import sd_lock_utility.os_client

import tests.mockups


class TestOSClient(tests.mockups.SDLockUtilTestBase):
    """Class for testing openstack client."""

    def setUp(self):
        """."""
        super().setUp()
        self.time_mock = unittest.mock.Mock(return_value=1000)
        self.time_patch = unittest.mock.patch(
            "sd_lock_utility.os_client.time.time",
            self.time_mock,
        )

    async def test_openstack_get_token_should_return_the_existing_token_if_valid(self):
        """Test that openstack_get_token returns current token if valid."""
        with self.time_patch:
            ret = await sd_lock_utility.os_client.openstack_get_token(self.test_session)

        self.assertEqual(ret, self.test_session["openstack_token"])

    async def test_openstack_get_token_should_create_a_new_token_invalid(self):
        """Test that openstack_get_token creates new token if expired."""
        self.test_session["openstack_token_valid_until"] = 1

        self.mock_response.headers["X-Subject-Token"] = "creation-test-token"
        self.mock_response.json.return_value = {
            "token": {
                "user": {
                    "name": "test-user",
                },
                "roles": [
                    {
                        "name": "object_store_user",
                    },
                ],
                "catalog": [
                    {
                        "type": "object-store",
                        "id": "test-id",
                        "name": "swift",
                        "endpoints": [
                            {
                                "region_id": "default",
                                "url": "https://test-swift:443/swift/v1/AUTH_test-id-0",
                                "region": "default",
                                "interface": "admin",
                                "id": "test-id",
                            },
                            {
                                "region_id": "default",
                                "url": "https://test-swift:443/swift/v1/AUTH_test-id-0",
                                "region": "default",
                                "interface": "public",
                                "id": "test-id",
                            },
                            {
                                "region_id": "default",
                                "url": "https://test-swift:443/swift/v1/AUTH_test-id-0",
                                "region": "default",
                                "interface": "internal",
                                "id": "test-id",
                            },
                        ],
                    },
                ],
            },
        }

        with self.time_patch:
            ret = await sd_lock_utility.os_client.openstack_get_token(self.test_session)

        self.time_mock.assert_called()
        self.test_session["client"].post.assert_called_once_with(
            "http://openstack-test-auth-url/auth/tokens",
            **{
                "json": {
                    "auth": {
                        "identity": {
                            "methods": [
                                "password",
                            ],
                            "password": {
                                "user": {
                                    "name": "test-username",
                                    "domain": {
                                        "name": "test-user-domain",
                                    },
                                    "password": "test-password",
                                },
                            },
                        },
                        "scope": {
                            "project": {
                                "id": "test-project-id",
                            },
                        },
                    },
                },
            },
        )
        self.mock_response.json.assert_awaited_once()
        self.assertEqual(ret, "creation-test-token")

    async def test_slice_encrtypted_segment(self):
        """Test slice_encrypted_segment should open and slice a file."""
        mock_file_content = [b"", b"1", b"2", b"3", b"4", b"5"]

        async def mock_file_read(len: int) -> bytes:
            return mock_file_content.pop()

        mock_file = types.SimpleNamespace(
            **{
                "seek": unittest.mock.AsyncMock(),
                "read": mock_file_read,
            }
        )
        mock_aiofiles = unittest.mock.Mock(return_value=self.mock_handler(mock_file))
        patch_aiofiles = unittest.mock.patch(
            "sd_lock_utility.os_client.aiofiles.open", mock_aiofiles
        )

        mock_urandom = unittest.mock.Mock(return_value=b"123456789012")
        patch_urandom = unittest.mock.patch(
            "sd_lock_utility.os_client.secrets.token_bytes", mock_urandom
        )

        mock_encrypt = unittest.mock.Mock(return_value=b"test-encrypted")
        patch_encrypt = unittest.mock.patch(
            "sd_lock_utility.os_client.nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt",
            mock_encrypt,
        )

        ret = []
        with patch_aiofiles, patch_urandom, patch_encrypt:
            async for seg in sd_lock_utility.os_client.slice_encrypted_segment(
                {"progress": True},
                self.test_session,
                {
                    "path": "test-path",
                    "localpath": "test-path",
                    "session_key": "test-key",
                },
                0,
                None,
            ):
                ret.append(seg)

        mock_file.seek.assert_awaited_once_with(0)
        mock_urandom.assert_called_with(12)
        mock_encrypt.assert_called()
        self.assertIn(b"123456789012test-encrypted", ret)

    async def test_openstack_check_container_raise_with_no_container_access(self):
        """Test that openstack_check_container raises if no access."""
        self.mock_response.status = 403
        with (
            self.time_patch,
            self.assertRaises(
                sd_lock_utility.os_client.sd_lock_utility.exceptions.NoContainerAccess
            ),
        ):
            await sd_lock_utility.os_client.openstack_check_container(
                self.test_session, "test-container"
            )

        self.test_session["client"].head.assert_called_once_with(
            "http://openstack-test-storage-endpoint/test-container",
            **{
                "headers": {
                    "Content-Length": "0",
                    "X-Auth-Token": "test-openstack-token",
                },
                "raise_for_status": False,
            },
        )

    async def test_openstack_create_container_create_container_if_no_access(self):
        """Test that openstack_create_container creates container if no access."""
        self.mock_response.status = 201
        patch_check_container = unittest.mock.patch(
            "sd_lock_utility.os_client.openstack_check_container",
            unittest.mock.AsyncMock(
                side_effect=sd_lock_utility.os_client.sd_lock_utility.exceptions.NoContainerAccess
            ),
        )

        with patch_check_container, self.time_patch:
            await sd_lock_utility.os_client.openstack_create_container(
                self.test_session, {"debug": False}
            )
        self.test_session["client"].put.assert_any_call(
            "http://openstack-test-storage-endpoint/test-container",
            **{
                "headers": {
                    "Content-Length": "0",
                    "X-Auth-Token": "test-openstack-token",
                },
            },
        )
        self.test_session["client"].put.assert_any_call(
            "http://openstack-test-storage-endpoint/test-container_segments",
            **{
                "headers": {
                    "Content-Length": "0",
                    "X-Auth-Token": "test-openstack-token",
                },
            },
        )

    async def test_openstack_create_container_raises_on_failure(self):
        """Test that openstack_create_container raises if can't create container."""
        self.mock_response.status = 400
        patch_check_container = unittest.mock.patch(
            "sd_lock_utility.os_client.openstack_check_container",
            unittest.mock.AsyncMock(
                side_effect=sd_lock_utility.os_client.sd_lock_utility.exceptions.NoContainerAccess
            ),
        )

        with (
            self.time_patch,
            patch_check_container,
            self.assertRaises(
                sd_lock_utility.os_client.sd_lock_utility.exceptions.ContainerCreationFailed
            ),
        ):
            await sd_lock_utility.os_client.openstack_create_container(
                self.test_session, {"debug": False}
            )

    async def test_openstack_upload_encrypted_segment(self):
        """Test that openstack_upload_encrypted_segment calls put."""
        patch_openstack_create_container = unittest.mock.patch(
            "sd_lock_utility.os_client.openstack_create_container",
            unittest.mock.AsyncMock(),
        )
        mock_slice_segment = unittest.mock.Mock(return_value="sliced_segment")
        patch_slice_segment = unittest.mock.patch(
            "sd_lock_utility.os_client.slice_encrypted_segment", mock_slice_segment
        )

        with patch_openstack_create_container, patch_slice_segment, self.time_patch:
            await sd_lock_utility.os_client.openstack_upload_encrypted_segment(
                {
                    "debug": False,
                },
                self.test_session,
                {"path": "test/path"},
                0,
                "test-uuid",
                None,
            )

        self.test_session["client"].put.assert_called_once_with(
            "http://openstack-test-storage-endpoint/test-container_segments/test/path.c4gh/test-uuid/00000001",
            **{
                "data": "sliced_segment",
                "headers": {"X-Auth-Token": "test-openstack-token"},
            },
        )
        mock_slice_segment.assert_called_once_with(
            {
                "debug": False,
            },
            self.test_session,
            {"path": "test/path"},
            0,
            None,
        )

    async def test_openstack_create_manifest(self):
        """Test openstack_create_manifest should create a manifest."""
        with self.time_patch:
            await sd_lock_utility.os_client.openstack_create_manifest(
                self.test_session, {"path": "test/path"}, "test-uuid"
            )

        self.test_session["client"].put.assert_called_once_with(
            "http://openstack-test-storage-endpoint/test-container/test/path.c4gh",
            **{
                "data": b"",
                "headers": {
                    "X-Auth-Token": "test-openstack-token",
                    "X-Object-Manifest": "test-container_segments/test/path.c4gh/test-uuid/",
                    "Content-Length": "0",
                },
            },
        )

    async def test_get_container_objects_page(self):
        """Test get_container_objects_page should properly return a page."""
        self.mock_response.json.return_value = [{"name": "test-object-1"}]

        with self.time_patch:
            ret = await sd_lock_utility.os_client.get_container_objects_page(
                self.test_session, marker="test-marker"
            )
        self.test_session["client"].get.assert_called_once_with(
            "http://openstack-test-storage-endpoint/test-container",
            **{
                "headers": {"X-Auth-Token": "test-openstack-token"},
                "params": {"format": "json", "marker": "test-marker"},
            },
        )
        self.assertEqual(ret, ["test-object-1"])

    async def test_get_container_objects(self):
        """Test get_container_objects gets all pages of container objects."""
        object_pages = ["test-object-1", "test-object-2", "test-object-3"]

        async def mock_test_object_page(*_, **__):
            if len(object_pages) > 0:
                return [object_pages.pop()]
            return []

        patch_objects_page = unittest.mock.patch(
            "sd_lock_utility.os_client.get_container_objects_page", mock_test_object_page
        )

        with patch_objects_page:
            ret = await sd_lock_utility.os_client.get_container_objects(self.test_session)

        self.assertEqual(
            ret, [("", [], ["test-object-3", "test-object-2", "test-object-1"])]
        )

    async def test_openstack_download_decrypted_object(self):
        """Test correctly downloading an decrypted object."""
        mock_file = types.SimpleNamespace(
            **{
                "write": unittest.mock.AsyncMock(),
            }
        )
        mock_aiofiles = unittest.mock.Mock(return_value=self.mock_handler(mock_file))
        patch_aiofiles = unittest.mock.patch(
            "sd_lock_utility.os_client.aiofiles.open", mock_aiofiles
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
            "sd_lock_utility.os_client.nacl.bindings.crypto_aead_chacha20poly1305_ietf_decrypt",
            mock_encrypt,
        )

        with patch_aiofiles, self.time_patch, patch_encrypt:
            await sd_lock_utility.os_client.openstack_download_decrypted_object(
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

    async def test_openstack_download_decrypted_object_wrap_progress(self):
        """Test correctly downloading an encrypted object without progress wrap."""
        mock_download = unittest.mock.AsyncMock()
        patch_download = unittest.mock.patch(
            "sd_lock_utility.os_client.openstack_download_decrypted_object", mock_download
        )

        self.mock_response.headers["Content-Length"] = 123

        with self.time_patch, patch_download:
            ret = await sd_lock_utility.os_client.openstack_download_decrypted_object_wrap_progress(
                {"progress": False, "debug": False},
                self.test_session,
                {
                    "path": "test/file",
                    "localpath": "test/file",
                    "session_key": "test-key",
                },
            )

            self.assertEqual(ret, 0)

        self.test_session["client"].get.assert_called_once_with(
            "http://openstack-test-storage-endpoint/test-container/test/file.c4gh",
            **{"headers": {"X-Auth-Token": "test-openstack-token"}},
        )
        mock_download.assert_called_once_with(
            self.mock_response.content,
            {"progress": False, "debug": False},
            self.test_session,
            {"path": "test/file", "localpath": "test/file", "session_key": "test-key"},
            None,
        )
