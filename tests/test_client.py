"""Unit tests for the client functions."""

import unittest
import unittest.mock
import types
import base64
import json

import sd_lock_utility.client

import sd_lock_utility.exceptions
import tests.mockups


class TestSignAPIRequest(unittest.IsolatedAsyncioTestCase):
    """Test api request signature."""

    async def test_sign_api_request_should_return_a_valid_signature(self):
        """Test that _sign_api_request returns a valid signature."""

        time_mock = unittest.mock.Mock(return_value=1.0)
        time_patch = unittest.mock.patch(
            "sd_lock_utility.client.time.time",
            time_mock,
        )
        hexdigest_mock = unittest.mock.Mock(return_value="test-signature")
        hmac_mock = unittest.mock.Mock(
            return_value=types.SimpleNamespace(
                **{
                    "hexdigest": hexdigest_mock,
                }
            )
        )
        hmac_patch = unittest.mock.patch(
            "sd_lock_utility.client.hmac.new",
            hmac_mock,
        )

        with time_patch, hmac_patch:
            ret = sd_lock_utility.client._sign_api_request("/test/path", key="test-key")

        self.assertIn("valid", ret)
        self.assertIn("signature", ret)
        self.assertEqual(ret["valid"], 3601)
        self.assertEqual(ret["signature"], "test-signature")

        time_mock.assert_called_once()
        hmac_mock.assert_called_once_with(
            key="test-key", msg=b"3601/test/path", digestmod="sha256"
        )
        hexdigest_mock.assert_called_once()


class TestClientModule(tests.mockups.SDLockUtilTestBase):
    """Test client module functions."""

    async def test_open_session_should_raise_without_token(self):
        """Test that open_session raises without a token."""
        self.test_parameters.pop("token")
        with self.assertRaises(sd_lock_utility.client.sd_lock_utility.exceptions.NoToken):
            await sd_lock_utility.client.open_session(**self.test_parameters)

    async def test_open_session_should_raise_without_address(self):
        """Test that open_session raises without an address."""
        self.test_parameters.pop("address")
        with self.assertRaises(
            sd_lock_utility.client.sd_lock_utility.exceptions.NoAddress
        ):
            await sd_lock_utility.client.open_session(**self.test_parameters)

    async def test_open_session_should_raise_without_project_name(self):
        """Test that open_session raises without a project id."""
        self.test_parameters.pop("project_name")
        with self.assertRaises(
            sd_lock_utility.client.sd_lock_utility.exceptions.NoProject
        ):
            await sd_lock_utility.client.open_session(**self.test_parameters)

    async def test_open_session_should_raise_without_container(self):
        """Test that open_session raises without a container."""
        self.test_parameters.pop("container")
        with self.assertRaises(
            sd_lock_utility.client.sd_lock_utility.exceptions.NoContainer
        ):
            await sd_lock_utility.client.open_session(**self.test_parameters)

    async def test_open_session_succeeds_with_all_parameters(self):
        """Test that open_session succeeds when all required parameters are provided."""
        ret = await sd_lock_utility.client.open_session(**self.test_parameters)
        self.assertEqual(ret["container"], self.test_parameters["container"])
        self.assertEqual(ret["token"], self.test_parameters["token"].encode("utf-8"))
        self.assertEqual(
            ret["openstack_project_name"], self.test_parameters["project_name"]
        )
        self.assertEqual(ret["address"], self.test_parameters["address"])

    async def test_signed_fetch_should_succeed_updated_params(self):
        """Test that signed_fetch works with added parameters."""
        with self.patch_sign_request, self.patch_timeout:
            ret = await sd_lock_utility.client.signed_fetch(
                self.test_session,
                "/test/path",
                params={"test-param-1": "1", "test-param-2": "2"},
                json_data={"test-json-1": 1, "test-json-2": 2},
            )

        self.assertEqual(ret, "test-text")
        self.test_session["client"].request.assert_called_once_with(
            **{
                "method": "GET",
                "url": "http://test-address/test/path",
                "params": {
                    "valid": 1234,
                    "signature": "test-signature",
                    "test-param-1": "1",
                    "test-param-2": "2",
                },
                "json": {
                    "test-json-1": 1,
                    "test-json-2": 2,
                },
                "data": None,
                "timeout": "test-timeout",
                "ssl": False,
            }
        )
        self.mock_timeout.assert_called_once_with(total=60)
        self.mock_response.text.assert_awaited_once()

    async def test_signed_fetch_should_fail_with_invalid_url(self):
        """Test that signed_fetch returns None with InvalidURL."""
        self.test_session["client"].request = unittest.mock.Mock(
            return_value=self.mock_handler(
                None,
                sd_lock_utility.client.aiohttp.client.InvalidURL("test-url"),
            )
        )
        with (
            self.patch_sign_request,
            self.patch_timeout,
            self.assertRaises(sd_lock_utility.client.aiohttp.client.InvalidURL),
        ):
            await sd_lock_utility.client.signed_fetch(self.test_session, "/test/path")

    async def test_signed_fetch_should_let_other_exceptions_bubble(self):
        """Test that signed_fetch bubbles through other exceptions."""
        self.test_session["client"].request = unittest.mock.Mock(
            return_value=self.mock_handler(
                None,
                sd_lock_utility.client.aiohttp.client.ClientConnectionError,
            )
        )
        with (
            self.patch_sign_request,
            self.patch_timeout,
            self.assertRaises(
                sd_lock_utility.client.aiohttp.client.ClientConnectionError,
            ),
        ):
            await sd_lock_utility.client.signed_fetch(self.test_session, "/test/path")

    async def test_signed_fetch_should_fail_with_empty_response(self):
        """Test that singed_fetch returns None with empty response."""
        self.mock_response.status = 204
        with self.patch_sign_request, self.patch_timeout:
            ret = await sd_lock_utility.client.signed_fetch(
                self.test_session, "/test/path"
            )
        self.assertIsNone(ret)

    async def test_whitelist_key_should_await_with_correct_arguments(self):
        """Test that whitelist_key awaits signed_fetch with correct arguments."""
        with self.patch_signed_fetch:
            await sd_lock_utility.client.whitelist_key(
                self.test_session, "example-key-to-whitelist"
            )

        self.mock_signed_fetch.assert_awaited_once_with(
            self.test_session,
            "/cryptic/test-project-name/whitelist",
            **{
                "method": "PUT",
                "params": {
                    "flavor": "crypt4gh",
                },
                "data": "example-key-to-whitelist",
                "prefix": "/runner",
            },
        )

    async def test_unlist_key_should_await_with_correct_arguments(self):
        """Test that unlist_key awaits signed_fetch with correct arguments."""
        with self.patch_signed_fetch:
            await sd_lock_utility.client.unlist_key(self.test_session)

        self.mock_signed_fetch.assert_awaited_once_with(
            self.test_session,
            "/cryptic/test-project-name/whitelist",
            **{
                "method": "DELETE",
                "prefix": "/runner",
            },
        )

    async def test_get_public_key_should_return_public_key(self):
        """Test that get_public_key returns public key."""
        self.mock_signed_fetch.return_value = "test-public-key"
        with self.patch_signed_fetch:
            ret = await sd_lock_utility.client.get_public_key(self.test_session)

        self.assertEqual(ret, "test-public-key")
        self.mock_signed_fetch.assert_awaited_once_with(
            self.test_session,
            "/cryptic/test-project-name/keys",
            prefix="/runner",
        )

    async def test_get_public_key_returns_empty_with_no_key(self):
        """Test that get_public_key returns empty if there's no public key."""
        self.mock_signed_fetch.return_value = None
        with self.patch_signed_fetch:
            ret = await sd_lock_utility.client.get_public_key(self.test_session)

        self.assertEqual(ret, "")

    async def test_push_header_should_await_with_correct_arguments(self):
        """Test that push_header awaits signed_fetch with correct arguments."""
        with self.patch_signed_fetch:
            await sd_lock_utility.client.push_header(
                self.test_session, b"test-header", "test/file/path"
            )

        self.mock_signed_fetch.assert_awaited_once_with(
            self.test_session,
            "/header/test-project-name/test-container/test/file/path",
            **{
                "method": "PUT",
                "data": b"test-header",
                "params": None,
                "prefix": "/runner",
            },
        )

    async def test_get_header_should_get_header(self):
        """Test that get_header awaits signed_fetch with correct arguments."""
        header = b"example-header"
        self.mock_signed_fetch.return_value = base64.urlsafe_b64encode(header)
        with self.patch_signed_fetch:
            ret = await sd_lock_utility.client.get_header(
                self.test_session, "test/file/path"
            )

        self.mock_signed_fetch.assert_awaited_once_with(
            self.test_session,
            "/header/test-project-name/test-container/test/file/path",
            params=None,
            prefix="/runner",
        )
        self.assertEqual(ret, header)

    async def test_get_header_should_raise_with_no_header(self):
        """Test that get_header raises when no header is available."""
        self.mock_signed_fetch.return_value = None
        with (
            self.patch_signed_fetch,
            self.assertRaises(
                sd_lock_utility.client.sd_lock_utility.exceptions.NoFileHeader
            ),
        ):
            await sd_lock_utility.client.get_header(self.test_session, "test/file/path")

    # Tests for sd_lock_util.client:check_shared_status
    async def test_check_shared_status_should_skip_if_no_owner(self):
        """Test that share status check is skipped if there's an owner."""
        self.test_session["owner"] = "test-owner"
        with self.patch_signed_fetch:
            await sd_lock_utility.client.check_shared_status(self.test_session)

        self.mock_signed_fetch.assert_not_awaited()
        self.assertEqual(self.test_session["owner"], "test-owner")

    async def test_check_shared_status_finds_correct_bucket_from_listing(self):
        """Test that shared status check matches owner and sets shared status."""
        self.mock_signed_fetch.return_value = json.dumps(
            [
                {
                    "container": "bogus-container-1",
                    "owner": "bogus-owner",
                },
                {
                    "container": "bogus-container-2",
                    "owner": "bogus-owner",
                },
                {
                    "container": "test-container",
                    "owner": "test-owner",
                },
            ]
        )

        with self.patch_signed_fetch:
            await sd_lock_utility.client.check_shared_status(self.test_session)

        self.mock_signed_fetch.assert_awaited_once_with(
            self.test_session,
            "/access/test-project-id",
            prefix="/sharing",
        )
        self.assertEqual(self.test_session["owner"], "test-owner")

    async def test_check_shared_status_skips_on_failure(self):
        """Test that a failed status check doesn't bubble an exception."""
        self.mock_signed_fetch.return_value = "garbage_json[]]}q]$þı˝wj ̛œörkmg"

        with self.patch_signed_fetch:
            await sd_lock_utility.client.check_shared_status(self.test_session)

        self.assertEqual(self.test_session["owner"], "")

    # Tests for sd_lock_util.client:get_shared_ids
    async def test_get_shared_ids_should_return_empty_with_no_owner(self):
        """Test that fetching shared ids fails if no owner name is confiugred."""
        ret = await sd_lock_utility.client.get_shared_ids(self.test_session)
        self.assertEqual(ret["id"], "")
        self.assertEqual(ret["name"], "")

    async def test_get_shared_ids_should_skip_if_owner_name_is_configured(self):
        """Test that fetching shared ids is skipped if ids are already present."""
        self.test_session["owner_name"] = "test-owner"
        ret = await sd_lock_utility.client.get_shared_ids(self.test_session)
        self.assertEqual(ret["id"], "")
        self.assertEqual(ret["name"], "")

    async def test_get_shared_ids_should_set_owner_name(self):
        """Test that fetching shared ids sets owner name in session."""
        self.test_session["owner"] = "test-owner-id"
        self.mock_signed_fetch.return_value = json.dumps(
            {
                "name": "test-owner-name",
                "id": "test-owner-id",
            }
        )

        with self.patch_signed_fetch:
            ret = await sd_lock_utility.client.get_shared_ids(self.test_session)

        self.assertEqual(ret["name"], "test-owner-name")
        self.assertEqual(ret["id"], "test-owner-id")
        self.assertEqual(self.test_session["owner_name"], "test-owner-name")
        self.assertEqual(self.test_session["owner"], "test-owner-id")

    async def test_get_shared_ids_should_return_empty_if_fetch_fails(self):
        """Test that a failed id fetch doesn't bubble an exception."""
        self.test_session["owner"] = "test-owner-id"
        self.mock_signed_fetch.return_value = "garbage_json[]]}q]$þı˝wj ̛œörkmg"

        with self.patch_signed_fetch:
            ret = await sd_lock_utility.client.get_shared_ids(self.test_session)

        self.assertEqual(ret["id"], "")
        self.assertEqual(ret["name"], "")

    # Tests for sd_lock_util.client:share_folder_to_project
    async def test_folder_share_should_check_owner_and_call_share_endpoint(self):
        """Test that folder is shared correctly using the sharing endpoint."""
        self.test_session["owner_name"] = "test-owner-name"
        self.test_session["owner"] = "test-owner-id"

        with self.patch_signed_fetch, self.patch_shared_ids:
            await sd_lock_utility.client.share_folder_to_project(self.test_session)

        self.mock_shared_ids.assert_awaited_once_with(self.test_session)
        self.mock_signed_fetch.assert_awaited_once_with(
            self.test_session,
            "/cryptic/test-project-name/test-container",
            json_data={
                "name": "test-owner-name",
                "id": "test-owner-id",
            },
            prefix="/runner",
        )

    async def test_folder_share_should_fail_if_no_owner_in_config(self):
        """Test that folder share fails correctly when owner is not provided."""
        with (
            self.patch_signed_fetch,
            self.patch_shared_ids,
            self.assertRaises(sd_lock_utility.exceptions.NoOwner),
        ):
            await sd_lock_utility.client.share_folder_to_project(self.test_session)
