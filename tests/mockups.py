"""Common mockups for tests."""

import types
import unittest
import unittest.mock


import sd_lock_utility.client


class SDLockUtilTestBase(unittest.IsolatedAsyncioTestCase):
    """Base unit test class for sd_lock_utility tests."""

    def setUp(self):
        """Set up relevant mocks."""

        self.test_parameters = {
            "token": "test-token",
            "address": "test-address",
            "project_id": "test-id",
            "project_name": "test-name",
            "container": "test-container",
            "os_auth_url": "test-os-url",
            "no_check_certificate": False,
        }

        self.mock_response = types.SimpleNamespace(
            **{
                "status": 200,
                "headers": {},
                "text": unittest.mock.AsyncMock(return_value="test-text"),
                "json": unittest.mock.AsyncMock(return_value={"a": 1}),
                "content": types.SimpleNamespace(
                    **{"readexactly": unittest.mock.AsyncMock()}
                ),
            }
        )

        class MockHandler:
            def __init__(self, mock_response, raises=None):
                """."""
                self.mock_response = mock_response
                self.raises = raises

            async def __aenter__(self):
                """."""
                if self.raises:
                    raise self.raises
                return self.mock_response

            async def __aexit__(self, *_):
                """."""

        self.mock_handler = MockHandler

        self.mock_sign_request = unittest.mock.Mock(
            return_value={
                "valid": 1234,
                "signature": "test-signature",
            }
        )
        self.patch_sign_request = unittest.mock.patch(
            "sd_lock_utility.client._sign_api_request",
            self.mock_sign_request,
        )

        self.mock_timeout = unittest.mock.Mock(return_value="test-timeout")
        self.patch_timeout = unittest.mock.patch(
            "sd_lock_utility.client.aiohttp.client.ClientTimeout",
            self.mock_timeout,
        )

        self.mock_signed_fetch = unittest.mock.AsyncMock()
        self.patch_signed_fetch = unittest.mock.patch(
            "sd_lock_utility.client.signed_fetch",
            self.mock_signed_fetch,
        )

        self.test_session: sd_lock_utility.client.sd_lock_utility.types.SDAPISession = {
            "client": types.SimpleNamespace(
                **{
                    "close": unittest.mock.AsyncMock(),
                    "request": unittest.mock.Mock(
                        return_value=self.mock_handler(self.mock_response)
                    ),
                    "post": unittest.mock.Mock(
                        return_value=self.mock_handler(self.mock_response)
                    ),
                    "head": unittest.mock.Mock(
                        return_value=self.mock_handler(self.mock_response)
                    ),
                    "put": unittest.mock.Mock(
                        return_value=self.mock_handler(self.mock_response)
                    ),
                    "get": unittest.mock.Mock(
                        return_value=self.mock_handler(self.mock_response)
                    ),
                }
            ),
            "token": b"test-token",
            "address": "http://test-address",
            "openstack_project_id": "test-project-id",
            "openstack_project_name": "test-project-name",
            "openstack_auth_url": "http://openstack-test-auth-url",
            "openstack_password": "test-password",
            "openstack_user_domain": "test-user-domain",
            "openstack_username": "test-username",
            "openstack_token": "test-openstack-token",
            "openstack_object_storage_endpoint": "http://openstack-test-storage-endpoint",
            "openstack_token_valid_until": 14213213,
            "container": "test-container",
            "no_check_certificate": True,
            "owner": "",
            "owner_name": "",
        }
