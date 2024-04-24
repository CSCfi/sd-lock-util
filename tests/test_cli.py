"""Test CLI functions."""

import unittest
import unittest.mock

import click.testing

import sd_lock_utility.cli


class TestCliFunctions(unittest.TestCase):
    """Test class for CLI functions."""

    def setUp(self):
        """Set up relevant mocks."""
        self.mock_asyncio_run = unittest.mock.Mock(return_value=0)
        self.patch_run = unittest.mock.patch(
            "sd_lock_utility.cli.asyncio.run", self.mock_asyncio_run
        )

        self.mock_sys_exit = unittest.mock.Mock()
        self.patch_exit = unittest.mock.patch(
            "sd_lock_utility.cli.sys.exit", self.mock_sys_exit
        )

        self.mock_lock = unittest.mock.Mock(return_value=0)
        self.patch_lock = unittest.mock.patch(
            "sd_lock_utility.cli.sd_lock_utility.lock.lock", self.mock_lock
        )
        self.patch_unlock = unittest.mock.patch(
            "sd_lock_utility.cli.sd_lock_utility.unlock.unlock", self.mock_lock
        )
        self.patch_pubkey = unittest.mock.patch(
            "sd_lock_utility.cli.sd_lock_utility.lock.get_pubkey", self.mock_lock
        )

        self.runner = click.testing.CliRunner()

    def test_cli_lock_correct_parameters(self):
        """Test that CLI lock command call lock with correct parameters."""
        with self.patch_lock, self.patch_exit, self.patch_run:
            self.runner.invoke(
                sd_lock_utility.cli.lock,
                [
                    "--container",
                    "test-container",
                    "--project-id",
                    "test-project-id",
                    "--project-name",
                    "test-project-name",
                    "--owner",
                    "test-owner",
                    "--os-auth-url",
                    "test-os-auth-url",
                    "--sd-connect-address",
                    "test-address",
                    "--sd-api-token",
                    "test-token",
                    "--no-preserve-original",
                    "--no-check-certificate",
                    "--verbose",
                    "--debug",
                    "--progress",
                    "test-path",
                ],
            )

        self.mock_lock.assert_called_once_with(
            {
                "path": "test-path",
                "container": "test-container",
                "project_id": "test-project-id",
                "project_name": "test-project-name",
                "owner": "test-owner",
                "openstack_auth_url": "test-os-auth-url",
                "sd_connect_address": "test-address",
                "no_content_upload": False,
                "no_preserve_original": True,
                "sd_api_token": "test-token",
                "prefix": "",
                "no_check_certificate": True,
                "progress": True,
            }
        )
        self.mock_asyncio_run.assert_called_once_with(0)
        self.mock_sys_exit.assert_any_call(0)

    def test_cli_pubkey_correct_parameters(self):
        """Test that CLI pubkey command call pubkey with correct parameters."""
        with self.patch_pubkey, self.patch_exit, self.patch_run:
            self.runner.invoke(
                sd_lock_utility.cli.pubkey,
                [
                    "--project-id",
                    "test-project-id",
                    "--project-name",
                    "test-project-name",
                    "--owner",
                    "test-owner",
                    "--sd-connect-address",
                    "test-address",
                    "--sd-api-token",
                    "test-token",
                    "--no-check-certificate",
                    "--verbose",
                ],
            )

        self.mock_lock.assert_called_once_with(
            {
                "path": "",
                "container": "placeholder",
                "project_id": "test-project-id",
                "project_name": "test-project-name",
                "owner": "test-owner",
                "openstack_auth_url": "",
                "sd_connect_address": "test-address",
                "no_preserve_original": False,
                "sd_api_token": "test-token",
                "prefix": "",
                "no_check_certificate": True,
                "progress": False,
            }
        )
        self.mock_asyncio_run.assert_called_once_with(0)
        self.mock_sys_exit.assert_any_call(0)

    def test_cli_unlock_correct_parameters(self):
        """Test that CLI unlock command call unlock with correct parameters."""
        with self.patch_unlock, self.patch_exit, self.patch_run:
            self.runner.invoke(
                sd_lock_utility.cli.unlock,
                [
                    "--container",
                    "test-container",
                    "--project-id",
                    "test-project-id",
                    "--project-name",
                    "test-project-name",
                    "--owner",
                    "test-owner",
                    "--os-auth-url",
                    "test-os-auth-url",
                    "--sd-connect-address",
                    "test-address",
                    "--sd-api-token",
                    "test-token",
                    "--path",
                    "test-path",
                    "--no-preserve-original",
                    "--no-check-certificate",
                    "--verbose",
                    "--debug",
                    "--progress",
                ],
            )

        self.mock_lock.assert_called_once_with(
            {
                "path": "test-path",
                "container": "test-container",
                "project_id": "test-project-id",
                "project_name": "test-project-name",
                "owner": "test-owner",
                "openstack_auth_url": "test-os-auth-url",
                "sd_connect_address": "test-address",
                "no_content_download": False,
                "no_preserve_original": True,
                "sd_api_token": "test-token",
                "prefix": "",
                "no_check_certificate": True,
                "progress": True,
            }
        )
        self.mock_asyncio_run.assert_called_once_with(0)
        self.mock_sys_exit.assert_any_call(0)
