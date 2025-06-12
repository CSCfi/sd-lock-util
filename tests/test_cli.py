"""Test CLI functions."""

import pathlib
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
            "sd_lock_utility.cli.sd_lock_utility.lock.wrap_lock_exceptions",
            self.mock_lock,
        )
        self.patch_unlock = unittest.mock.patch(
            "sd_lock_utility.cli.sd_lock_utility.unlock.wrap_unlock_exceptions",
            self.mock_lock,
        )
        self.patch_pubkey = unittest.mock.patch(
            "sd_lock_utility.cli.sd_lock_utility.lock.get_pubkey",
            self.mock_lock,
        )

        self.mock_idcheck = unittest.mock.Mock(return_value=0)
        self.patch_idcheck = unittest.mock.patch(
            "sd_lock_utility.cli.sd_lock_utility.lock.get_id",
            self.mock_idcheck,
        )

        self.mock_fix_perm = unittest.mock.Mock(return_value=0)
        self.patch_fix_perm = unittest.mock.patch(
            "sd_lock_utility.cli.sd_lock_utility.sharing.fix_header_permissions_uploader",
            self.mock_fix_perm,
        )

        self.mock_fix_head = unittest.mock.Mock(return_value=0)
        self.patch_fix_head = unittest.mock.patch(
            "sd_lock_utility.cli.sd_lock_utility.sharing.fix_header_permissions_owner",
            self.mock_fix_head,
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
                    "--owner-name",
                    "test-owner-name",
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
                "path": pathlib.Path("test-path"),
                "container": "test-container",
                "project_id": "test-project-id",
                "project_name": "test-project-name",
                "owner": "test-owner",
                "owner_name": "test-owner-name",
                "openstack_auth_url": "test-os-auth-url",
                "sd_connect_address": "test-address",
                "no_content_upload": False,
                "no_preserve_original": True,
                "sd_api_token": "test-token",
                "prefix": "",
                "no_check_certificate": True,
                "progress": False,
                "debug": True,
                "verbose": True,
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
                    "--owner-name",
                    "test-owner-name",
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
                "path": pathlib.Path("."),
                "container": "placeholder",
                "project_id": "test-project-id",
                "project_name": "test-project-name",
                "owner": "test-owner",
                "owner_name": "test-owner-name",
                "openstack_auth_url": "",
                "sd_connect_address": "test-address",
                "no_preserve_original": False,
                "sd_api_token": "test-token",
                "prefix": "",
                "no_check_certificate": True,
                "progress": False,
                "debug": False,
                "verbose": True,
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
                    "--owner-name",
                    "test-owner-name",
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
                "path": pathlib.Path("test-path"),
                "no_path": False,
                "container": "test-container",
                "project_id": "test-project-id",
                "project_name": "test-project-name",
                "owner": "test-owner",
                "owner_name": "test-owner-name",
                "openstack_auth_url": "test-os-auth-url",
                "sd_connect_address": "test-address",
                "no_content_download": False,
                "no_preserve_original": True,
                "sd_api_token": "test-token",
                "prefix": "",
                "no_check_certificate": True,
                "progress": False,
                "debug": True,
                "verbose": True,
            }
        )
        self.mock_asyncio_run.assert_called_once_with(0)
        self.mock_sys_exit.assert_any_call(0)

    def test_cli_idcheck_with_correct_parameters(self):
        """Test that idcheck can be run with correct parameters."""
        with self.patch_idcheck, self.patch_exit, self.patch_run:
            self.runner.invoke(
                sd_lock_utility.cli.idcheck,
                [
                    "test-owner",
                    "--project-id",
                    "test-project-id",
                    "--project-name",
                    "test-project-name",
                    "--sd-connect-address",
                    "test-address",
                    "--sd-api-token",
                    "test-token",
                    "--no-check-certificate",
                    "--verbose",
                    "--debug",
                ],
            )

        self.mock_idcheck.assert_called_once_with(
            {
                "path": pathlib.Path("."),
                "container": "placeholder",
                "project_id": "test-project-id",
                "project_name": "test-project-name",
                "owner": "test-owner",
                "owner_name": "",
                "openstack_auth_url": "",
                "sd_connect_address": "test-address",
                "no_preserve_original": False,
                "sd_api_token": "test-token",
                "prefix": "",
                "no_check_certificate": True,
                "progress": False,
                "debug": True,
                "verbose": True,
            }
        )
        self.mock_asyncio_run.assert_called_once_with(0)
        self.mock_sys_exit.assert_any_call(0)

    def test_cli_fix_header_permissions_correct_parameters(self):
        """Test that header fix script can be run with the correct parameters."""
        with self.patch_fix_perm, self.patch_exit, self.patch_run:
            self.runner.invoke(
                sd_lock_utility.cli.fix_header_permissions,
                [
                    "--container",
                    "test-container",
                    "--project-id",
                    "test-project-id",
                    "--project-name",
                    "test-project-name",
                    "--owner",
                    "test-owner",
                    "--owner-name",
                    "test-owner-name",
                    "--os-auth-url",
                    "test-os-auth-url",
                    "--sd-connect-address",
                    "test-address",
                    "--sd-api-token",
                    "test-token",
                    "--no-check-certificate",
                    "--verbose",
                    "--debug",
                ],
            )

        self.mock_fix_perm.assert_called_once_with(
            {
                "path": pathlib.Path("."),
                "no_path": True,
                "container": "test-container",
                "project_id": "test-project-id",
                "project_name": "test-project-name",
                "owner": "test-owner",
                "owner_name": "test-owner-name",
                "openstack_auth_url": "test-os-auth-url",
                "sd_connect_address": "test-address",
                "no_content_download": False,
                "no_preserve_original": False,
                "sd_api_token": "test-token",
                "prefix": "",
                "no_check_certificate": True,
                "progress": False,
                "debug": True,
                "verbose": True,
            }
        )
        self.mock_asyncio_run.assert_called_once_with(0)
        self.mock_sys_exit.assert_any_call(0)

    def test_cli_fix_missing_headers_correct_parameters(self):
        """Test that CLI missing header command calls with correct parameters."""
        with self.patch_fix_head, self.patch_exit, self.patch_run:
            self.runner.invoke(
                sd_lock_utility.cli.fix_missing_headers,
                [
                    "--container",
                    "test-container",
                    "--project-id",
                    "test-project-id",
                    "--project-name",
                    "test-project-name",
                    "--owner",
                    "test-owner",
                    "--owner-name",
                    "test-owner-name",
                    "--os-auth-url",
                    "test-os-auth-url",
                    "--sd-connect-address",
                    "test-address",
                    "--sd-api-token",
                    "test-token",
                    "--no-check-certificate",
                    "--verbose",
                    "--debug",
                ],
            )

        self.mock_fix_head.assert_called_once_with(
            {
                "path": pathlib.Path("."),
                "no_path": True,
                "container": "test-container",
                "project_id": "test-project-id",
                "project_name": "test-project-name",
                "owner": "test-owner",
                "owner_name": "test-owner-name",
                "openstack_auth_url": "test-os-auth-url",
                "sd_connect_address": "test-address",
                "no_content_download": False,
                "no_preserve_original": False,
                "sd_api_token": "test-token",
                "prefix": "",
                "no_check_certificate": True,
                "progress": False,
                "debug": True,
                "verbose": True,
            }
        )
        self.mock_asyncio_run.assert_called_once_with(0)
        self.mock_sys_exit.assert_any_call(0)
