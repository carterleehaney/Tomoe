"""Integration tests for SMB protocol.

These tests require a Windows host with SMB and admin shares configured (provided by the CI runner).
They are skipped automatically when no SMB server is reachable.
"""

import os
import tempfile

import pytest

from tomoe.common import AuthenticationError, ConnectionError, check_port_open


def _smb_available(host, port):
    return check_port_open(host, port, timeout=3)


@pytest.fixture(autouse=True)
def _skip_unless_smb(smb_host):
    host, port = smb_host
    if not _smb_available(host, port):
        pytest.skip(f"SMB server not reachable at {host}:{port}")


@pytest.mark.integration
class TestSMBExecute:
    def test_smb_execute_command(self, smb_host, smb_creds):
        from tomoe.protocols.smb import execute

        host, _ = smb_host
        username, password = smb_creds
        output = execute(
            host=host, username=username, password=password,
            domain="", command="echo hello from smb",
            script_path=None, script_args="", verbose=False,
            shell_type="cmd",
        )
        assert "hello from smb" in output

    def test_smb_execute_whoami(self, smb_host, smb_creds):
        from tomoe.protocols.smb import execute

        host, _ = smb_host
        username, password = smb_creds
        output = execute(
            host=host, username=username, password=password,
            domain="", command="whoami",
            script_path=None, script_args="", verbose=False,
            shell_type="cmd",
        )
        # PsExec runs as SYSTEM by default
        assert "system" in output.lower() or "testuser" in output.lower()


@pytest.mark.integration
class TestSMBUploadDownload:
    def test_smb_upload_file(self, smb_host, smb_creds, tmp_file):
        from tomoe.protocols.smb import upload

        host, _ = smb_host
        username, password = smb_creds
        remote_path = "C:\\Windows\\Temp\\tomoe_smb_test_upload.txt"

        result = upload(
            host=host, username=username, password=password,
            domain="", source=tmp_file, dest=remote_path,
            verbose=False,
        )
        assert "Copied" in result or "copied" in result.lower()

    def test_smb_download_file(self, smb_host, smb_creds):
        from tomoe.protocols.smb import upload, download, execute

        host, _ = smb_host
        username, password = smb_creds
        remote_path = "C:\\Windows\\Temp\\tomoe_smb_test_download.txt"

        # Create a local file to upload first
        local_fd, local_upload_path = tempfile.mkstemp(prefix="tomoe_smb_up_")
        try:
            with os.fdopen(local_fd, "w") as f:
                f.write("smb download test content\n")

            upload(
                host=host, username=username, password=password,
                domain="", source=local_upload_path, dest=remote_path,
                verbose=False,
            )
        finally:
            os.unlink(local_upload_path)

        # Now download it
        local_dl_fd, local_dl_path = tempfile.mkstemp(prefix="tomoe_smb_dl_")
        os.close(local_dl_fd)
        try:
            download(
                host=host, username=username, password=password,
                domain="", source=remote_path, dest=local_dl_path,
                verbose=False,
            )
            with open(local_dl_path, "r") as f:
                downloaded = f.read()
            assert "smb download test content" in downloaded
        finally:
            os.unlink(local_dl_path)


@pytest.mark.integration
class TestSMBAuthFailure:
    def test_smb_auth_failure(self, smb_host):
        from tomoe.protocols.smb import execute

        host, _ = smb_host
        with pytest.raises((AuthenticationError, Exception)):
            execute(
                host=host, username="testuser", password="wrongpassword",
                domain="", command="whoami",
                script_path=None, script_args="", verbose=False,
                shell_type="cmd",
            )
