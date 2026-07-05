"""Integration tests for the SMB connection.

These tests require a Windows host with SMB and admin shares configured (provided by the CI runner).
They are skipped automatically when no SMB server is reachable.
"""

import os
import tempfile

import pytest

from tomoe.common import AuthenticationError, ConnectionError, check_port_open
from tomoe.config import Credential, RunOptions
from tomoe.connections.smb import SMBConnection


def _smb_available(host, port):
    return check_port_open(host, port, timeout=3)


def _make_connection(host, username, password, port=None, shell_type="cmd"):
    credential = Credential(username=username, password=password)
    options = RunOptions(port=port, shell_type=shell_type)
    return SMBConnection(host, credential, options)


@pytest.fixture(autouse=True)
def _skip_unless_smb(smb_host):
    host, port = smb_host
    if not _smb_available(host, port):
        pytest.skip(f"SMB server not reachable at {host}:{port}")


@pytest.mark.integration
class TestSMBExecute:
    def test_smb_execute_command(self, smb_host, smb_creds):
        host, port = smb_host
        username, password = smb_creds
        conn = _make_connection(host, username, password, port=port)
        result = conn.execute(command="echo hello from smb")
        assert "hello from smb" in result.output

    def test_smb_execute_whoami(self, smb_host, smb_creds):
        host, port = smb_host
        username, password = smb_creds
        conn = _make_connection(host, username, password, port=port)
        result = conn.execute(command="whoami")
        # PsExec runs as SYSTEM by default
        assert "system" in result.output.lower() or "testuser" in result.output.lower()


@pytest.mark.integration
class TestSMBUploadDownload:
    def test_smb_upload_file(self, smb_host, smb_creds, tmp_file):
        host, port = smb_host
        username, password = smb_creds
        conn = _make_connection(host, username, password, port=port)
        remote_path = "C:\\Windows\\Temp\\tomoe_smb_test_upload.txt"

        result = conn.put_file(tmp_file, remote_path)
        assert "Copied" in result or "copied" in result.lower()

    def test_smb_download_file(self, smb_host, smb_creds):
        host, port = smb_host
        username, password = smb_creds
        conn = _make_connection(host, username, password, port=port)
        remote_path = "C:\\Windows\\Temp\\tomoe_smb_test_download.txt"

        # Create a local file to upload first
        local_fd, local_upload_path = tempfile.mkstemp(prefix="tomoe_smb_up_")
        try:
            with os.fdopen(local_fd, "w") as f:
                f.write("smb download test content\n")

            conn.put_file(local_upload_path, remote_path)
        finally:
            os.unlink(local_upload_path)

        # Now download it
        local_dl_fd, local_dl_path = tempfile.mkstemp(prefix="tomoe_smb_dl_")
        os.close(local_dl_fd)
        try:
            conn.get_file(remote_path, local_dl_path)
            with open(local_dl_path, "r") as f:
                downloaded = f.read()
            assert "smb download test content" in downloaded
        finally:
            os.unlink(local_dl_path)


@pytest.mark.integration
class TestSMBAuthFailure:
    def test_smb_auth_failure(self, smb_host):
        host, port = smb_host
        conn = _make_connection(host, "testuser", "wrongpassword", port=port)
        with pytest.raises(AuthenticationError):
            conn.execute(command="whoami")
