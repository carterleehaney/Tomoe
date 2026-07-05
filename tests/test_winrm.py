"""Integration tests for the WinRM connection.

These tests require a Windows host with WinRM configured (provided by the CI runner).
They are skipped automatically when no WinRM server is reachable.
"""

import os
import tempfile

import pytest

from tomoe.common import AuthenticationError, ConnectionError, check_port_open
from tomoe.config import Credential, RunOptions
from tomoe.connections.winrm import WinRMConnection


def _winrm_available(host, port):
    return check_port_open(host, port, timeout=3)


def _make_connection(host, username, password, port=None):
    credential = Credential(username=username, password=password)
    options = RunOptions(port=port)
    return WinRMConnection(host, credential, options)


@pytest.fixture(autouse=True)
def _skip_unless_winrm(winrm_host):
    host, port = winrm_host
    if not _winrm_available(host, port):
        pytest.skip(f"WinRM server not reachable at {host}:{port}")


@pytest.mark.integration
class TestWinRMExecute:
    def test_winrm_execute_command(self, winrm_host, winrm_creds):
        host, port = winrm_host
        username, password = winrm_creds
        conn = _make_connection(host, username, password, port=port)
        result = conn.execute(command="Write-Output 'hello from winrm'")
        assert "hello from winrm" in result.output

    def test_winrm_execute_whoami(self, winrm_host, winrm_creds):
        host, port = winrm_host
        username, password = winrm_creds
        conn = _make_connection(host, username, password, port=port)
        result = conn.execute(command="whoami")
        # The output should contain the username (possibly with hostname prefix)
        assert username.lower() in result.output.lower() or "testuser" in result.output.lower()


@pytest.mark.integration
class TestWinRMUploadDownload:
    def test_winrm_upload_file(self, winrm_host, winrm_creds, tmp_file):
        host, port = winrm_host
        username, password = winrm_creds
        conn = _make_connection(host, username, password, port=port)
        remote_path = "C:\\Windows\\Temp\\tomoe_test_upload.txt"

        conn.put_file(tmp_file, remote_path)

        # Verify file exists on remote
        result = conn.execute(command=f"Get-Content '{remote_path}'")
        assert "hello from tomoe test" in result.output

        # Clean up
        conn.execute(command=f"Remove-Item '{remote_path}' -Force")

    def test_winrm_download_file(self, winrm_host, winrm_creds):
        host, port = winrm_host
        username, password = winrm_creds
        conn = _make_connection(host, username, password, port=port)
        remote_path = "C:\\Windows\\Temp\\tomoe_test_download.txt"
        content = "download test from winrm"

        # Create file on remote
        conn.execute(command=f"Set-Content -Path '{remote_path}' -Value '{content}'")

        local_fd, local_path = tempfile.mkstemp(prefix="tomoe_winrm_dl_")
        os.close(local_fd)
        try:
            conn.get_file(remote_path, local_path)
            with open(local_path, "r") as f:
                downloaded = f.read()
            assert content in downloaded
        finally:
            os.unlink(local_path)
            # Clean up remote
            try:
                conn.execute(command=f"Remove-Item '{remote_path}' -Force")
            except Exception:
                pass


@pytest.mark.integration
class TestWinRMAuthFailure:
    def test_winrm_auth_failure(self, winrm_host):
        host, port = winrm_host
        conn = _make_connection(host, "testuser", "wrongpassword", port=port)
        with pytest.raises(AuthenticationError):
            conn.execute(command="whoami")
