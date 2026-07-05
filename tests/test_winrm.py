"""Integration tests for WinRM protocol.

These tests require a Windows host with WinRM configured (provided by the CI runner).
They are skipped automatically when no WinRM server is reachable.
"""

import os
import tempfile

import pytest

from tomoe.common import AuthenticationError, ConnectionError, check_port_open


def _winrm_available(host, port):
    return check_port_open(host, port, timeout=3)


@pytest.fixture(autouse=True)
def _skip_unless_winrm(winrm_host):
    host, port = winrm_host
    if not _winrm_available(host, port):
        pytest.skip(f"WinRM server not reachable at {host}:{port}")


@pytest.mark.integration
class TestWinRMExecute:
    def test_winrm_execute_command(self, winrm_host, winrm_creds):
        from tomoe.protocols.winrm import execute

        host, _ = winrm_host
        username, password = winrm_creds
        output = execute(
            host=host, username=username, password=password,
            domain="", command="Write-Output 'hello from winrm'",
            script_path=None, script_args="", verbose=False,
        )
        assert "hello from winrm" in output

    def test_winrm_execute_whoami(self, winrm_host, winrm_creds):
        from tomoe.protocols.winrm import execute

        host, _ = winrm_host
        username, password = winrm_creds
        output = execute(
            host=host, username=username, password=password,
            domain="", command="whoami",
            script_path=None, script_args="", verbose=False,
        )
        # The output should contain the username (possibly with hostname prefix)
        assert username.lower() in output.lower() or "testuser" in output.lower()


@pytest.mark.integration
class TestWinRMUploadDownload:
    def test_winrm_upload_file(self, winrm_host, winrm_creds, tmp_file):
        from tomoe.protocols.winrm import upload, execute

        host, _ = winrm_host
        username, password = winrm_creds
        remote_path = "C:\\Windows\\Temp\\tomoe_test_upload.txt"

        upload(
            host=host, username=username, password=password,
            domain="", source=tmp_file, dest=remote_path,
            verbose=False,
        )

        # Verify file exists on remote
        output = execute(
            host=host, username=username, password=password,
            domain="", command=f"Get-Content '{remote_path}'",
            script_path=None, script_args="", verbose=False,
        )
        assert "hello from tomoe test" in output

        # Clean up
        execute(
            host=host, username=username, password=password,
            domain="", command=f"Remove-Item '{remote_path}' -Force",
            script_path=None, script_args="", verbose=False,
        )

    def test_winrm_download_file(self, winrm_host, winrm_creds):
        from tomoe.protocols.winrm import download, execute

        host, _ = winrm_host
        username, password = winrm_creds
        remote_path = "C:\\Windows\\Temp\\tomoe_test_download.txt"
        content = "download test from winrm"

        # Create file on remote
        execute(
            host=host, username=username, password=password,
            domain="", command=f"Set-Content -Path '{remote_path}' -Value '{content}'",
            script_path=None, script_args="", verbose=False,
        )

        local_fd, local_path = tempfile.mkstemp(prefix="tomoe_winrm_dl_")
        os.close(local_fd)
        try:
            download(
                host=host, username=username, password=password,
                domain="", source=remote_path, dest=local_path,
                verbose=False,
            )
            with open(local_path, "r") as f:
                downloaded = f.read()
            assert content in downloaded
        finally:
            os.unlink(local_path)
            # Clean up remote
            try:
                execute(
                    host=host, username=username, password=password,
                    domain="", command=f"Remove-Item '{remote_path}' -Force",
                    script_path=None, script_args="", verbose=False,
                )
            except Exception:
                pass


@pytest.mark.integration
class TestWinRMAuthFailure:
    def test_winrm_auth_failure(self, winrm_host):
        from tomoe.protocols.winrm import execute

        host, _ = winrm_host
        with pytest.raises(AuthenticationError):
            execute(
                host=host, username="testuser", password="wrongpassword",
                domain="", command="whoami",
                script_path=None, script_args="", verbose=False,
            )
