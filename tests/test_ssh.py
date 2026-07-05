"""Integration tests for the SSH connection.

These tests require a running SSH server (provided by Docker in CI, on the
port given by SSH_TEST_PORT / the ssh_host fixture). They are skipped
automatically when no SSH server is reachable.

Unlike the old raw-paramiko version of this file, these tests drive Tomoe's
own SSHConnection end to end (connect/execute/put_file/get_file), using the
configurable port (RunOptions.port) to target the non-standard container
port.
"""

import os
import tempfile

import pytest

from tomoe.common import AuthenticationError, ConnectionError, check_port_open
from tomoe.config import Credential, RunOptions
from tomoe.connections.ssh import SSHConnection


def _ssh_available(host, port):
    """Check whether the SSH test server is reachable."""
    return check_port_open(host, port, timeout=3)


def _make_connection(host, port, username, password, **options_kwargs):
    credential = Credential(username=username, password=password)
    options = RunOptions(target_os="linux", port=port, **options_kwargs)
    return SSHConnection(host, credential, options)


@pytest.fixture
def ssh_connection(ssh_host, ssh_creds):
    """Yield an SSHConnection targeting the test server, skip if unavailable."""
    host, port = ssh_host
    username, password = ssh_creds
    if not _ssh_available(host, port):
        pytest.skip(f"SSH server not reachable at {host}:{port}")
    return _make_connection(host, port, username, password)


@pytest.mark.integration
class TestSSHExecute:
    def test_ssh_execute_command(self, ssh_connection):
        result = ssh_connection.execute(command="echo hello")
        assert "hello" in result.output

    def test_ssh_execute_whoami(self, ssh_connection, ssh_creds):
        username, _ = ssh_creds
        result = ssh_connection.execute(command="whoami")
        assert username in result.output


@pytest.mark.integration
class TestSSHUploadDownload:
    def test_ssh_upload_file(self, ssh_connection, tmp_file):
        remote_path = "/tmp/tomoe_test_upload.txt"
        try:
            output = ssh_connection.put_file(tmp_file, remote_path)
            assert "Copied" in output

            verify = ssh_connection.execute(command=f"cat {remote_path}")
            assert "hello from tomoe test" in verify.output
        finally:
            try:
                ssh_connection.execute(command=f"rm -f {remote_path}")
            except Exception:
                pass

    def test_ssh_download_file(self, ssh_connection):
        remote_path = "/tmp/tomoe_test_download.txt"
        content = "download test content"

        ssh_connection.execute(command=f'echo "{content}" > {remote_path}')

        local_fd, local_path = tempfile.mkstemp(prefix="tomoe_dl_")
        os.close(local_fd)
        try:
            output = ssh_connection.get_file(remote_path, local_path)
            assert "Downloaded" in output

            with open(local_path, "r") as f:
                downloaded = f.read()
            assert content in downloaded
        finally:
            os.unlink(local_path)
            try:
                ssh_connection.execute(command=f"rm -f {remote_path}")
            except Exception:
                pass


@pytest.mark.integration
class TestSSHAuthFailure:
    def test_ssh_auth_failure(self, ssh_host):
        host, port = ssh_host
        if not _ssh_available(host, port):
            pytest.skip(f"SSH server not reachable at {host}:{port}")
        conn = _make_connection(host, port, "testuser", "wrongpassword")
        with pytest.raises(AuthenticationError):
            conn.execute(command="whoami")

    def test_ssh_connection_failure(self):
        """Connecting to a non-listening port should fail."""
        conn = _make_connection("localhost", 1, "testuser", "testpass123")
        with pytest.raises(ConnectionError):
            conn.execute(command="whoami")
