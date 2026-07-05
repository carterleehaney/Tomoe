"""Integration tests for SSH protocol functions.

These tests require a running SSH server (provided by Docker in CI).
They are skipped automatically when no SSH server is reachable.
"""

import os
import tempfile

import paramiko
import pytest

from tomoe.common import AuthenticationError, ConnectionError, check_port_open


def _ssh_available(host, port):
    """Check whether the SSH test server is reachable."""
    return check_port_open(host, port, timeout=3)


def _connect(host, port, username, password):
    """Create a paramiko SSH client connected to the test server."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, port=port, username=username, password=password, timeout=10)
    return client


def _exec(client, cmd):
    """Run a command and return stripped stdout."""
    _, stdout, _ = client.exec_command(cmd)
    return stdout.read().decode("utf-8", errors="replace").strip()


@pytest.fixture
def ssh_client(ssh_host, ssh_creds):
    """Yield a connected paramiko SSH client, skip if server unavailable."""
    host, port = ssh_host
    username, password = ssh_creds
    if not _ssh_available(host, port):
        pytest.skip(f"SSH server not reachable at {host}:{port}")
    client = _connect(host, port, username, password)
    yield client
    client.close()


@pytest.mark.integration
class TestSSHExecute:
    def test_ssh_execute_command(self, ssh_client):
        output = _exec(ssh_client, "echo hello")
        assert "hello" in output

    def test_ssh_execute_whoami(self, ssh_client, ssh_creds):
        username, _ = ssh_creds
        output = _exec(ssh_client, "whoami")
        assert username in output


@pytest.mark.integration
class TestSSHUploadDownload:
    def test_ssh_upload_file(self, ssh_client, tmp_file):
        remote_path = "/tmp/tomoe_test_upload.txt"
        sftp = ssh_client.open_sftp()
        try:
            sftp.put(tmp_file, remote_path)
            output = _exec(ssh_client, f"cat {remote_path}")
            assert "hello from tomoe test" in output
        finally:
            try:
                sftp.remove(remote_path)
            except Exception:
                pass
            sftp.close()

    def test_ssh_download_file(self, ssh_client):
        remote_path = "/tmp/tomoe_test_download.txt"
        content = "download test content"

        # Create a file on the remote side
        _exec(ssh_client, f'echo "{content}" > {remote_path}')

        local_fd, local_path = tempfile.mkstemp(prefix="tomoe_dl_")
        os.close(local_fd)
        try:
            sftp = ssh_client.open_sftp()
            try:
                sftp.get(remote_path, local_path)
            finally:
                sftp.close()

            with open(local_path, "r") as f:
                downloaded = f.read()
            assert content in downloaded
        finally:
            os.unlink(local_path)
            try:
                _exec(ssh_client, f"rm -f {remote_path}")
            except Exception:
                pass


@pytest.mark.integration
class TestSSHAuthFailure:
    def test_ssh_auth_failure(self, ssh_host):
        host, port = ssh_host
        if not _ssh_available(host, port):
            pytest.skip(f"SSH server not reachable at {host}:{port}")
        with pytest.raises(paramiko.AuthenticationException):
            _connect(host, port, "testuser", "wrongpassword")

    def test_ssh_connection_failure(self):
        """Connecting to a non-listening port should fail."""
        with pytest.raises((OSError, paramiko.SSHException)):
            _connect("localhost", 1, "testuser", "testpass123")
