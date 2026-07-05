"""Mock-based feature tests for the connections layer.

Unlike the ``test_{ssh,winrm,smb}.py`` integration tests (which need live
servers and self-skip otherwise), these tests mock the wire libraries
(paramiko / pypsrp / pypsexec / smbclient) at their edges so Tomoe's OWN
Connection subclasses run for real. They exercise the happy path plus
error-classification (auth vs connection) and the shutdown_event contract,
and run everywhere with no external services.
"""

from threading import Event
from unittest import mock

import paramiko
import pytest

from tomoe.common import AuthenticationError, ConnectionError
from tomoe.config import Credential, RunOptions
from tomoe.connections.ssh import SSHConnection
from tomoe.connections.winrm import WinRMConnection
from tomoe.connections.smb import SMBConnection


def _cred(username="user", password="pass"):
    return Credential(username=username, password=password)


def _opts(**kwargs):
    return RunOptions(**kwargs)


# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #

def _mock_ssh_client(out=b"", err=b"", exit_status=0):
    client = mock.MagicMock()
    stdout = mock.MagicMock()
    stdout.read.return_value = out
    stdout.channel.recv_exit_status.return_value = exit_status
    stderr = mock.MagicMock()
    stderr.read.return_value = err
    client.exec_command.return_value = (mock.MagicMock(), stdout, stderr)
    return client


class TestSSHFeature:
    def test_execute_command_returns_stdout(self):
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.ssh.paramiko.SSHClient") as SSHClient:
            client = _mock_ssh_client(out=b"hello world\n")
            SSHClient.return_value = client
            conn = SSHConnection("10.0.0.1", _cred(), _opts(target_os="linux"))
            result = conn.execute(command="echo hi")
        assert "hello world" in result.output
        client.connect.assert_called_once()

    def test_execute_maps_auth_error(self):
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.ssh.paramiko.SSHClient") as SSHClient:
            client = mock.MagicMock()
            client.connect.side_effect = paramiko.AuthenticationException("bad creds")
            SSHClient.return_value = client
            conn = SSHConnection("10.0.0.1", _cred("user", "wrong"), _opts(target_os="linux"))
            with pytest.raises(AuthenticationError):
                conn.execute(command="whoami")

    def test_execute_maps_connection_error(self):
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.ssh.paramiko.SSHClient") as SSHClient:
            client = mock.MagicMock()
            client.connect.side_effect = paramiko.SSHException("negotiation failed")
            SSHClient.return_value = client
            conn = SSHConnection("10.0.0.1", _cred(), _opts(target_os="linux"))
            with pytest.raises(ConnectionError):
                conn.execute(command="whoami")

    def test_execute_unreachable_port_raises_connection_error(self):
        with mock.patch("tomoe.connections.base.check_port_open", return_value=False):
            conn = SSHConnection("10.0.0.1", _cred(), _opts(target_os="linux"))
            with pytest.raises(ConnectionError):
                conn.execute(command="whoami")

    def test_key_auth_when_password_none(self):
        # password=None => key-based auth (agent + ~/.ssh keys enabled).
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.ssh.paramiko.SSHClient") as SSHClient:
            client = _mock_ssh_client(out=b"ok")
            SSHClient.return_value = client
            conn = SSHConnection("10.0.0.1", _cred("user", None), _opts(target_os="linux"))
            conn.execute(command="id")
        kwargs = client.connect.call_args.kwargs
        assert kwargs["password"] is None
        assert kwargs["allow_agent"] is True
        assert kwargs["look_for_keys"] is True

    def test_empty_password_is_not_key_auth(self):
        # password="" is a literal (empty) password, distinct from None.
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.ssh.paramiko.SSHClient") as SSHClient:
            client = _mock_ssh_client(out=b"ok")
            SSHClient.return_value = client
            conn = SSHConnection("10.0.0.1", _cred("user", ""), _opts(target_os="linux"))
            conn.execute(command="id")
        kwargs = client.connect.call_args.kwargs
        assert kwargs["password"] == ""
        assert kwargs["allow_agent"] is False
        assert kwargs["look_for_keys"] is False

    def test_execute_preset_shutdown_raises_keyboardinterrupt(self):
        ev = Event()
        ev.set()
        conn = SSHConnection("10.0.0.1", _cred(), _opts(target_os="linux"))
        with pytest.raises(KeyboardInterrupt):
            conn.execute(command="whoami", shutdown_event=ev)

    def test_upload_file(self, tmp_file):
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.ssh.paramiko.SSHClient") as SSHClient:
            client = mock.MagicMock()
            sftp = mock.MagicMock()
            client.open_sftp.return_value = sftp
            SSHClient.return_value = client
            conn = SSHConnection("10.0.0.1", _cred(), _opts(target_os="linux"))
            result = conn.put_file(tmp_file, "/tmp/dest.txt")
        sftp.put.assert_called_once()
        assert "Copied" in result

    def test_upload_directory_recursive(self, tmp_dir):
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.ssh.paramiko.SSHClient") as SSHClient:
            client = mock.MagicMock()
            sftp = mock.MagicMock()
            client.open_sftp.return_value = sftp
            SSHClient.return_value = client
            conn = SSHConnection("10.0.0.1", _cred(), _opts(target_os="linux"))
            result = conn.put_file(tmp_dir, "/remote/dir")
        # tmp_dir fixture creates exactly 3 files.
        assert sftp.put.call_count == 3
        assert "3 file(s)" in result

    def test_download_file(self, tmp_path):
        dest = tmp_path / "dl.txt"
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.ssh.paramiko.SSHClient") as SSHClient:
            client = mock.MagicMock()
            sftp = mock.MagicMock()
            client.open_sftp.return_value = sftp
            st = mock.MagicMock()
            st.st_mode = 0o100644  # regular file
            sftp.stat.return_value = st

            def fake_get(remote, local):
                with open(local, "w") as f:
                    f.write("payload")

            sftp.get.side_effect = fake_get
            SSHClient.return_value = client
            conn = SSHConnection("10.0.0.1", _cred(), _opts(target_os="linux"))
            result = conn.get_file("/remote/file.txt", str(dest))
        sftp.get.assert_called_once()
        assert "Downloaded" in result
        assert dest.read_text() == "payload"


# --------------------------------------------------------------------------- #
# WinRM
# --------------------------------------------------------------------------- #

def _winrm_ps(RunspacePool, PowerShell, output=None, invoke_side_effect=None):
    """Wire up mocked RunspacePool + PowerShell and return the PowerShell mock."""
    rsp = RunspacePool.return_value
    rsp.__enter__.return_value = mock.MagicMock()
    rsp.__exit__.return_value = False  # do NOT suppress exceptions
    ps = PowerShell.return_value
    ps.output = output if output is not None else []
    ps.had_errors = False
    ps.streams.information = []
    ps.streams.warning = []
    ps.streams.error = []
    if invoke_side_effect is not None:
        ps.invoke.side_effect = invoke_side_effect
    return ps


class TestWinRMFeature:
    def test_execute_command_returns_output(self):
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.winrm.WSMan"), \
             mock.patch("tomoe.connections.winrm.RunspacePool") as RunspacePool, \
             mock.patch("tomoe.connections.winrm.PowerShell") as PowerShell:
            _winrm_ps(RunspacePool, PowerShell, output=["hello from winrm"])
            conn = WinRMConnection("host", _cred(), _opts())
            result = conn.execute(command="Write-Output 'x'")
        assert "hello from winrm" in result.output

    def test_execute_maps_auth_error(self):
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.winrm.WSMan"), \
             mock.patch("tomoe.connections.winrm.RunspacePool") as RunspacePool, \
             mock.patch("tomoe.connections.winrm.PowerShell") as PowerShell:
            _winrm_ps(RunspacePool, PowerShell,
                      invoke_side_effect=Exception("the server returned 401 unauthorized"))
            conn = WinRMConnection("host", _cred("user", "wrong"), _opts())
            with pytest.raises(AuthenticationError):
                conn.execute(command="whoami")

    def test_execute_maps_connection_error(self):
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.winrm.WSMan"), \
             mock.patch("tomoe.connections.winrm.RunspacePool") as RunspacePool, \
             mock.patch("tomoe.connections.winrm.PowerShell") as PowerShell:
            _winrm_ps(RunspacePool, PowerShell,
                      invoke_side_effect=Exception("connection timed out"))
            conn = WinRMConnection("host", _cred(), _opts())
            with pytest.raises(ConnectionError):
                conn.execute(command="whoami")

    def test_execute_unreachable_port_raises_connection_error(self):
        with mock.patch("tomoe.connections.base.check_port_open", return_value=False):
            conn = WinRMConnection("host", _cred(), _opts())
            with pytest.raises(ConnectionError):
                conn.execute(command="whoami")

    def test_execute_preset_shutdown_raises_keyboardinterrupt(self):
        ev = Event()
        ev.set()
        conn = WinRMConnection("host", _cred(), _opts())
        with pytest.raises(KeyboardInterrupt):
            conn.execute(command="whoami", shutdown_event=ev)

    def test_upload_file(self, tmp_file):
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.winrm.Client") as Client:
            Client.return_value.__exit__.return_value = False
            client = Client.return_value.__enter__.return_value
            conn = WinRMConnection("host", _cred(), _opts())
            result = conn.put_file(tmp_file, "C:\\Temp\\f.txt")
        client.copy.assert_called_once()
        assert "Copied" in result

    def test_download_file(self, tmp_path):
        dest = tmp_path / "wd.txt"
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.winrm.Client") as Client:
            Client.return_value.__exit__.return_value = False
            client = Client.return_value.__enter__.return_value
            client.execute_ps.return_value = ("FILE", mock.MagicMock(), False)

            def fake_fetch(remote, local):
                with open(local, "w") as f:
                    f.write("winrm-data")

            client.fetch.side_effect = fake_fetch
            conn = WinRMConnection("host", _cred(), _opts())
            result = conn.get_file("C:\\Temp\\f.txt", str(dest))
        assert "Downloaded" in result
        assert dest.read_text() == "winrm-data"


# --------------------------------------------------------------------------- #
# SMB
# --------------------------------------------------------------------------- #

class TestSMBFeature:
    def test_execute_command_returns_output(self):
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.smb.Client") as Client:
            client = Client.return_value
            client.run_executable.return_value = (b"hello from smb\n", b"", 0)
            conn = SMBConnection("host", _cred(), _opts(shell_type="cmd"))
            result = conn.execute(command="echo hi")
        assert "hello from smb" in result.output
        client.connect.assert_called_once()
        client.create_service.assert_called_once()

    def test_execute_maps_auth_error(self):
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.smb.Client") as Client:
            Client.return_value.connect.side_effect = Exception("STATUS_LOGON_FAILURE")
            conn = SMBConnection("host", _cred("user", "wrong"), _opts(shell_type="cmd"))
            with pytest.raises(AuthenticationError):
                conn.execute(command="whoami")

    def test_execute_maps_connection_error(self):
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.smb.Client") as Client:
            Client.return_value.connect.side_effect = Exception("Connection refused")
            conn = SMBConnection("host", _cred(), _opts(shell_type="cmd"))
            with pytest.raises(ConnectionError):
                conn.execute(command="whoami")

    def test_execute_unreachable_port_raises_connection_error(self):
        with mock.patch("tomoe.connections.base.check_port_open", return_value=False):
            conn = SMBConnection("host", _cred(), _opts(shell_type="cmd"))
            with pytest.raises(ConnectionError):
                conn.execute(command="whoami")

    def test_execute_honors_encrypt_false(self):
        # Proves the SMB layer threads encrypt=False into the pypsexec Client
        # (i.e. --no-encrypt is honored at the connection boundary) — this is
        # the structural fix: encrypt lives on self.options, not a call kwarg.
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.smb.Client") as Client:
            Client.return_value.run_executable.return_value = (b"ok", b"", 0)
            conn = SMBConnection("host", _cred(), _opts(shell_type="cmd", encrypt=False))
            conn.execute(command="x")
        assert Client.call_args.kwargs["encrypt"] is False

    def test_upload_file(self, tmp_file):
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.smb.smbclient"), \
             mock.patch("tomoe.connections.smb.smb_open") as smb_open_mock:
            remote_file = mock.MagicMock()
            smb_open_mock.return_value.__enter__.return_value = remote_file
            conn = SMBConnection("host", _cred(), _opts())
            result = conn.put_file(tmp_file, "C:\\Windows\\Temp\\f.txt")
        smb_open_mock.assert_called_once()
        remote_file.write.assert_called()
        assert "Copied" in result

    def test_upload_honors_encrypt_false(self, tmp_file):
        # --no-encrypt must also reach the smbclient session used by put_file,
        # not just the pypsexec Client used by execute.
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.smb.smbclient") as smbclient_mock, \
             mock.patch("tomoe.connections.smb.smb_open") as smb_open_mock:
            remote_file = mock.MagicMock()
            smb_open_mock.return_value.__enter__.return_value = remote_file
            conn = SMBConnection("host", _cred(), _opts(encrypt=False))
            conn.put_file(tmp_file, "C:\\Windows\\Temp\\f.txt")
        assert smbclient_mock.register_session.call_args.kwargs["encrypt"] is False

    def test_download_file(self, tmp_path):
        dest = tmp_path / "sd.txt"
        with mock.patch("tomoe.connections.base.check_port_open", return_value=True), \
             mock.patch("tomoe.connections.smb.smbclient"), \
             mock.patch("tomoe.connections.smb.smb_exists", return_value=True), \
             mock.patch("tomoe.connections.smb.smb_isdir", return_value=False), \
             mock.patch("tomoe.connections.smb.smb_open") as smb_open_mock:
            remote_file = mock.MagicMock()
            remote_file.read.side_effect = [b"smb-data", b""]
            smb_open_mock.return_value.__enter__.return_value = remote_file
            conn = SMBConnection("host", _cred(), _opts())
            result = conn.get_file("C:\\Windows\\Temp\\f.txt", str(dest))
        assert "Downloaded" in result
        assert dest.read_bytes() == b"smb-data"
