"""Unit tests for tomoe.orchestrator — dataclasses and execute_on_host logic."""

from threading import Lock, Event
from unittest.mock import MagicMock

import pytest

from tomoe.common import AuthenticationError
from tomoe.connections.base import Connection, ExecResult
from tomoe.orchestrator import HostResult, HostStatus, execute_on_host


class TestHostResult:
    def test_basic_construction(self):
        r = HostResult(host="10.0.0.1", success=True, username="admin", message="OK", output="hello")
        assert r.host == "10.0.0.1"
        assert r.success is True
        assert r.username == "admin"
        assert r.message == "OK"
        assert r.output == "hello"

    def test_defaults(self):
        r = HostResult(host="10.0.0.1", success=False)
        assert r.username is None
        assert r.message == ""
        assert r.output == ""


class TestHostStatus:
    def test_basic_construction(self):
        s = HostStatus(host="10.0.0.1", status="pending")
        assert s.host == "10.0.0.1"
        assert s.status == "pending"
        assert s.current_user == "-"
        assert s.message == "Waiting..."

    def test_custom_fields(self):
        s = HostStatus(host="10.0.0.1", status="trying", current_user="admin", message="Authenticating...")
        assert s.status == "trying"
        assert s.current_user == "admin"


class TestExecuteOnHost:
    def _make_mock_connection_cls(self, execute_side_effect=None, upload_side_effect=None, download_side_effect=None):
        """Build a fake Connection subclass backed by trackable MagicMocks.

        The mocks live on the class (not per-instance) so assertions like
        ``execute_mock.assert_called_once()`` see calls across every
        credential attempt, since ``execute_on_host`` instantiates a fresh
        connection object per username/password pair.
        """
        execute_mock = MagicMock(side_effect=execute_side_effect) if execute_side_effect else MagicMock(
            return_value=ExecResult(host="10.0.0.1", stdout="output")
        )
        upload_mock = MagicMock(side_effect=upload_side_effect) if upload_side_effect else MagicMock(return_value="uploaded")
        download_mock = MagicMock(side_effect=download_side_effect) if download_side_effect else MagicMock(return_value="downloaded")

        class FakeConnection(Connection):
            DEFAULT_PORT = 1
            PROTOCOL = "mock"

            def connect(self):
                pass

            def execute(self, command=None, *, script_path=None, script_args="", status_callback=None, shutdown_event=None):
                return execute_mock(
                    command=command, script_path=script_path, script_args=script_args,
                    status_callback=status_callback, shutdown_event=shutdown_event,
                )

            def put_file(self, src, dst, *, status_callback=None):
                return upload_mock(src=src, dst=dst, status_callback=status_callback)

            def get_file(self, src, dst, *, status_callback=None):
                return download_mock(src=src, dst=dst, status_callback=status_callback)

        FakeConnection.execute_mock = execute_mock
        FakeConnection.upload_mock = upload_mock
        FakeConnection.download_mock = download_mock
        return FakeConnection

    def _run_execute(self, connection_cls, usernames, passwords, **kwargs):
        """Run execute_on_host with the given fake connection class, patching CONNECTIONS."""
        from tomoe.connections import CONNECTIONS

        original_connections = CONNECTIONS.copy()
        try:
            CONNECTIONS["mock"] = connection_cls
            host_statuses = {}
            status_lock = Lock()

            defaults = dict(
                host="10.0.0.1",
                usernames=usernames,
                passwords=passwords,
                domain="",
                protocol="mock",
                script_path=None,
                command="whoami",
                script_args="",
                verbose=False,
                host_statuses=host_statuses,
                status_lock=status_lock,
            )
            defaults.update(kwargs)
            return execute_on_host(**defaults)
        finally:
            CONNECTIONS.clear()
            CONNECTIONS.update(original_connections)

    def test_execute_on_host_success(self):
        connection_cls = self._make_mock_connection_cls()
        result = self._run_execute(connection_cls, ["admin"], ["pass123"])

        assert result.success is True
        assert result.host == "10.0.0.1"
        assert result.username == "admin"
        assert result.output == "output"
        connection_cls.execute_mock.assert_called_once()

    def test_execute_on_host_auth_failure_rotates_credentials(self):
        """When AuthenticationError is raised, the next credential pair is tried."""
        call_count = 0

        def side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            raise AuthenticationError("bad creds")

        connection_cls = self._make_mock_connection_cls(execute_side_effect=side_effect)
        result = self._run_execute(connection_cls, ["user1", "user2"], ["pass1", "pass2"])

        assert result.success is False
        assert "Invalid credentials" in result.message
        # Should have tried all 4 combinations: user1/pass1, user1/pass2, user2/pass1, user2/pass2
        assert call_count == 4

    def test_execute_on_host_non_auth_error_stops(self):
        """A non-auth exception stops immediately without trying more credentials."""
        connection_cls = self._make_mock_connection_cls(
            execute_side_effect=RuntimeError("network down")
        )
        result = self._run_execute(connection_cls, ["user1", "user2"], ["pass1", "pass2"])

        assert result.success is False
        assert "network down" in result.message
        # Should have stopped after the first failure
        connection_cls.execute_mock.assert_called_once()

    def test_execute_on_host_upload(self):
        connection_cls = self._make_mock_connection_cls()
        result = self._run_execute(
            connection_cls, ["admin"], ["pass"],
            command=None, source="/tmp/file.txt", dest="/remote/file.txt",
        )

        assert result.success is True
        assert "uploaded" in result.message.lower() or "uploaded" in result.output.lower()
        connection_cls.upload_mock.assert_called_once()

    def test_execute_on_host_download(self):
        connection_cls = self._make_mock_connection_cls()
        result = self._run_execute(
            connection_cls, ["admin"], ["pass"],
            command=None, source="/remote/file.txt", dest="/tmp/file.txt",
            download=True,
        )

        assert result.success is True
        connection_cls.download_mock.assert_called_once()
