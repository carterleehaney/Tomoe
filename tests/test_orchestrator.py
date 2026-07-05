"""Unit tests for tomoe.orchestrator — dataclasses and execute_on_host logic."""

from threading import Lock, Event
from unittest.mock import MagicMock
from types import ModuleType

import pytest

from tomoe.common import AuthenticationError
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
    def _make_mock_protocol(self, execute_side_effect=None, upload_side_effect=None, download_side_effect=None):
        """Create a mock protocol module with execute/upload/download."""
        proto = ModuleType("mock_proto")
        proto.execute = MagicMock(side_effect=execute_side_effect) if execute_side_effect else MagicMock(return_value="output")
        proto.upload = MagicMock(side_effect=upload_side_effect) if upload_side_effect else MagicMock(return_value="uploaded")
        proto.download = MagicMock(side_effect=download_side_effect) if download_side_effect else MagicMock(return_value="downloaded")
        return proto

    def _run_execute(self, proto, usernames, passwords, **kwargs):
        """Run execute_on_host with the given mock protocol, patching get_protocol."""
        import tomoe.orchestrator as orch
        import tomoe.protocols as protocols

        original_protocols = protocols.PROTOCOLS.copy()
        try:
            protocols.PROTOCOLS["mock"] = proto
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
            protocols.PROTOCOLS.clear()
            protocols.PROTOCOLS.update(original_protocols)

    def test_execute_on_host_success(self):
        proto = self._make_mock_protocol()
        result = self._run_execute(proto, ["admin"], ["pass123"])

        assert result.success is True
        assert result.host == "10.0.0.1"
        assert result.username == "admin"
        assert result.output == "output"
        proto.execute.assert_called_once()

    def test_execute_on_host_auth_failure_rotates_credentials(self):
        """When AuthenticationError is raised, the next credential pair is tried."""
        call_count = 0

        def side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            raise AuthenticationError("bad creds")

        proto = self._make_mock_protocol(execute_side_effect=side_effect)
        result = self._run_execute(proto, ["user1", "user2"], ["pass1", "pass2"])

        assert result.success is False
        assert "Invalid credentials" in result.message
        # Should have tried all 4 combinations: user1/pass1, user1/pass2, user2/pass1, user2/pass2
        assert call_count == 4

    def test_execute_on_host_non_auth_error_stops(self):
        """A non-auth exception stops immediately without trying more credentials."""
        proto = self._make_mock_protocol(
            execute_side_effect=RuntimeError("network down")
        )
        result = self._run_execute(proto, ["user1", "user2"], ["pass1", "pass2"])

        assert result.success is False
        assert "network down" in result.message
        # Should have stopped after the first failure
        proto.execute.assert_called_once()

    def test_execute_on_host_upload(self):
        proto = self._make_mock_protocol()
        result = self._run_execute(
            proto, ["admin"], ["pass"],
            command=None, source="/tmp/file.txt", dest="/remote/file.txt",
        )

        assert result.success is True
        assert "uploaded" in result.message.lower() or "uploaded" in result.output.lower()
        proto.upload.assert_called_once()

    def test_execute_on_host_download(self):
        proto = self._make_mock_protocol()
        result = self._run_execute(
            proto, ["admin"], ["pass"],
            command=None, source="/remote/file.txt", dest="/tmp/file.txt",
            download=True,
        )

        assert result.success is True
        proto.download.assert_called_once()
