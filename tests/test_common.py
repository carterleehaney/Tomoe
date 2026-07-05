"""Unit tests for tomoe.common — error hierarchy, auth helpers, port checking."""

from threading import Event, Thread

import pytest

from tomoe.common import (
    TomoeError,
    AuthenticationError,
    ConnectionError,
    build_auth_username,
    check_port_open,
    run_interruptible,
)


class TestErrorHierarchy:
    def test_authentication_error_is_tomoe_error(self):
        assert issubclass(AuthenticationError, TomoeError)

    def test_connection_error_is_tomoe_error(self):
        assert issubclass(ConnectionError, TomoeError)

    def test_authentication_error_instance(self):
        err = AuthenticationError("bad creds")
        assert isinstance(err, TomoeError)
        assert str(err) == "bad creds"

    def test_connection_error_instance(self):
        err = ConnectionError("refused")
        assert isinstance(err, TomoeError)
        assert str(err) == "refused"


class TestBuildAuthUsername:
    def test_with_domain(self):
        result = build_auth_username("user", "DOMAIN")
        assert result == "DOMAIN\\user"

    def test_without_domain(self):
        result = build_auth_username("user", "")
        assert result == "user"

    def test_without_domain_none(self):
        result = build_auth_username("user", None)
        assert result == "user"

    def test_linux_ignores_domain(self):
        result = build_auth_username("user", "DOMAIN", is_linux=True)
        assert result == "user"

    def test_linux_without_domain(self):
        result = build_auth_username("user", "", is_linux=True)
        assert result == "user"


class TestCheckPortOpen:
    def test_unreachable_port(self):
        # Port 1 on localhost should not be open
        result = check_port_open("localhost", 1, timeout=1)
        assert result is False

    def test_invalid_host(self):
        result = check_port_open("192.0.2.1", 22, timeout=1)
        assert result is False


class TestRunInterruptible:
    def test_returns_value_when_no_event(self):
        # With no shutdown_event, target runs inline and its value is returned.
        assert run_interruptible(lambda: "done") == "done"

    def test_returns_value_with_unset_event(self):
        ev = Event()
        assert run_interruptible(lambda: 42, ev, "host", poll_interval=0.01) == 42

    def test_propagates_exception(self):
        def boom():
            raise ValueError("kaboom")

        with pytest.raises(ValueError, match="kaboom"):
            run_interruptible(boom, Event(), "host", poll_interval=0.01)

    def test_raises_keyboardinterrupt_when_event_fires_midrun(self):
        # A blocked target is interrupted once the shutdown event is set from
        # another thread. The target waits on a separate event that is never
        # set, so only the shutdown path can end the call (no completion race).
        shutdown = Event()
        never = Event()
        started = Event()

        def slow():
            started.set()
            never.wait(5)  # blocks; `never` is never set
            return "should not be returned"

        def trigger():
            started.wait(2)
            shutdown.set()

        Thread(target=trigger, daemon=True).start()
        with pytest.raises(KeyboardInterrupt):
            run_interruptible(slow, shutdown, "10.0.0.1", poll_interval=0.02)
