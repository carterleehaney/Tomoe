"""Unit tests for tomoe.common — error hierarchy, auth helpers, port checking."""

from tomoe.common import (
    TomoeError,
    AuthenticationError,
    ConnectionError,
    build_auth_username,
    check_port_open,
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
