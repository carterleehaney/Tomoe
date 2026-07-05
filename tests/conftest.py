import os
import tempfile

import pytest


@pytest.fixture
def ssh_host():
    """Return (host, port) for the SSH test container."""
    port = int(os.environ.get("SSH_TEST_PORT", "2222"))
    return ("localhost", port)


@pytest.fixture
def ssh_creds():
    """Return (username, password) for the SSH test container."""
    return ("testuser", "testpass123")


@pytest.fixture
def winrm_host():
    """Return (host, port) for the WinRM test target."""
    host = os.environ.get("WINRM_TEST_HOST", "localhost")
    port = int(os.environ.get("WINRM_TEST_PORT", "5985"))
    return (host, port)


@pytest.fixture
def winrm_creds():
    """Return (username, password) for WinRM tests."""
    return ("testuser", "TestPass123!")


@pytest.fixture
def smb_host():
    """Return (host, port) for the SMB test target."""
    host = os.environ.get("SMB_TEST_HOST", "localhost")
    port = int(os.environ.get("SMB_TEST_PORT", "445"))
    return (host, port)


@pytest.fixture
def smb_creds():
    """Return (username, password) for SMB tests."""
    return ("testuser", "TestPass123!")


@pytest.fixture
def tmp_file():
    """Create a temporary file with known content, yield its path, then clean up."""
    content = "hello from tomoe test\nline two\n"
    fd, path = tempfile.mkstemp(prefix="tomoe_test_", suffix=".txt")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        yield path
    finally:
        if os.path.exists(path):
            os.unlink(path)


@pytest.fixture
def tmp_dir():
    """Create a temporary directory with a few test files, yield its path, then clean up."""
    import shutil

    dirpath = tempfile.mkdtemp(prefix="tomoe_test_dir_")
    try:
        for name in ("file_a.txt", "file_b.txt", "file_c.txt"):
            with open(os.path.join(dirpath, name), "w") as f:
                f.write(f"content of {name}\n")
        yield dirpath
    finally:
        shutil.rmtree(dirpath, ignore_errors=True)
