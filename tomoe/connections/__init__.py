from tomoe.connections.base import Connection, ExecResult, NotSupportedError
from tomoe.connections.smb import SMBConnection
from tomoe.connections.ssh import SSHConnection
from tomoe.connections.winrm import WinRMConnection

CONNECTIONS: dict[str, type[Connection]] = {
    "winrm": WinRMConnection,
    "smb": SMBConnection,
    "ssh": SSHConnection,
}


def get_connection(name: str) -> type[Connection]:
    return CONNECTIONS[name]


__all__ = [
    "Connection",
    "ExecResult",
    "NotSupportedError",
    "CONNECTIONS",
    "get_connection",
    "SMBConnection",
    "SSHConnection",
    "WinRMConnection",
]
