"""The Connection ABC every protocol module implements.

NetExec-style abstraction: a connection owns its host/credential/options and
exposes a small, uniform surface (``connect``, ``execute``, ``put_file``,
``get_file``, optionally ``interactive``). The three abstract operation
methods have IDENTICAL signatures in every subclass so that dispatch code in
``orchestrator.py`` never needs to special-case a protocol.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from threading import Event
from typing import Callable, Optional

from tomoe.common import TomoeError, check_port_open
from tomoe.config import Credential, RunOptions


class NotSupportedError(TomoeError):
    """Raised when a connection is asked to do something it doesn't support
    (e.g. an interactive shell on a protocol other than WinRM)."""


@dataclass
class ExecResult:
    """Result of a command execution, uniform across all protocols."""

    host: str
    stdout: str = ""
    stderr: str = ""
    return_code: int = 0

    @property
    def output(self) -> str:
        """Combined text for orchestrator/cli printing (stdout, then stderr)."""
        if self.stdout and self.stderr:
            return self.stdout + "\n" + self.stderr
        return self.stdout or self.stderr


class Connection(ABC):
    DEFAULT_PORT: int
    PROTOCOL: str
    SUPPORTS_INTERACTIVE: bool = False

    def __init__(self, host: str, credential: Credential, options: RunOptions):
        self.host = host
        self.credential = credential
        self.options = options or RunOptions()

    @property
    def port(self) -> int:
        """Effective port: an explicit ``RunOptions.port`` override wins,
        otherwise the protocol's ``DEFAULT_PORT``."""
        return self.options.port or self.DEFAULT_PORT

    def check_reachable(self, timeout: int = 5) -> bool:
        return check_port_open(self.host, self.port, timeout=timeout)

    @abstractmethod
    def connect(self) -> None:
        """Authenticate to the host. Raise AuthenticationError/ConnectionError."""

    @abstractmethod
    def execute(
        self,
        command: Optional[str] = None,
        *,
        script_path: Optional[str] = None,
        script_args: str = "",
        status_callback: Optional[Callable[[str], None]] = None,
        shutdown_event: Optional[Event] = None,
    ) -> ExecResult:
        """Run ``command`` or the script at ``script_path`` on the remote host."""

    @abstractmethod
    def put_file(
        self,
        src: str,
        dst: str,
        *,
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Copy a local file or directory ``src`` to remote ``dst``."""

    @abstractmethod
    def get_file(
        self,
        src: str,
        dst: str,
        *,
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Copy a remote file or directory ``src`` to local ``dst``."""

    def interactive(self) -> int:
        raise NotSupportedError(f"{self.PROTOCOL} does not support interactive shells")
