"""Config objects shared by the connection layer.

These dataclasses replace the loose, protocol-specific kwargs dict
(``shell_type``, ``encrypt``, ``target_os``, ...) that used to be splatted
into module-level ``execute``/``upload``/``download`` calls. Every
connection reads its knobs from ``self.options`` instead of from
call-site kwargs.
"""

from dataclasses import dataclass
from typing import Literal, Optional


@dataclass
class Credential:
    """A single username/password/domain triple.

    ``auth_name`` is the ONE place that handles domain qualification. It
    subsumes ``common.build_auth_username`` and the SMB-only ``DOMAIN\\user``
    splitting that used to live only in ``protocols/smb.py``.
    """

    username: str
    password: Optional[str] = None
    domain: str = ""

    def auth_name(self, is_linux: bool = False) -> str:
        """Return the fully-qualified auth username for this credential.

        If ``username`` is already in ``DOMAIN\\user`` form and no explicit
        domain was set, the embedded domain is used. Domain qualification is
        skipped for Linux targets (SSH auth there has no notion of it).
        """
        username = self.username
        domain = self.domain

        if "\\" in username and not domain:
            domain, username = username.split("\\", 1)

        if domain and not is_linux:
            return f"{domain}\\{username}"
        return username


@dataclass
class RunOptions:
    """Every protocol-specific knob, as a field instead of a kwarg.

    This is what eliminates the old ad hoc kwargs dict: ``cli.main()``
    builds one of these from parsed args and passes it straight through to
    the ``Connection``, which reads whichever fields are relevant to it.
    """

    shell_type: str = "powershell"
    encrypt: bool = True
    target_os: str = "windows"
    timeout: int = 30
    threads: int = 10
    verbose: bool = False
    port: Optional[int] = None


@dataclass
class TransferSpec:
    direction: Literal["upload", "download"]
    src: str
    dst: str
