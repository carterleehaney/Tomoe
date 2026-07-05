"""SMB connection (pypsexec + smbclient), migrated from ``protocols/smb.py``.

This is where the structural SMB fix lives: ``shell_type``/``encrypt`` are no
longer kwargs threaded ad hoc into ``upload``/``download`` (the old
``tomoe smb --upload/--download`` TypeError is gone because ``put_file``/
``get_file`` never accepted those params to begin with here) — they live on
``self.options`` and are read directly by ``execute``/``put_file``/
``get_file``/``connect``, so ``--no-encrypt`` actually reaches the SMB
session in every code path.
"""

import logging
import os
import warnings
from contextlib import contextmanager
from threading import Event, Thread
from typing import Callable, Optional

import smbclient
import smbclient.shutil as smb_shutil
from pypsexec.client import Client
from smbclient import open_file as smb_open
from smbclient import remove as smb_remove
from smbclient import walk as smb_walk
from smbclient.path import exists as smb_exists
from smbclient.path import isdir as smb_isdir
from smbclient.path import isfile as smb_isfile

from tomoe.common import AuthenticationError, ConnectionError
from tomoe.connections.base import Connection, ExecResult

# Suppress cryptography deprecation warnings from dependencies
warnings.filterwarnings("ignore", category=DeprecationWarning, module=".*crypto.*")
warnings.filterwarnings("ignore", message=".*ARC4.*")

DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1MB chunks for file transfers
DEFAULT_CONNECTION_TIMEOUT = 30  # seconds


def _make_unc_path(server, share, path):
    """Create a UNC path for smbclient operations."""
    if path:
        path = path.replace("/", "\\")
        return f"\\\\{server}\\{share}\\{path}"
    else:
        return f"\\\\{server}\\{share}"


def _copy_file_chunked(source_file, dest_file, chunk_size=DEFAULT_CHUNK_SIZE):
    """Copy data from source file to destination file in chunks."""
    while True:
        chunk = source_file.read(chunk_size)
        if not chunk:
            break
        dest_file.write(chunk)


class SMBConnection(Connection):
    DEFAULT_PORT = 445
    PROTOCOL = "smb"

    def connect(self) -> None:
        """SMB validates connectivity up front; authentication happens as
        part of ``execute``/``put_file``/``get_file`` (pypsexec's ``Client``
        and smbclient's session registration each perform their own auth)."""
        if not self.check_reachable(timeout=5):
            raise ConnectionError(f"Port {self.port} not reachable on {self.host}")

    def execute(
        self,
        command: Optional[str] = None,
        *,
        script_path: Optional[str] = None,
        script_args: str = "",
        status_callback: Optional[Callable[[str], None]] = None,
        shutdown_event: Optional[Event] = None,
    ) -> ExecResult:
        """Execute a script or command on a remote Windows host using SMB/psexec."""
        host = self.host
        auth_username = self.credential.auth_name()
        password = self.credential.password
        verbose = self.options.verbose
        shell_type = self.options.shell_type
        encrypt = self.options.encrypt

        # Suppress pypsexec logging to avoid artifacts in output
        pypsexec_logger = logging.getLogger("pypsexec")
        if not verbose:
            pypsexec_logger.setLevel(logging.CRITICAL + 1)  # Effectively disable
        else:
            pypsexec_logger.setLevel(logging.INFO)

        # Perform a quick connectivity check before attempting SMB.
        if not self.check_reachable(timeout=5):
            raise ConnectionError(f"Port {self.port} not reachable on {host}")

        script_name = None
        share = None
        remote_path = None
        client = None
        execution_done = Event()
        cleanup_started = Event()

        def start_cleanup():
            """Best-effort cleanup that can be triggered during shutdown."""
            if cleanup_started.is_set():
                return

            cleanup_started.set()

            if status_callback and shutdown_event and shutdown_event.is_set():
                status_callback("Shutdown requested, starting SMB cleanup...")

            try:
                if client is not None:
                    try:
                        client.remove_service()
                    except Exception:
                        pass
                    try:
                        client.disconnect()
                    except Exception:
                        pass

                if script_name is not None and share is not None and remote_path is not None:
                    try:
                        script_unc_path = _make_unc_path(host, share, remote_path)
                        smb_remove(script_unc_path)
                        logging.debug(f"Cleaned up script file: {share}\\{remote_path}")
                    except Exception:
                        pass

                if script_path is not None:
                    try:
                        smbclient.delete_session(host)
                    except Exception:
                        pass
            except Exception:
                pass

        def run_remote_command(executable, arguments):
            execution_result = {}
            execution_done.clear()

            def execute_remote():
                try:
                    stdout, stderr, rc = client.run_executable(
                        executable=executable,
                        arguments=arguments,
                    )
                    execution_result["stdout"] = stdout
                    execution_result["stderr"] = stderr
                    execution_result["rc"] = rc
                except Exception as exc:
                    execution_result["exception"] = exc
                finally:
                    execution_done.set()

            execution_thread = Thread(target=execute_remote, daemon=True)
            execution_thread.start()

            while not execution_done.wait(timeout=0.25):
                if shutdown_event and shutdown_event.is_set():
                    start_cleanup()
                    raise KeyboardInterrupt(f"Interrupted by user while executing on {host}")

            if "exception" in execution_result:
                raise execution_result["exception"]

            return (
                execution_result["stdout"],
                execution_result["stderr"],
                execution_result["rc"],
            )

        try:
            client = Client(
                host,
                username=auth_username,
                password=password,
                encrypt=encrypt,
            )

            logging.debug(f"Connecting to {host} as {auth_username}...")

            client.connect()

            if status_callback:
                status_callback("Authenticated, preparing command...")

            logging.debug("Creating remote service...")

            client.create_service()

            if script_path:
                logging.debug(f"Uploading script: {script_path}")

                script_name = os.path.basename(script_path)

                smbclient.register_session(
                    host,
                    username=auth_username,
                    password=password,
                    port=self.port,
                    encrypt=encrypt,
                    connection_timeout=DEFAULT_CONNECTION_TIMEOUT,
                )

                share = None
                remote_path = None

                try:
                    admin_unc_path = _make_unc_path(host, "ADMIN$", script_name)
                    with open(script_path, "rb") as local_file:
                        with smb_open(admin_unc_path, mode="wb") as remote_file:
                            _copy_file_chunked(local_file, remote_file)
                    share = "ADMIN$"
                    remote_path = script_name
                    logging.debug(f"Script uploaded to \\\\{host}\\ADMIN$\\{script_name}")
                except Exception as e:
                    logging.debug(f"ADMIN$ upload failed: {e}, trying C$\\Windows\\Temp...")

                    try:
                        temp_path = f"Windows\\Temp\\{script_name}"
                        temp_unc_path = _make_unc_path(host, "C$", temp_path)
                        with open(script_path, "rb") as local_file:
                            with smb_open(temp_unc_path, mode="wb") as remote_file:
                                _copy_file_chunked(local_file, remote_file)
                        share = "C$"
                        remote_path = temp_path
                        logging.debug(f"Script uploaded to \\\\{host}\\C$\\{temp_path}")
                    except Exception as e2:
                        raise Exception(f"Failed to upload script to any share: ADMIN$ and C$ both failed: {e2}")

                if share == "ADMIN$":
                    unc_path = f"\\\\{host}\\ADMIN$\\{script_name}"
                else:
                    unc_path = f"C:\\Windows\\Temp\\{script_name}"

                if shell_type.lower() == "cmd":
                    script_ext = os.path.splitext(script_name)[1].lower()
                    if script_ext not in [".bat", ".cmd"]:
                        raise ValueError(f"CMD shell requires .bat or .cmd files, got: {script_ext}")

                    executable = "cmd.exe"
                    if script_args:
                        arguments = f'/c "{unc_path}" {script_args}'
                    else:
                        arguments = f'/c "{unc_path}"'
                else:
                    script_ext = os.path.splitext(script_name)[1].lower()
                    if script_ext != ".ps1":
                        raise ValueError(f"PowerShell shell requires .ps1 files, got: {script_ext}")

                    if script_args:
                        ps_command = f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"& '{unc_path}' {script_args}; [System.Environment]::Exit($LASTEXITCODE)\""
                    else:
                        ps_command = f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"& '{unc_path}'; [System.Environment]::Exit($LASTEXITCODE)\""

                    executable = "cmd.exe"
                    arguments = f"/c {ps_command} < NUL 2>&1"

            elif command:
                logging.debug(f"Executing command: {command}")

                if shell_type.lower() == "cmd":
                    executable = "cmd.exe"
                    arguments = f"/c {command}"
                else:
                    ps_command = f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command}; [System.Environment]::Exit($LASTEXITCODE)\""
                    executable = "cmd.exe"
                    arguments = f"/c {ps_command} < NUL 2>&1"
            else:
                raise ValueError("Either script_path or command must be provided.")

            logging.debug(f"Executing on {host}...")

            if status_callback:
                status_callback("Executing...")

            stdout, stderr, rc = run_remote_command(executable, arguments)

            temp_stdout = stdout.decode("utf-8", errors="replace") if stdout else ""

            if (rc != 0 or "The system cannot find the path specified" in temp_stdout or "' is not recognized" in temp_stdout) and "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" in arguments:
                logging.debug("Full path failed. Retrying with short 'powershell.exe' path...")

                arguments = arguments.replace(
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "powershell.exe",
                )

                logging.debug(f"Retry arguments: {arguments}")

                stdout, stderr, rc = run_remote_command(executable, arguments)

            logging.debug(f"Command executed with return code: {rc}")

            start_cleanup()

            stdout_text = stdout.decode("utf-8", errors="replace").strip() if stdout else ""
            stderr_text = stderr.decode("utf-8", errors="replace").strip() if stderr else ""

            logging.debug(f"Output captured: stdout={len(stdout_text)} chars, stderr={len(stderr_text)} chars")

            if stdout_text and stderr_text:
                combined = stdout_text + "\n" + stderr_text
            elif stdout_text:
                combined = stdout_text
            elif stderr_text:
                combined = stderr_text
            else:
                combined = f"Command executed with return code: {rc}"

            return ExecResult(host=host, stdout=combined, return_code=rc)

        except Exception as e:
            error_str = str(e).lower()

            if any(auth_err in error_str for auth_err in [
                "logon_failure", "access_denied", "status_logon_failure",
                "bad password", "wrong password", "invalid credentials",
                "authentication", "unauthorized", "rejected", "access is denied"
            ]):
                raise AuthenticationError(f"Authentication failed for {auth_username}@{host}: {e}")

            if any(conn_err in error_str for conn_err in [
                "connection", "timeout", "refused", "unreachable", "reset",
                "cannot connect", "failed to connect"
            ]):
                raise ConnectionError(f"Connection failed to {host}: {e}")

            logging.debug(f"SMB execution failed: {e}")
            raise
        finally:
            start_cleanup()

    @contextmanager
    def _smb_session(self):
        """Context manager for SMB session registration, using ``self.options.encrypt``."""
        host = self.host
        auth_username = self.credential.auth_name()
        password = self.credential.password
        encrypt = self.options.encrypt

        if not self.check_reachable(timeout=5):
            raise ConnectionError(f"Port {self.port} not reachable on {host}")

        try:
            logging.debug(f"Connecting to {host}...")
            logging.debug(f"Authenticating as {auth_username}...")

            smbclient.register_session(
                host,
                username=auth_username,
                password=password,
                port=self.port,
                encrypt=encrypt,
                connection_timeout=DEFAULT_CONNECTION_TIMEOUT,
            )

            yield host

        except Exception as e:
            error_msg = str(e).lower()
            auth_error_patterns = [
                "logon_failure", "access_denied", "status_logon_failure",
                "bad password", "wrong password", "invalid credentials",
                "authentication", "unauthorized", "rejected", "logon failure"
            ]
            if any(pattern in error_msg for pattern in auth_error_patterns):
                raise AuthenticationError(f"Authentication failed: {e}")
            raise ConnectionError(f"Connection failed to {host}: {e}")
        finally:
            try:
                smbclient.delete_session(host)
            except Exception:
                pass

    def put_file(
        self,
        src: str,
        dst: str,
        *,
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Copy a local file or directory to a remote Windows host using SMB."""
        auth_username = self.credential.auth_name()
        logging.debug(f"Preparing to copy to {self.host} as {auth_username}")

        if not os.path.exists(src):
            raise FileNotFoundError(f"Source not found: {src}")

        dest_normalized = dst.replace("/", "\\").lstrip("\\")

        if len(dest_normalized) < 3 or dest_normalized[1] != ":":
            raise ValueError(f"Invalid destination format. Expected Windows path like 'C:\\path\\to\\file', got: {dst}")

        share = f"{dest_normalized[0]}$"
        remote_base_path = dest_normalized[3:] if len(dest_normalized) > 3 else ""

        logging.debug(f"Share: {share}, Remote base path: {remote_base_path}")

        with self._smb_session() as server:
            if os.path.isfile(src):
                if status_callback:
                    status_callback("Copying 1 file...")
                file_size = os.path.getsize(src)
                remote_path = remote_base_path if remote_base_path else os.path.basename(src)

                logging.debug(f"Uploading {src} ({file_size} bytes) to \\\\{server}\\{share}\\{remote_path}...")

                remote_unc_path = _make_unc_path(server, share, remote_path)
                with open(src, "rb") as local_file:
                    with smb_open(remote_unc_path, mode="wb") as remote_file:
                        _copy_file_chunked(local_file, remote_file)

                if status_callback:
                    status_callback("Copying 1/1 files...")

                logging.debug(f"File copied successfully: {file_size} bytes")

                return f"Copied {os.path.basename(src)} ({file_size} bytes) to \\\\{server}\\{share}\\{remote_path}"

            else:
                total_files = 0
                total_bytes = 0

                if status_callback:
                    total_file_count = sum(len(files) for _, _, files in os.walk(src))
                    status_callback(f"Copying 0/{total_file_count} files...")

                for root, dirs, files in os.walk(src):
                    rel_root = os.path.relpath(root, src)
                    if rel_root == ".":
                        rel_root = ""

                    if rel_root:
                        remote_dir = remote_base_path + "\\" + rel_root.replace("/", "\\") if remote_base_path else rel_root.replace("/", "\\")
                    else:
                        remote_dir = remote_base_path

                    if remote_dir:
                        remote_dir_unc = _make_unc_path(server, share, remote_dir)
                        try:
                            smbclient.makedirs(remote_dir_unc, exist_ok=True)
                            logging.debug(f"Created directory: \\\\{server}\\{share}\\{remote_dir}")
                        except smbclient.SMBException as e:
                            msg = str(e).lower()
                            if "already exists" in msg or "status_object_name_collision" in msg:
                                logging.debug(f"Directory already exists: \\\\{server}\\{share}\\{remote_dir}")
                            else:
                                raise

                    for filename in files:
                        local_file_path = os.path.join(root, filename)
                        if remote_dir:
                            remote_file_path = remote_dir + "\\" + filename
                        else:
                            remote_file_path = filename

                        file_size = os.path.getsize(local_file_path)

                        logging.debug(f"Uploading {local_file_path} ({file_size} bytes) to \\\\{server}\\{share}\\{remote_file_path}...")

                        remote_file_unc = _make_unc_path(server, share, remote_file_path)
                        with open(local_file_path, "rb") as local_file:
                            with smb_open(remote_file_unc, mode="wb") as remote_file:
                                _copy_file_chunked(local_file, remote_file)

                        total_files += 1
                        total_bytes += file_size

                        if status_callback:
                            status_callback(f"Copying {total_files}/{total_file_count} files...")

                logging.debug(f"Directory copied successfully: {total_files} files, {total_bytes} bytes")

                return f"Copied {total_files} file(s) ({total_bytes} bytes) to \\\\{server}\\{share}\\{remote_base_path}"

    def get_file(
        self,
        src: str,
        dst: str,
        *,
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Download a file or directory from a remote Windows host using SMB."""
        auth_username = self.credential.auth_name()
        logging.debug(f"Preparing to download from {self.host} as {auth_username}")

        source_normalized = src.replace("/", "\\")
        source_normalized = source_normalized.lstrip("\\")

        if len(source_normalized) < 3 or source_normalized[1] != ":":
            raise ValueError(f"Invalid source format. Expected Windows path like 'C:\\path\\to\\file', got: {src}")

        share = f"{source_normalized[0]}$"
        remote_base_path = source_normalized[3:] if len(source_normalized) > 3 else ""

        logging.debug(f"Share: {share}, Remote base path: {remote_base_path}")

        with self._smb_session() as server:
            remote_unc_path = _make_unc_path(server, share, remote_base_path)

            is_directory = False
            if smb_exists(remote_unc_path):
                try:
                    is_directory = smb_isdir(remote_unc_path)
                except (OSError, IOError):
                    is_directory = False
            else:
                raise FileNotFoundError(f"Remote path does not exist: {remote_unc_path}")

            if not is_directory:
                if status_callback:
                    status_callback("Downloading 1 file...")

                if os.path.isdir(dst):
                    dst = os.path.join(dst, os.path.basename(remote_base_path))

                dest_dir = os.path.dirname(dst)
                if dest_dir:
                    os.makedirs(dest_dir, exist_ok=True)

                logging.debug(f"Downloading \\\\{server}\\{share}\\{remote_base_path} to {dst}...")

                with smb_open(remote_unc_path, mode="rb") as remote_file:
                    with open(dst, "wb") as local_file:
                        _copy_file_chunked(remote_file, local_file)

                file_size = os.path.getsize(dst)

                if status_callback:
                    status_callback("Downloading 1/1 files...")

                logging.debug(f"File downloaded successfully: {file_size} bytes")

                return f"Downloaded {os.path.basename(remote_base_path)} ({file_size} bytes) from \\\\{server}\\{share}\\{remote_base_path}"

            else:
                total_files = 0
                total_bytes = 0

                if status_callback:
                    status_callback("Scanning remote directory...")

                for remote_root, dirs, files in smb_walk(remote_unc_path):
                    if remote_root == remote_unc_path:
                        rel_path = ""
                    else:
                        rel_path = remote_root[len(remote_unc_path):].lstrip("\\/")

                    if rel_path:
                        local_dir = os.path.join(dst, rel_path.replace("\\", os.sep))
                    else:
                        local_dir = dst
                    os.makedirs(local_dir, exist_ok=True)

                    for filename in files:
                        if not remote_root.endswith("\\"):
                            remote_file_path = remote_root + "\\" + filename
                        else:
                            remote_file_path = remote_root + filename

                        local_file_path = os.path.join(local_dir, filename)

                        logging.debug(f"Downloading {remote_file_path} to {local_file_path}...")

                        with smb_open(remote_file_path, mode="rb") as remote_file:
                            with open(local_file_path, "wb") as local_file:
                                _copy_file_chunked(remote_file, local_file)

                        file_size = os.path.getsize(local_file_path)
                        total_files += 1
                        total_bytes += file_size

                        if status_callback:
                            status_callback(f"Downloaded {total_files} file(s)...")

                logging.debug(f"Directory downloaded successfully: {total_files} files, {total_bytes} bytes")

                return f"Downloaded {total_files} file(s) ({total_bytes} bytes) from \\\\{server}\\{share}\\{remote_base_path}"
