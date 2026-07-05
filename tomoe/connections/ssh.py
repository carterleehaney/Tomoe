"""SSH connection (paramiko), migrated from the old ``protocols/ssh.py``.

Wire-level logic (paramiko client setup, SFTP walk, error-string
classification) is carried over faithfully; only the plumbing around it
(host/credential/options bookkeeping, port configurability) changed.
"""

import logging
import os
import random
import socket
import stat as stat_module
import string
from threading import Event
from typing import Callable, Optional

import paramiko

from tomoe.common import AuthenticationError, ConnectionError, run_interruptible
from tomoe.connections.base import Connection, ExecResult

logger = logging.getLogger(__name__)


def _sftp_walk(sftp, remote_dir, sep="/"):
    """Recursively walk a remote directory tree via SFTP, similar to os.walk."""
    try:
        entries = sftp.listdir_attr(remote_dir)
    except IOError:
        return

    dirs = []
    files = []
    for entry in entries:
        if stat_module.S_ISDIR(entry.st_mode):
            dirs.append(entry.filename)
        else:
            files.append(entry.filename)

    yield remote_dir, dirs, files

    for d in dirs:
        child_path = remote_dir.rstrip(sep) + sep + d
        yield from _sftp_walk(sftp, child_path, sep)


def _strip_windows_drive(rel_path, path_sep):
    """Strip leading Windows drive from relative path."""
    if not rel_path or not path_sep:
        return rel_path
    if len(rel_path) >= 2 and rel_path[0].isalpha() and rel_path[1] == ":":
        rel_path = rel_path[2:].lstrip(path_sep)
    return rel_path


class SSHConnection(Connection):
    DEFAULT_PORT = 22
    PROTOCOL = "ssh"

    def __init__(self, host, credential, options):
        super().__init__(host, credential, options)
        self.client: Optional[paramiko.SSHClient] = None

    @property
    def is_linux(self) -> bool:
        return self.options.target_os == "linux"

    def connect(self) -> None:
        """Create and authenticate a paramiko SSHClient."""
        auth_username = self.credential.auth_name(is_linux=self.is_linux)
        password = self.credential.password

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # If no password was supplied (sentinel: None), use standard SSH
        # key-based auth (agent + default key files in ~/.ssh/). An empty
        # string is still treated as an explicit (if lousy) password.
        use_key_auth = password is None

        auth_mode = "key-based (agent + ~/.ssh/)" if use_key_auth else "password"
        logging.debug("SSH auth mode: %s for %s@%s", auth_mode, auth_username, self.host)

        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=auth_username,
                password=password,
                timeout=30,
                allow_agent=use_key_auth,
                look_for_keys=use_key_auth,
            )
        except paramiko.AuthenticationException as e:
            logging.debug("SSH authentication failed: %s", e)
            raise AuthenticationError(f"Authentication failed for {auth_username}@{self.host}: {e}")
        except (paramiko.SSHException, socket.error, OSError) as e:
            logging.debug("SSH connection failed: %s", e)
            raise ConnectionError(f"Connection failed to {self.host}: {e}")

        self.client = client

    def execute(
        self,
        command: Optional[str] = None,
        *,
        script_path: Optional[str] = None,
        script_args: str = "",
        status_callback: Optional[Callable[[str], None]] = None,
        shutdown_event: Optional[Event] = None,
    ) -> ExecResult:
        """Execute a script or command on a remote host using SSH."""
        if shutdown_event is not None and shutdown_event.is_set():
            raise KeyboardInterrupt(f"Interrupted by user before executing on {self.host}")

        if not self.check_reachable(timeout=5):
            raise ConnectionError(f"Port {self.port} not reachable on {self.host}")

        auth_username = self.credential.auth_name(is_linux=self.is_linux)
        is_linux = self.is_linux

        self.connect()
        client = self.client

        if status_callback:
            status_callback("Authenticated, preparing command...")

        remote_script_path = None

        try:
            if script_path:
                logging.debug("Reading local script: %s", script_path)

                rand_suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))

                if is_linux:
                    _, ext = os.path.splitext(script_path)
                    script_ext = ext if ext else ".sh"
                    remote_script_path = f"/tmp/tomoe_{rand_suffix}{script_ext}"
                else:
                    remote_script_path = f"C:\\Windows\\Temp\\tomoe_{rand_suffix}.ps1"

                if status_callback:
                    status_callback("Uploading script...")

                sftp = client.open_sftp()
                try:
                    sftp.put(script_path, remote_script_path)
                    logging.debug("Uploaded script to %s", remote_script_path)
                finally:
                    sftp.close()

                if is_linux:
                    cmd_args = f'bash "{remote_script_path}" {script_args}'
                else:
                    cmd_args = f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{remote_script_path}" {script_args}'

            elif command:
                logging.debug("Executing command: %s", command)

                if is_linux:
                    cmd_args = command
                else:
                    cmd_args = f'powershell.exe -NoProfile -NonInteractive -Command "{command}"'

            else:
                raise ValueError("Either --script or --command must be provided.")

            logging.debug("Executing on %s via SSH...", self.host)

            if status_callback:
                status_callback("Executing...")

            def _run_command():
                stdin, stdout, stderr = client.exec_command(cmd_args, timeout=300)
                out = stdout.read().decode("utf-8", errors="replace").replace("\r", "").strip()
                err = stderr.read().decode("utf-8", errors="replace").replace("\r", "").strip()
                code = stdout.channel.recv_exit_status()
                return out, err, code

            stdout_text, stderr_text, exit_code = run_interruptible(_run_command, shutdown_event, self.host)

            logging.info("Command executed, exit code: %d", exit_code)
            logging.debug("stdout: %d chars, stderr: %d chars", len(stdout_text), len(stderr_text))

            if remote_script_path:
                try:
                    sftp = client.open_sftp()
                    try:
                        sftp.remove(remote_script_path)
                        logging.debug("Cleaned up remote script: %s", remote_script_path)
                    finally:
                        sftp.close()
                except Exception:
                    logging.debug("Failed to clean up remote script: %s", remote_script_path)

            if stderr_text and ("is not recognized" in stderr_text or "cannot be loaded" in stderr_text):
                logging.debug("Command execution failed: %s", stderr_text)
                return ExecResult(host=self.host, stdout=f"ERROR: {stderr_text}", return_code=exit_code)

            if not stdout_text and not stderr_text and exit_code != 0:
                error_msg = f"Command failed with exit code {exit_code}"
                logging.debug("%s", error_msg)
                return ExecResult(host=self.host, stdout=error_msg, return_code=exit_code)

            if stdout_text and stderr_text:
                combined = stdout_text + "\n" + stderr_text
            elif stdout_text:
                combined = stdout_text
            elif stderr_text:
                combined = stderr_text
            else:
                combined = f"Command executed with exit code {exit_code}"

            return ExecResult(host=self.host, stdout=combined, return_code=exit_code)

        except (AuthenticationError, ConnectionError):
            raise
        except Exception as e:
            error_str = str(e).lower()

            if any(auth_err in error_str for auth_err in [
                "authentication", "auth", "login failed",
                "invalid credentials", "access denied", "permission denied",
                "unauthorized", "rejected"
            ]):
                logging.debug("SSH authentication failed: %s", e)
                raise AuthenticationError(f"Authentication failed for {auth_username}@{self.host}: {e}")

            if any(conn_err in error_str for conn_err in [
                "connection", "timeout", "refused", "unreachable", "reset", "eof"
            ]):
                logging.debug("SSH connection failed: %s", e)
                raise ConnectionError(f"Connection failed to {self.host}: {e}")

            logging.debug("SSH execution failed: %s", e)
            raise
        finally:
            client.close()

    def put_file(
        self,
        src: str,
        dst: str,
        *,
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Copy a local file or directory to a remote host using SSH/SFTP."""
        is_linux = self.is_linux
        sep = "/" if is_linux else "\\"

        if not self.check_reachable(timeout=5):
            raise ConnectionError(f"Port {self.port} not reachable on {self.host}")

        if not os.path.exists(src):
            raise FileNotFoundError(f"Source not found: {src}")

        auth_username = self.credential.auth_name(is_linux=is_linux)

        self.connect()
        client = self.client

        try:
            sftp = client.open_sftp()

            try:
                if os.path.isfile(src):
                    if status_callback:
                        status_callback("Copying 0/1 files...")
                    file_size = os.path.getsize(src)

                    if is_linux:
                        dest_normalized = dst.replace("\\", "/")
                        if dest_normalized.endswith("/") or dest_normalized == "":
                            remote_path = dest_normalized + os.path.basename(src)
                        else:
                            remote_path = dest_normalized
                    else:
                        dest_normalized = dst.replace("/", "\\").lstrip("\\")
                        if len(dest_normalized) >= 2 and dest_normalized[1] == ":":
                            drive = dest_normalized[:2]
                            path_after_drive = dest_normalized[3:] if len(dest_normalized) > 3 else ""
                            if path_after_drive:
                                remote_path = dest_normalized
                            else:
                                remote_path = drive + "\\" + os.path.basename(src)
                        else:
                            remote_path = dest_normalized if dest_normalized else os.path.basename(src)

                    logging.debug("Uploading %s (%d bytes) to %s:%s...", src, file_size, self.host, remote_path)

                    sftp.put(src, remote_path)

                    if status_callback:
                        status_callback("Copying 1/1 files...")

                    logging.info("File copied successfully: %d bytes", file_size)

                    return f"Copied {os.path.basename(src)} ({file_size} bytes) to {self.host}:{remote_path}"

                elif os.path.isdir(src):
                    if status_callback:
                        status_callback("Scanning directory...")

                    total_files = 0
                    total_bytes = 0

                    if is_linux:
                        dest_normalized = dst.replace("\\", "/").rstrip("/")
                    else:
                        dest_normalized = dst.replace("/", "\\").rstrip("\\")

                    dirs_to_create = []
                    files_to_copy = []

                    for root, dirs, files in os.walk(src):
                        rel_root = os.path.relpath(root, src)
                        if rel_root == ".":
                            rel_root = ""

                        if rel_root:
                            rel_root_normalized = rel_root.replace("\\", "/") if is_linux else rel_root.replace("/", "\\")
                            remote_dir = dest_normalized + sep + rel_root_normalized
                        else:
                            remote_dir = dest_normalized

                        if remote_dir and remote_dir not in dirs_to_create:
                            dirs_to_create.append(remote_dir)

                        for filename in files:
                            local_file_path = os.path.join(root, filename)
                            if remote_dir:
                                remote_file_path = remote_dir + sep + filename
                            else:
                                remote_file_path = filename
                            files_to_copy.append((local_file_path, remote_file_path))

                    if status_callback:
                        status_callback(f"Creating directories, 0/{len(files_to_copy)} files copied...")

                    for remote_dir in dirs_to_create:
                        try:
                            sftp.mkdir(remote_dir)
                            logging.debug("Created directory: %s", remote_dir)
                        except IOError:
                            path_sep = "/" if is_linux else "\\"
                            parts = [p for p in remote_dir.split(path_sep) if p]
                            current = path_sep if remote_dir.startswith(path_sep) else ""
                            for part in parts:
                                if current and not current.endswith(path_sep):
                                    current += path_sep
                                current += part
                                try:
                                    sftp.stat(current)
                                except IOError:
                                    try:
                                        sftp.mkdir(current)
                                        logging.debug("Created directory (nested): %s", current)
                                    except IOError:
                                        logging.debug("Failed to create nested directory: %s", current)

                    total_file_count = len(files_to_copy)
                    if status_callback:
                        status_callback(f"Copying 0/{total_file_count} files...")

                    for local_file_path, remote_file_path in files_to_copy:
                        file_size = os.path.getsize(local_file_path)

                        logging.debug("Uploading %s (%d bytes) to %s:%s...", local_file_path, file_size, self.host, remote_file_path)

                        sftp.put(local_file_path, remote_file_path)

                        total_files += 1
                        total_bytes += file_size

                        if status_callback:
                            status_callback(f"Copying {total_files}/{total_file_count} files...")

                    logging.info("Directory copied successfully: %d files, %d bytes", total_files, total_bytes)

                    return f"Copied {total_files} file(s) ({total_bytes} bytes) to {self.host}:{dest_normalized}"

                else:
                    raise ValueError(f"Source '{src}' exists but is neither a regular file nor a directory")

            finally:
                sftp.close()

        except (AuthenticationError, ConnectionError):
            raise
        except Exception as e:
            error_str = str(e).lower()

            if ("no such file" in error_str or "permission denied" in error_str) and "sftp" not in error_str:
                logging.debug("SSH copy failed: %s", e)
                raise

            if any(auth_err in error_str for auth_err in [
                "authentication", "auth failed", "login failed",
                "invalid credentials", "access denied", "unauthorized", "rejected"
            ]):
                logging.debug("SSH authentication failed: %s", e)
                raise AuthenticationError(f"Authentication failed for {auth_username}@{self.host}: {e}")

            if any(conn_err in error_str for conn_err in [
                "connection", "timeout", "refused", "unreachable", "reset", "eof"
            ]):
                logging.debug("SSH connection failed: %s", e)
                raise ConnectionError(f"Connection failed to {self.host}: {e}")

            logging.debug("SSH copy failed: %s", e)
            raise
        finally:
            client.close()

    def get_file(
        self,
        src: str,
        dst: str,
        *,
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Download a file or directory from a remote host using SSH/SFTP."""
        is_linux = self.is_linux
        sep = "/" if is_linux else "\\"

        if not self.check_reachable(timeout=5):
            raise ConnectionError(f"Port {self.port} not reachable on {self.host}")

        auth_username = self.credential.auth_name(is_linux=is_linux)

        self.connect()
        client = self.client

        try:
            sftp = client.open_sftp()

            try:
                if status_callback:
                    status_callback("Checking remote path...")

                try:
                    remote_stat = sftp.stat(src)
                except IOError:
                    raise FileNotFoundError(f"Remote path not found: {src}")

                is_directory = stat_module.S_ISDIR(remote_stat.st_mode)

                if not is_directory:
                    if status_callback:
                        status_callback("Downloading 0/1 files...")

                    if os.path.isdir(dst):
                        if is_linux:
                            filename = src.rsplit("/", 1)[-1]
                        else:
                            filename = src.rsplit("\\", 1)[-1]
                        dst = os.path.join(dst, filename)

                    dest_dir = os.path.dirname(dst)
                    if dest_dir:
                        os.makedirs(dest_dir, exist_ok=True)

                    logging.debug("Downloading %s:%s to %s...", self.host, src, dst)

                    sftp.get(src, dst)

                    file_size = os.path.getsize(dst)

                    if status_callback:
                        status_callback("Downloading 1/1 files...")

                    logging.info("File downloaded successfully: %d bytes", file_size)

                    if is_linux:
                        filename = src.rsplit("/", 1)[-1]
                    else:
                        filename = src.rsplit("\\", 1)[-1]

                    return f"Downloaded {filename} ({file_size} bytes) from {self.host}:{src}"

                else:
                    if status_callback:
                        status_callback("Scanning remote directory...")

                    total_files = 0
                    total_bytes = 0

                    os.makedirs(dst, exist_ok=True)

                    source_stripped = src.rstrip(sep)

                    for remote_root, dirs, files in _sftp_walk(sftp, source_stripped, sep):
                        if remote_root == source_stripped:
                            rel_path = ""
                        else:
                            rel_path = remote_root[len(source_stripped):].lstrip(sep)
                        if not is_linux:
                            rel_path = _strip_windows_drive(rel_path, sep)
                        rel_path = rel_path.lstrip(sep).lstrip("/")

                        if rel_path:
                            local_dir = os.path.join(dst, rel_path.replace(sep, os.sep))
                        else:
                            local_dir = dst
                        os.makedirs(local_dir, exist_ok=True)

                        for filename in files:
                            remote_file_path = remote_root.rstrip(sep) + sep + filename
                            local_file_path = os.path.join(local_dir, filename)

                            logging.debug("Downloading %s:%s to %s...", self.host, remote_file_path, local_file_path)

                            sftp.get(remote_file_path, local_file_path)

                            file_size = os.path.getsize(local_file_path)
                            total_files += 1
                            total_bytes += file_size

                            if status_callback:
                                status_callback(f"Downloaded {total_files} file(s)...")

                    logging.info("Directory downloaded successfully: %d files, %d bytes", total_files, total_bytes)

                    return f"Downloaded {total_files} file(s) ({total_bytes} bytes) from {self.host}:{src}"

            finally:
                sftp.close()

        except (AuthenticationError, ConnectionError, FileNotFoundError):
            raise
        except Exception as e:
            error_str = str(e).lower()

            if "no such file" in error_str or "permission denied" in error_str:
                logging.debug("SSH download failed: %s", e)
                raise

            if any(auth_err in error_str for auth_err in [
                "authentication", "auth failed", "login failed",
                "invalid credentials", "access denied", "unauthorized", "rejected"
            ]):
                logging.debug("SSH authentication failed: %s", e)
                raise AuthenticationError(f"Authentication failed for {auth_username}@{self.host}: {e}")

            if any(conn_err in error_str for conn_err in [
                "connection", "timeout", "refused", "unreachable", "reset", "eof"
            ]):
                logging.debug("SSH connection failed: %s", e)
                raise ConnectionError(f"Connection failed to {self.host}: {e}")

            logging.debug("SSH download failed: %s", e)
            raise
        finally:
            client.close()
