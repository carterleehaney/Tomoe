import os
import logging
import socket
import random
import string
import paramiko

from tomoe.common import AuthenticationError, ConnectionError, check_port_open, build_auth_username, run_interruptible


logger = logging.getLogger(__name__)


def _create_ssh_client(target_ip, auth_username, password, verbose=False):
    """Create and return a connected paramiko SSHClient."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # If no password was supplied (sentinel: None), use standard SSH
    # key-based auth (agent + default key files in ~/.ssh/). An empty
    # string is still treated as an explicit (if lousy) password.
    use_key_auth = password is None

    auth_mode = "key-based (agent + ~/.ssh/)" if use_key_auth else "password"
    logging.debug("SSH auth mode: %s for %s@%s", auth_mode, auth_username, target_ip)

    try:
        client.connect(
            hostname=target_ip,
            port=22,
            username=auth_username,
            password=password,
            timeout=30,
            allow_agent=use_key_auth,
            look_for_keys=use_key_auth,
        )
    except paramiko.AuthenticationException as e:
        logging.debug("SSH authentication failed: %s", e)
        raise AuthenticationError(f"Authentication failed for {auth_username}@{target_ip}: {e}")
    except (paramiko.SSHException, socket.error, OSError) as e:
        logging.debug("SSH connection failed: %s", e)
        raise ConnectionError(f"Connection failed to {target_ip}: {e}")

    return client


def execute(host, username, password, domain="", script_path=None, command=None, script_args="", verbose=False, status_callback=None, target_os="windows", shutdown_event=None):
    """Execute a script or command on a remote host using SSH."""

    if shutdown_event is not None and shutdown_event.is_set():
        raise KeyboardInterrupt(f"Interrupted by user before executing on {host}")

    is_linux = target_os == "linux"

    # Perform a quick connectivity check before attempting SSH.
    # This prevents long timeout delays when the target is unreachable.
    if not check_port_open(host, 22, timeout=5):
        raise ConnectionError(f"Port 22 not reachable on {host}")

    # Construct the authentication username.
    auth_username = build_auth_username(username, domain, is_linux=is_linux)

    client = _create_ssh_client(host, auth_username, password, verbose)

    # SSH connected successfully - authentication has passed.
    if status_callback:
        status_callback("Authenticated, preparing command...")

    remote_script_path = None

    try:
        if script_path:
            # Upload the script to a temporary location via SFTP, then execute it.
            logging.debug("Reading local script: %s", script_path)

            # Generate a unique temporary filename on the remote host.
            rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

            if is_linux:
                # Determine script extension from the source file, default to .sh
                _, ext = os.path.splitext(script_path)
                script_ext = ext if ext else ".sh"
                remote_script_path = f"/tmp/tomoe_{rand_suffix}{script_ext}"
            else:
                remote_script_path = f"C:\\Windows\\Temp\\tomoe_{rand_suffix}.ps1"

            # Upload the script via SFTP.
            if status_callback:
                status_callback("Uploading script...")

            sftp = client.open_sftp()
            try:
                sftp.put(script_path, remote_script_path)
                logging.debug("Uploaded script to %s", remote_script_path)
            finally:
                sftp.close()

            # Build the execution command.
            if is_linux:
                cmd_args = f'bash "{remote_script_path}" {script_args}'
            else:
                cmd_args = f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{remote_script_path}" {script_args}'

        elif command:
            # For simple commands, invoke directly (Linux) or via PowerShell (Windows).
            logging.debug("Executing command: %s", command)

            if is_linux:
                cmd_args = command
            else:
                cmd_args = f'powershell.exe -NoProfile -NonInteractive -Command "{command}"'

        else:
            raise ValueError("Either --script or --command must be provided.")

        logging.debug("Executing on %s via SSH...", host)

        # Execute the command on the remote host.
        if status_callback:
            status_callback("Executing...")

        def _run_command():
            stdin, stdout, stderr = client.exec_command(cmd_args, timeout=300)
            # Read stdout and stderr.
            out = stdout.read().decode('utf-8', errors='replace').replace('\r', '').strip()
            err = stderr.read().decode('utf-8', errors='replace').replace('\r', '').strip()
            code = stdout.channel.recv_exit_status()
            return out, err, code

        # Run in an interruptible wrapper so Ctrl-C (shutdown_event) can abort a
        # long-running command mid-flight; the finally block below closes the
        # client, which unblocks the abandoned read.
        stdout_text, stderr_text, exit_code = run_interruptible(_run_command, shutdown_event, host)

        logging.info("Command executed, exit code: %d", exit_code)
        logging.debug("stdout: %d chars, stderr: %d chars", len(stdout_text), len(stderr_text))

        # Clean up the temporary script file if one was uploaded.
        if remote_script_path:
            try:
                sftp = client.open_sftp()
                try:
                    sftp.remove(remote_script_path)
                    logging.debug("Cleaned up remote script: %s", remote_script_path)
                finally:
                    sftp.close()
            except Exception:
                # Best-effort cleanup; don't fail the operation if cleanup fails.
                logging.debug("Failed to clean up remote script: %s", remote_script_path)

        # Validate command execution and provide meaningful error messages.
        if stderr_text and ("is not recognized" in stderr_text or "cannot be loaded" in stderr_text):
            logging.debug("Command execution failed: %s", stderr_text)
            return f"ERROR: {stderr_text}"

        if not stdout_text and not stderr_text and exit_code != 0:
            error_msg = f"Command failed with exit code {exit_code}"
            logging.debug("%s", error_msg)
            return error_msg

        # Return combined output: stdout first, then stderr.
        if stdout_text and stderr_text:
            return stdout_text + "\n" + stderr_text
        if stdout_text:
            return stdout_text
        if stderr_text:
            return stderr_text
        return f"Command executed with exit code {exit_code}"

    except (AuthenticationError, ConnectionError):
        raise
    except Exception as e:
        error_str = str(e).lower()

        # Check if the exception indicates an authentication failure.
        if any(auth_err in error_str for auth_err in [
            "authentication", "auth", "login failed",
            "invalid credentials", "access denied", "permission denied",
            "unauthorized", "rejected"
        ]):
            logging.debug("SSH authentication failed: %s", e)
            raise AuthenticationError(f"Authentication failed for {auth_username}@{host}: {e}")

        # Check if the exception indicates a connection failure.
        if any(conn_err in error_str for conn_err in [
            "connection", "timeout", "refused", "unreachable", "reset", "eof"
        ]):
            logging.debug("SSH connection failed: %s", e)
            raise ConnectionError(f"Connection failed to {host}: {e}")

        logging.debug("SSH execution failed: %s", e)
        raise
    finally:
        client.close()


def _sftp_isdir(sftp, path):
    """Check if a remote path is a directory via SFTP stat."""
    import stat
    try:
        return stat.S_ISDIR(sftp.stat(path).st_mode)
    except IOError:
        return False


def _sftp_walk(sftp, remote_dir, sep="/"):
    """Recursively walk a remote directory tree via SFTP, similar to os.walk."""
    import stat as stat_module
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


def download(host, username, password, domain="", source="", dest="", verbose=False, status_callback=None, target_os="windows"):
    """Download a file or directory from a remote host using SSH/SFTP."""

    is_linux = target_os == "linux"
    sep = "/" if is_linux else "\\"

    # Perform a quick connectivity check before attempting SSH.
    if not check_port_open(host, 22, timeout=5):
        raise ConnectionError(f"Port 22 not reachable on {host}")

    # Construct the authentication username.
    auth_username = build_auth_username(username, domain, is_linux=is_linux)

    client = _create_ssh_client(host, auth_username, password, verbose)

    try:
        sftp = client.open_sftp()

        try:
            # Check if the remote source exists and determine if it's a file or directory.
            if status_callback:
                status_callback("Checking remote path...")

            try:
                remote_stat = sftp.stat(source)
            except IOError:
                raise FileNotFoundError(f"Remote path not found: {source}")

            import stat as stat_module
            is_directory = stat_module.S_ISDIR(remote_stat.st_mode)

            if not is_directory:
                # Single file download.
                if status_callback:
                    status_callback("Downloading 0/1 files...")

                # If dest is an existing directory, append the source filename.
                if os.path.isdir(dest):
                    if is_linux:
                        filename = source.rsplit('/', 1)[-1]
                    else:
                        filename = source.rsplit('\\', 1)[-1]
                    dest = os.path.join(dest, filename)

                # Ensure local destination directory exists.
                dest_dir = os.path.dirname(dest)
                if dest_dir:
                    os.makedirs(dest_dir, exist_ok=True)

                logging.debug("Downloading %s:%s to %s...", host, source, dest)

                sftp.get(source, dest)

                file_size = os.path.getsize(dest)

                if status_callback:
                    status_callback("Downloading 1/1 files...")

                logging.info("File downloaded successfully: %d bytes", file_size)

                if is_linux:
                    filename = source.rsplit('/', 1)[-1]
                else:
                    filename = source.rsplit('\\', 1)[-1]

                return f"Downloaded {filename} ({file_size} bytes) from {host}:{source}"

            else:
                # Directory download - recursive.
                if status_callback:
                    status_callback("Scanning remote directory...")

                total_files = 0
                total_bytes = 0

                # Ensure local destination directory exists.
                os.makedirs(dest, exist_ok=True)

                source_stripped = source.rstrip(sep)

                def _strip_windows_drive(rel_path, path_sep):
                    """Strip leading Windows drive from relative path."""
                    if not rel_path or not path_sep:
                        return rel_path
                    # Match single letter + colon at start (e.g. C: or C:\ or C:/)
                    if len(rel_path) >= 2 and rel_path[0].isalpha() and rel_path[1] == ':':
                        rel_path = rel_path[2:].lstrip(path_sep)
                    return rel_path

                for remote_root, dirs, files in _sftp_walk(sftp, source_stripped, sep):
                    # Calculate relative path from source.
                    if remote_root == source_stripped:
                        rel_path = ""
                    else:
                        rel_path = remote_root[len(source_stripped):].lstrip(sep)
                    # For Windows remotes, don't create a literal "C:" directory locally.
                    if not is_linux:
                        rel_path = _strip_windows_drive(rel_path, sep)
                    # Avoid leading slash so join() doesn't produce an absolute path (e.g. server uses C:/).
                    rel_path = rel_path.lstrip(sep).lstrip("/")

                    # Create local directory.
                    if rel_path:
                        local_dir = os.path.join(dest, rel_path.replace(sep, os.sep))
                    else:
                        local_dir = dest
                    os.makedirs(local_dir, exist_ok=True)

                    # Download each file.
                    for filename in files:
                        remote_file_path = remote_root.rstrip(sep) + sep + filename
                        local_file_path = os.path.join(local_dir, filename)

                        logging.debug("Downloading %s:%s to %s...", host, remote_file_path, local_file_path)

                        sftp.get(remote_file_path, local_file_path)

                        file_size = os.path.getsize(local_file_path)
                        total_files += 1
                        total_bytes += file_size

                        if status_callback:
                            status_callback(f"Downloaded {total_files} file(s)...")

                logging.info("Directory downloaded successfully: %d files, %d bytes", total_files, total_bytes)

                return f"Downloaded {total_files} file(s) ({total_bytes} bytes) from {host}:{source}"

        finally:
            sftp.close()

    except (AuthenticationError, ConnectionError, FileNotFoundError):
        raise
    except Exception as e:
        error_str = str(e).lower()

        # Check if this is a file/path access error.
        if "no such file" in error_str or "permission denied" in error_str:
            logging.debug("SSH download failed: %s", e)
            raise

        # Check if the exception indicates an authentication failure.
        if any(auth_err in error_str for auth_err in [
            "authentication", "auth failed", "login failed",
            "invalid credentials", "access denied", "unauthorized", "rejected"
        ]):
            logging.debug("SSH authentication failed: %s", e)
            raise AuthenticationError(f"Authentication failed for {auth_username}@{host}: {e}")

        # Check if the exception indicates a connection failure.
        if any(conn_err in error_str for conn_err in [
            "connection", "timeout", "refused", "unreachable", "reset", "eof"
        ]):
            logging.debug("SSH connection failed: %s", e)
            raise ConnectionError(f"Connection failed to {host}: {e}")

        logging.debug("SSH download failed: %s", e)
        raise
    finally:
        client.close()


def upload(host, username, password, domain="", source="", dest="", verbose=False, status_callback=None, target_os="windows"):
    """Copy a local file or directory to a remote host using SSH/SFTP."""

    is_linux = target_os == "linux"
    sep = "/" if is_linux else "\\"

    # Perform a quick connectivity check before attempting SSH.
    if not check_port_open(host, 22, timeout=5):
        raise ConnectionError(f"Port 22 not reachable on {host}")

    # Validate source exists.
    if not os.path.exists(source):
        raise FileNotFoundError(f"Source not found: {source}")

    # Construct the authentication username.
    auth_username = build_auth_username(username, domain, is_linux=is_linux)

    client = _create_ssh_client(host, auth_username, password, verbose)

    try:
        sftp = client.open_sftp()

        try:
            if os.path.isfile(source):
                # Single file copy.
                if status_callback:
                    status_callback("Copying 0/1 files...")
                file_size = os.path.getsize(source)

                if is_linux:
                    # Linux path handling: normalize to forward slashes.
                    dest_normalized = dest.replace('\\', '/')

                    # If dest is a directory path (ends with /), append the source filename.
                    if dest_normalized.endswith('/') or dest_normalized == "":
                        remote_path = dest_normalized + os.path.basename(source)
                    else:
                        remote_path = dest_normalized
                else:
                    # Windows path handling: normalize to backslashes.
                    dest_normalized = dest.replace('/', '\\').lstrip('\\')

                    # Extract drive letter and path (e.g., "C:\path" -> drive="C:", path="path").
                    if len(dest_normalized) >= 2 and dest_normalized[1] == ':':
                        drive = dest_normalized[:2]  # "C:"
                        path_after_drive = dest_normalized[3:] if len(dest_normalized) > 3 else ""

                        if path_after_drive:
                            remote_path = dest_normalized
                        else:
                            remote_path = drive + '\\' + os.path.basename(source)
                    else:
                        remote_path = dest_normalized if dest_normalized else os.path.basename(source)

                logging.debug("Uploading %s (%d bytes) to %s:%s...", source, file_size, host, remote_path)

                sftp.put(source, remote_path)

                if status_callback:
                    status_callback("Copying 1/1 files...")

                logging.info("File copied successfully: %d bytes", file_size)

                return f"Copied {os.path.basename(source)} ({file_size} bytes) to {host}:{remote_path}"

            elif os.path.isdir(source):
                # Directory copy - recursive.
                if status_callback:
                    status_callback("Scanning directory...")

                total_files = 0
                total_bytes = 0

                # Normalize destination path based on target OS.
                if is_linux:
                    dest_normalized = dest.replace('\\', '/').rstrip('/')
                else:
                    dest_normalized = dest.replace('/', '\\').rstrip('\\')

                # Collect all directories to create and files to copy.
                dirs_to_create = []
                files_to_copy = []

                for root, dirs, files in os.walk(source):
                    rel_root = os.path.relpath(root, source)
                    if rel_root == ".":
                        rel_root = ""

                    if rel_root:
                        rel_root_normalized = rel_root.replace('\\', '/') if is_linux else rel_root.replace('/', '\\')
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

                # Create all directories first.
                if status_callback:
                    status_callback(f"Creating directories, 0/{len(files_to_copy)} files copied...")

                for remote_dir in dirs_to_create:
                    try:
                        sftp.mkdir(remote_dir)
                        logging.debug("Created directory: %s", remote_dir)
                    except IOError:
                        # Directory may already exist, or we need to create parent dirs.
                        # Fall back to creating nested directories via SFTP to avoid shell injection.
                        path_sep = '/' if is_linux else '\\'
                        parts = [p for p in remote_dir.split(path_sep) if p]
                        # Preserve leading separator for absolute paths.
                        current = path_sep if remote_dir.startswith(path_sep) else ""
                        for part in parts:
                            if current and not current.endswith(path_sep):
                                current += path_sep
                            current += part
                            try:
                                # Check if the directory already exists.
                                sftp.stat(current)
                            except IOError:
                                try:
                                    sftp.mkdir(current)
                                    logging.debug("Created directory (nested): %s", current)
                                except IOError:
                                    # Directory creation may fail if it was created concurrently; ignore.
                                    logging.debug("Failed to create nested directory: %s", current)

                # Copy each file.
                total_file_count = len(files_to_copy)
                if status_callback:
                    status_callback(f"Copying 0/{total_file_count} files...")

                for local_file_path, remote_file_path in files_to_copy:
                    file_size = os.path.getsize(local_file_path)

                    logging.debug("Uploading %s (%d bytes) to %s:%s...", local_file_path, file_size, host, remote_file_path)

                    sftp.put(local_file_path, remote_file_path)

                    total_files += 1
                    total_bytes += file_size

                    if status_callback:
                        status_callback(f"Copying {total_files}/{total_file_count} files...")

                logging.info("Directory copied successfully: %d files, %d bytes", total_files, total_bytes)

                return f"Copied {total_files} file(s) ({total_bytes} bytes) to {host}:{dest_normalized}"

            else:
                raise ValueError(f"Source '{source}' exists but is neither a regular file nor a directory")

        finally:
            sftp.close()

    except (AuthenticationError, ConnectionError):
        raise
    except Exception as e:
        error_str = str(e).lower()

        # Check if this is a file/path access error (not an auth error); exclude SFTP-related errors.
        if ("no such file" in error_str or "permission denied" in error_str) and "sftp" not in error_str:
            logging.debug("SSH copy failed: %s", e)
            raise

        # Check if the exception indicates an authentication failure.
        if any(auth_err in error_str for auth_err in [
            "authentication", "auth failed", "login failed",
            "invalid credentials", "access denied", "unauthorized", "rejected"
        ]):
            logging.debug("SSH authentication failed: %s", e)
            raise AuthenticationError(f"Authentication failed for {auth_username}@{host}: {e}")

        # Check if the exception indicates a connection failure.
        if any(conn_err in error_str for conn_err in [
            "connection", "timeout", "refused", "unreachable", "reset", "eof"
        ]):
            logging.debug("SSH connection failed: %s", e)
            raise ConnectionError(f"Connection failed to {host}: {e}")

        logging.debug("SSH copy failed: %s", e)
        raise
    finally:
        client.close()
