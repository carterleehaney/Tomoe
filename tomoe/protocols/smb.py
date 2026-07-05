import os
import logging
import time
from contextlib import contextmanager
from threading import Thread, Lock, Event
import random
import string
import socket
from pypsexec.client import Client
import smbclient
from smbclient import open_file as smb_open, listdir as smb_listdir, walk as smb_walk, remove as smb_remove
from smbclient.path import exists as smb_exists, isfile as smb_isfile, isdir as smb_isdir
import smbclient.shutil as smb_shutil
import warnings

from tomoe.common import AuthenticationError, ConnectionError, check_port_open, build_auth_username

# Suppress cryptography deprecation warnings from dependencies
warnings.filterwarnings("ignore", category=DeprecationWarning, module=".*crypto.*")
warnings.filterwarnings("ignore", message=".*ARC4.*")


# Constants for SMB operations
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1MB chunks for file transfers
DEFAULT_CONNECTION_TIMEOUT = 30  # seconds


def _make_unc_path(server, share, path):
    """Create a UNC path for smbclient operations."""
    if path:
        # Normalize path separators
        path = path.replace('/', '\\')
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


def execute(host, username, password, domain="", script_path=None, command=None, script_args="", verbose=False, status_callback=None, shell_type="powershell", encrypt=True, shutdown_event=None):
    """Execute a script or command on a remote Windows host using SMB/psexec."""

    # Extract domain from username if in DOMAIN\username format
    if '\\' in username:
        domain, username = username.split('\\', 1)

    # Suppress pypsexec logging to avoid artifacts in output
    pypsexec_logger = logging.getLogger('pypsexec')
    if not verbose:
        pypsexec_logger.setLevel(logging.CRITICAL + 1)  # Effectively disable
    else:
        pypsexec_logger.setLevel(logging.INFO)

    # Perform a quick connectivity check before attempting SMB.
    # This prevents long timeout delays when the target is unreachable.
    if not check_port_open(host, 445, timeout=5):
        raise ConnectionError(f"Port 445 not reachable on {host}")

    # Construct the authentication username.
    auth_username = build_auth_username(username, domain)

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
                    arguments=arguments
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
            execution_result["rc"]
        )

    try:
        # Create a pypsexec Client for remote execution
        # The Client class handles service installation, execution, and cleanup
        client = Client(
            host,
            username=auth_username,
            password=password,
            encrypt=encrypt
        )

        # Connect to the remote host
        logging.debug(f"Connecting to {host} as {auth_username}...")

        client.connect()

        # Create the remote service
        if status_callback:
            status_callback("Authenticated, preparing command...")

        logging.debug(f"Creating remote service...")

        client.create_service()

        # Build the command based on shell type
        if script_path:
            # Upload the script to the remote machine via SMB (matching old-smb.py behavior)
            logging.debug(f"Uploading script: {script_path}")

            script_name = os.path.basename(script_path)

            # Register SMB session for file upload
            full_username = build_auth_username(username, domain)

            smbclient.register_session(
                host,
                username=full_username,
                password=password,
                port=445,
                encrypt=encrypt,
                connection_timeout=DEFAULT_CONNECTION_TIMEOUT
            )

            # Try to upload to shares with fallback: ADMIN$ first, then C$\Windows\Temp
            share = None
            remote_path = None

            # Try ADMIN$ first (requires admin privileges)
            try:
                admin_unc_path = _make_unc_path(host, 'ADMIN$', script_name)
                with open(script_path, 'rb') as local_file:
                    with smb_open(admin_unc_path, mode='wb') as remote_file:
                        _copy_file_chunked(local_file, remote_file)
                share = 'ADMIN$'
                remote_path = script_name
                logging.debug(f"Script uploaded to \\\\{host}\\ADMIN$\\{script_name}")
            except Exception as e:
                logging.debug(f"ADMIN$ upload failed: {e}, trying C$\\Windows\\Temp...")

                # Fallback to C$\Windows\Temp
                try:
                    temp_path = f"Windows\\Temp\\{script_name}"
                    temp_unc_path = _make_unc_path(host, 'C$', temp_path)
                    with open(script_path, 'rb') as local_file:
                        with smb_open(temp_unc_path, mode='wb') as remote_file:
                            _copy_file_chunked(local_file, remote_file)
                    share = 'C$'
                    remote_path = temp_path
                    logging.debug(f"Script uploaded to \\\\{host}\\C$\\{temp_path}")
                except Exception as e2:
                    raise Exception(f"Failed to upload script to any share: ADMIN$ and C$ both failed: {e2}")

            # Execute directly from SMB share using UNC path (like old-smb.py)
            if share == 'ADMIN$':
                unc_path = f"\\\\{host}\\ADMIN$\\{script_name}"
            else:
                unc_path = f"C:\\Windows\\Temp\\{script_name}"

            # Build command based on shell type
            if shell_type.lower() == "cmd":
                # For CMD, execute batch file directly
                script_ext = os.path.splitext(script_name)[1].lower()
                if script_ext not in ['.bat', '.cmd']:
                    raise ValueError(f"CMD shell requires .bat or .cmd files, got: {script_ext}")

                executable = "cmd.exe"
                if script_args:
                    arguments = f'/c "{unc_path}" {script_args}'
                else:
                    arguments = f'/c "{unc_path}"'
            else:
                # For PowerShell (default) - invoke the script via PowerShell, wrapped by cmd.exe
                # to ensure the process terminates cleanly using an explicit exit code.
                script_ext = os.path.splitext(script_name)[1].lower()
                if script_ext != '.ps1':
                    raise ValueError(f"PowerShell shell requires .ps1 files, got: {script_ext}")

                if script_args:
                    ps_command = f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"& '{unc_path}' {script_args}; [System.Environment]::Exit($LASTEXITCODE)\""
                else:
                    ps_command = f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"& '{unc_path}'; [System.Environment]::Exit($LASTEXITCODE)\""

                executable = "cmd.exe"
                arguments = f"/c {ps_command} < NUL 2>&1"

        elif command:
            # For simple commands
            logging.debug(f"Executing command: {command}")

            if shell_type.lower() == "cmd":
                # Execute CMD command directly
                executable = "cmd.exe"
                arguments = f'/c {command}'
            else:
                # Execute PowerShell command with cmd.exe wrapper and explicit exit for proper cleanup
                ps_command = f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command}; [System.Environment]::Exit($LASTEXITCODE)\""
                executable = "cmd.exe"
                arguments = f"/c {ps_command} < NUL 2>&1"
        else:
            raise ValueError("Either script_path or command must be provided.")

        logging.debug(f"Executing on {host}...")

        if status_callback:
            status_callback("Executing...")

        # Execute the command and capture output
        stdout, stderr, rc = run_remote_command(executable, arguments)

        # Decode initial output to check for path errors
        temp_stdout = stdout.decode('utf-8', errors='replace') if stdout else ""

        # cmd.exe error for missing executable usually goes to stderr (redirected to stdout by 2>&1)
        if (rc != 0 or "The system cannot find the path specified" in temp_stdout or "' is not recognized" in temp_stdout) and "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" in arguments:
            logging.debug(f"Full path failed. Retrying with short 'powershell.exe' path...")

            # Reconstruct command with short 'powershell.exe' instead of full path
            arguments = arguments.replace(
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "powershell.exe"
            )

            logging.debug(f"Retry arguments: {arguments}")

            # Retry execution
            stdout, stderr, rc = run_remote_command(executable, arguments)

        logging.debug(f"Command executed with return code: {rc}")

        # Cleanup: remove the service and disconnect
        start_cleanup()

        # Decode output streams
        stdout_text = stdout.decode('utf-8', errors='replace').strip() if stdout else ""
        stderr_text = stderr.decode('utf-8', errors='replace').strip() if stderr else ""

        logging.debug(f"Output captured: stdout={len(stdout_text)} chars, stderr={len(stderr_text)} chars")

        # Return combined output: stdout first, then stderr
        if stdout_text and stderr_text:
            return stdout_text + "\n" + stderr_text
        if stdout_text:
            return stdout_text
        if stderr_text:
            return stderr_text
        return f"Command executed with return code: {rc}"

    except Exception as e:
        error_str = str(e).lower()

        # Check if the exception indicates an authentication failure.
        if any(auth_err in error_str for auth_err in [
            "logon_failure", "access_denied", "status_logon_failure",
            "bad password", "wrong password", "invalid credentials",
            "authentication", "unauthorized", "rejected", "access is denied"
        ]):
            raise AuthenticationError(f"Authentication failed for {username}@{host}: {e}")

        # Check if the exception indicates a connection failure.
        if any(conn_err in error_str for conn_err in [
            "connection", "timeout", "refused", "unreachable", "reset",
            "cannot connect", "failed to connect"
        ]):
            raise ConnectionError(f"Connection failed to {host}: {e}")

        # For any other exception, re-raise
        logging.debug(f"SMB execution failed: {e}")
        raise
    finally:
        # Ensure cleanup happens even if an error occurs
        start_cleanup()


@contextmanager
def _smb_connect(host, username, password, domain="", verbose=False, encrypt=None):
    """Context manager for SMB session registration."""
    # Extract domain from username if in DOMAIN\username format
    if '\\' in username:
        domain, username = username.split('\\', 1)

    # Perform a quick connectivity check before attempting SMB
    if not check_port_open(host, 445, timeout=5):
        raise ConnectionError(f"Port 445 not reachable on {host}")

    # Build full username with domain if provided
    full_username = build_auth_username(username, domain)

    try:
        logging.debug(f"Connecting to {host}...")
        logging.debug(f"Authenticating as {full_username}...")

        # Register SMB session with smbclient
        # This doesn't actually connect yet - connection happens on first operation
        smbclient.register_session(
            host,
            username=full_username,
            password=password,
            port=445,
            encrypt=encrypt,
            connection_timeout=DEFAULT_CONNECTION_TIMEOUT
        )

        yield host, username, domain

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
        # Clean up the registered session to avoid leaving it in the global registry
        try:
            smbclient.delete_session(host)
        except Exception:
            pass


def upload(host, username, password, domain="", source="", dest="", verbose=False, status_callback=None):
    """Copy a local file or directory to a remote Windows host using SMB."""

    # Extract domain from username early so log messages are accurate
    if '\\' in username:
        domain, username = username.split('\\', 1)

    logging.debug(f"Preparing to copy to {host} as {build_auth_username(username, domain)}")

    # Validate source exists
    if not os.path.exists(source):
        raise FileNotFoundError(f"Source not found: {source}")

    # Parse destination as a local Windows path (e.g., "C:\Windows\Temp\file.exe")
    # Convert to SMB path using C$ share
    dest_normalized = dest.replace('/', '\\')

    # Remove leading backslashes if present
    dest_normalized = dest_normalized.lstrip('\\')

    # Expect format like "C:\path\to\file" - extract drive letter and path
    if len(dest_normalized) < 3 or dest_normalized[1] != ':':
        raise ValueError(f"Invalid destination format. Expected Windows path like 'C:\\path\\to\\file', got: {dest}")

    # Use admin share corresponding to the drive letter (e.g., C$, D$, etc.)
    share = f"{dest_normalized[0]}$"
    # Remove "C:\" prefix to get the path relative to the share
    remote_base_path = dest_normalized[3:] if len(dest_normalized) > 3 else ""

    logging.debug(f"Share: {share}, Remote base path: {remote_base_path}")

    with _smb_connect(host, username, password, domain, verbose) as (server, username, domain):
        # Check if source is a file or directory
        if os.path.isfile(source):
            # Single file copy
            if status_callback:
                status_callback("Copying 1 file...")
            file_size = os.path.getsize(source)
            remote_path = remote_base_path if remote_base_path else os.path.basename(source)

            logging.debug(f"Uploading {source} ({file_size} bytes) to \\\\{server}\\{share}\\{remote_path}...")

            remote_unc_path = _make_unc_path(server, share, remote_path)
            with open(source, 'rb') as local_file:
                with smb_open(remote_unc_path, mode='wb') as remote_file:
                    _copy_file_chunked(local_file, remote_file)

            if status_callback:
                status_callback("Copying 1/1 files...")

            logging.debug(f"File copied successfully: {file_size} bytes")

            return f"Copied {os.path.basename(source)} ({file_size} bytes) to \\\\{server}\\{share}\\{remote_path}"

        else:
            # Directory copy - recursive
            total_files = 0
            total_bytes = 0

            # Pre-count total files for progress reporting only when a status callback is provided
            if status_callback:
                total_file_count = sum(len(files) for _, _, files in os.walk(source))
                status_callback(f"Copying 0/{total_file_count} files...")

            # Walk through all files and subdirectories
            for root, dirs, files in os.walk(source):
                # Calculate relative path from source directory
                rel_root = os.path.relpath(root, source)
                if rel_root == ".":
                    rel_root = ""

                # Create remote directory path
                if rel_root:
                    remote_dir = remote_base_path + "\\" + rel_root.replace('/', '\\') if remote_base_path else rel_root.replace('/', '\\')
                else:
                    remote_dir = remote_base_path

                # Create remote directories using smbclient
                if remote_dir:
                    remote_dir_unc = _make_unc_path(server, share, remote_dir)
                    try:
                        # makedirs creates all parent directories if they don't exist
                        smbclient.makedirs(remote_dir_unc, exist_ok=True)
                        logging.debug(f"Created directory: \\\\{server}\\{share}\\{remote_dir}")
                    except smbclient.SMBException as e:
                        # Ignore only "already exists" errors; re-raise others
                        msg = str(e).lower()
                        if "already exists" in msg or "status_object_name_collision" in msg:
                            logging.debug(f"Directory already exists: \\\\{server}\\{share}\\{remote_dir}")
                        else:
                            raise

                # Copy each file
                for filename in files:
                    local_file_path = os.path.join(root, filename)
                    if remote_dir:
                        remote_file_path = remote_dir + "\\" + filename
                    else:
                        remote_file_path = filename

                    file_size = os.path.getsize(local_file_path)

                    logging.debug(f"Uploading {local_file_path} ({file_size} bytes) to \\\\{server}\\{share}\\{remote_file_path}...")

                    remote_file_unc = _make_unc_path(server, share, remote_file_path)
                    with open(local_file_path, 'rb') as local_file:
                        with smb_open(remote_file_unc, mode='wb') as remote_file:
                            _copy_file_chunked(local_file, remote_file)

                    total_files += 1
                    total_bytes += file_size

                    if status_callback:
                        status_callback(f"Copying {total_files}/{total_file_count} files...")

            logging.debug(f"Directory copied successfully: {total_files} files, {total_bytes} bytes")

            return f"Copied {total_files} file(s) ({total_bytes} bytes) to \\\\{server}\\{share}\\{remote_base_path}"


def download(host, username, password, domain="", source="", dest="", verbose=False, status_callback=None):
    """Download a file or directory from a remote Windows host using SMB."""

    # Extract domain from username early so log messages are accurate
    if '\\' in username:
        domain, username = username.split('\\', 1)

    logging.debug(f"Preparing to download from {host} as {build_auth_username(username, domain)}")

    # Parse source as a remote Windows path (e.g., "C:\Windows\Temp\file.exe")
    # Convert to SMB path using C$ share
    source_normalized = source.replace('/', '\\')
    source_normalized = source_normalized.lstrip('\\')

    if len(source_normalized) < 3 or source_normalized[1] != ':':
        raise ValueError(f"Invalid source format. Expected Windows path like 'C:\\path\\to\\file', got: {source}")

    # Use admin share corresponding to the drive letter (e.g., C$, D$, etc.)
    share = f"{source_normalized[0]}$"
    remote_base_path = source_normalized[3:] if len(source_normalized) > 3 else ""

    logging.debug(f"Share: {share}, Remote base path: {remote_base_path}")

    with _smb_connect(host, username, password, domain, verbose) as (server, username, domain):
        # Determine if remote source is a file or directory
        remote_unc_path = _make_unc_path(server, share, remote_base_path)

        # Check if path exists and determine if it's a directory
        is_directory = False
        if smb_exists(remote_unc_path):
            try:
                is_directory = smb_isdir(remote_unc_path)
            except (OSError, IOError):
                # If we can't determine type, assume it's a file
                is_directory = False
        else:
            raise FileNotFoundError(f"Remote path does not exist: {remote_unc_path}")

        if not is_directory:
            # Single file download
            if status_callback:
                status_callback("Downloading 1 file...")

            # If dest is an existing directory, append the source filename
            if os.path.isdir(dest):
                dest = os.path.join(dest, os.path.basename(remote_base_path))

            # Ensure local destination directory exists
            dest_dir = os.path.dirname(dest)
            if dest_dir:
                os.makedirs(dest_dir, exist_ok=True)

            logging.debug(f"Downloading \\\\{server}\\{share}\\{remote_base_path} to {dest}...")

            with smb_open(remote_unc_path, mode='rb') as remote_file:
                with open(dest, 'wb') as local_file:
                    _copy_file_chunked(remote_file, local_file)

            file_size = os.path.getsize(dest)

            if status_callback:
                status_callback("Downloading 1/1 files...")

            logging.debug(f"File downloaded successfully: {file_size} bytes")

            return f"Downloaded {os.path.basename(remote_base_path)} ({file_size} bytes) from \\\\{server}\\{share}\\{remote_base_path}"

        else:
            # Directory download - recursive
            total_files = 0
            total_bytes = 0

            if status_callback:
                status_callback("Scanning remote directory...")

            # Use smbclient's walk function to recursively download
            for remote_root, dirs, files in smb_walk(remote_unc_path):
                # Calculate relative path from source
                # remote_root is like \\server\share\path\subdir
                # We need to get the relative part after remote_unc_path
                if remote_root == remote_unc_path:
                    rel_path = ""
                else:
                    # Strip the base path
                    rel_path = remote_root[len(remote_unc_path):].lstrip('\\/')

                # Create local directory
                if rel_path:
                    local_dir = os.path.join(dest, rel_path.replace('\\', os.sep))
                else:
                    local_dir = dest
                os.makedirs(local_dir, exist_ok=True)

                # Download each file
                for filename in files:
                    # Construct remote file path using UNC path separator
                    if not remote_root.endswith('\\'):
                        remote_file_path = remote_root + '\\' + filename
                    else:
                        remote_file_path = remote_root + filename

                    local_file_path = os.path.join(local_dir, filename)

                    logging.debug(f"Downloading {remote_file_path} to {local_file_path}...")

                    with smb_open(remote_file_path, mode='rb') as remote_file:
                        with open(local_file_path, 'wb') as local_file:
                            _copy_file_chunked(remote_file, local_file)

                    file_size = os.path.getsize(local_file_path)
                    total_files += 1
                    total_bytes += file_size

                    if status_callback:
                        status_callback(f"Downloaded {total_files} file(s)...")

            logging.debug(f"Directory downloaded successfully: {total_files} files, {total_bytes} bytes")

            return f"Downloaded {total_files} file(s) ({total_bytes} bytes) from \\\\{server}\\{share}\\{remote_base_path}"
