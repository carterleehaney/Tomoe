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

# Suppress cryptography deprecation warnings from dependencies
warnings.filterwarnings("ignore", category=DeprecationWarning, module=".*crypto.*")
warnings.filterwarnings("ignore", message=".*ARC4.*")


# Constants for SMB operations
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1MB chunks for file transfers
DEFAULT_CONNECTION_TIMEOUT = 30  # seconds


class SMBAuthenticationError(Exception):
    """Raised when SMB authentication fails due to invalid credentials."""
    pass


class SMBConnectionError(Exception):
    """Raised when an SMB connection cannot be established to the target host."""
    pass


def check_port_open(host, port=445, timeout=5):
    """
    Perform a quick TCP connectivity check to determine if a port is open.
    
    This function attempts to establish a TCP connection to the specified host
    and port. It is used as a pre-flight check before attempting SMB operations
    to avoid long timeout delays when the target is unreachable.
    
    Args:
        host: The hostname or IP address to check.
        port: The TCP port number to test (default is 445 for SMB).
        timeout: The connection timeout in seconds (default is 5 seconds).
    
    Returns:
        True if the port is open and accepting connections, False otherwise.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error:
        return False


def _make_unc_path(server, share, path):
    """
    Create a UNC path for smbclient operations.
    
    Args:
        server: The server hostname or IP
        share: The share name (e.g., 'C$', 'ADMIN$')
        path: The path within the share (can be empty string for root)
    
    Returns:
        A UNC path like \\\\server\\share\\path
    """
    if path:
        # Normalize path separators
        path = path.replace('/', '\\')
        return f"\\\\{server}\\{share}\\{path}"
    else:
        return f"\\\\{server}\\{share}"


def _copy_file_chunked(source_file, dest_file, chunk_size=DEFAULT_CHUNK_SIZE):
    """
    Copy data from source file to destination file in chunks.
    
    Args:
        source_file: Source file object (opened for reading)
        dest_file: Destination file object (opened for writing)
        chunk_size: Size of chunks to read/write (default: 1MB)
    
    This function is memory-efficient for large files as it reads and writes
    in chunks rather than loading the entire file into memory.
    """
    while True:
        chunk = source_file.read(chunk_size)
        if not chunk:
            break
        dest_file.write(chunk)


def run_psexec(target_ip, username, password, domain="", script_path=None, command=None, script_args="", verbose=False, status_callback=None, shell_type="powershell", encrypt=True):
    """
    Execute a script or command on a remote Windows host using SMB/psexec.
    
    Args:
        target_ip: The IP address or hostname of the remote Windows machine.
        username: The username for authentication.
        password: The password for authentication.
        domain: Optional domain name for authentication.
        script_path: Path to a local script file to execute remotely (.ps1 for PowerShell, .bat/.cmd for CMD).
        command: A command string to execute.
        script_args: Arguments to pass to the script.
        verbose: If True, print detailed status messages.
        status_callback: Optional callable(message) to report progress.
        shell_type: "powershell" (default) or "cmd" to specify the shell type.
        encrypt: Boolean, whether to use SMB encryption (default: True).
    
    Returns:
        String containing the combined output (stdout + stderr).
    
    Raises:
        SMBConnectionError: If connection fails.
        SMBAuthenticationError: If authentication fails.
    """
    
    # Extract domain from username if in DOMAIN\username format
    if '\\' in username:
        domain, username = username.split('\\', 1)
    
    # Suppress pypsexec logging to avoid artifacts in output
    import logging
    pypsexec_logger = logging.getLogger('pypsexec')
    if not verbose:
        pypsexec_logger.setLevel(logging.CRITICAL + 1)  # Effectively disable
    else:
        pypsexec_logger.setLevel(logging.INFO)
    
    # Perform a quick connectivity check before attempting SMB.
    # This prevents long timeout delays when the target is unreachable.
    if not check_port_open(target_ip, 445, timeout=5):
        raise SMBConnectionError(f"Port 445 not reachable on {target_ip}")
    
    # Construct the authentication username.
    # If a domain is specified, use the DOMAIN\username format.
    if domain:
        auth_username = f"{domain}\\{username}"
    else:
        auth_username = username
    
    script_name = None
    smb_conn = None
    
    try:
        # Create a pypsexec Client for remote execution
        # The Client class handles service installation, execution, and cleanup
        client = Client(
            target_ip,
            username=auth_username,
            password=password,
            encrypt=encrypt
        )
        
        # Connect to the remote host
        if verbose:
            print(f"[*] Connecting to {target_ip} as {auth_username}...")
        
        client.connect()
        
        # Create the remote service
        if status_callback:
            status_callback("Authenticated, preparing command...")
        
        if verbose:
            print(f"[*] Creating remote service...")
        
        client.create_service()
        
        # Build the command based on shell type
        if script_path:
            # Upload the script to the remote machine via SMB (matching old-smb.py behavior)
            if verbose:
                print(f"[*] Uploading script: {script_path}")
            
            script_name = os.path.basename(script_path)
            
            # Register SMB session for file upload
            # Build full username with domain if provided
            if domain:
                full_username = f"{domain}\\{username}"
            else:
                full_username = username
            
            smbclient.register_session(
                target_ip,
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
                admin_unc_path = _make_unc_path(target_ip, 'ADMIN$', script_name)
                with open(script_path, 'rb') as local_file:
                    with smb_open(admin_unc_path, mode='wb') as remote_file:
                        _copy_file_chunked(local_file, remote_file)
                share = 'ADMIN$'
                remote_path = script_name
                if verbose:
                    print(f"[*] Script uploaded to \\\\{target_ip}\\ADMIN$\\{script_name}")
            except Exception as e:
                if verbose:
                    print(f"[!] ADMIN$ upload failed: {e}, trying C$\\Windows\\Temp...")
                
                # Fallback to C$\Windows\Temp
                try:
                    temp_path = f"Windows\\Temp\\{script_name}"
                    temp_unc_path = _make_unc_path(target_ip, 'C$', temp_path)
                    with open(script_path, 'rb') as local_file:
                        with smb_open(temp_unc_path, mode='wb') as remote_file:
                            _copy_file_chunked(local_file, remote_file)
                    share = 'C$'
                    remote_path = temp_path
                    if verbose:
                        print(f"[*] Script uploaded to \\\\{target_ip}\\C$\\{temp_path}")
                except Exception as e2:
                    raise Exception(f"Failed to upload script to any share: ADMIN$ and C$ both failed: {e2}")
            
            # Execute directly from SMB share using UNC path (like old-smb.py)
            if share == 'ADMIN$':
                unc_path = f"\\\\{target_ip}\\ADMIN$\\{script_name}"
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
            if verbose:
                print(f"[*] Executing command: {command}")
            
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
        
        if verbose:
            print(f"[*] Executing on {target_ip}...")
        
        if status_callback:
            status_callback("Executing...")
        
        # Execute the command and capture output
        stdout, stderr, rc = client.run_executable(
            executable=executable,
            arguments=arguments
        )
        
        # Decode initial output to check for path errors
        temp_stdout = stdout.decode('utf-8', errors='replace') if stdout else ""
        
        # cmd.exe error for missing executable usually goes to stderr (redirected to stdout by 2>&1)
        if (rc != 0 or "The system cannot find the path specified" in temp_stdout or "' is not recognized" in temp_stdout) and "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" in arguments:
            if verbose:
                print(f"[*] Full path failed. Retrying with short 'powershell.exe' path...")
            
            # Reconstruct command with short 'powershell.exe' instead of full path
            arguments = arguments.replace(
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", 
                "powershell.exe"
            )
            
            if verbose:
                print(f"[*] Retry arguments: {arguments}")
                
            # Retry execution
            stdout, stderr, rc = client.run_executable(
                executable=executable,
                arguments=arguments
            )
        
        if verbose:
            print(f"[+] Command executed with return code: {rc}")
        
        # Cleanup: remove the service and disconnect
        client.remove_service()
        client.disconnect()
        
        # Decode output streams
        stdout_text = stdout.decode('utf-8', errors='replace').strip() if stdout else ""
        stderr_text = stderr.decode('utf-8', errors='replace').strip() if stderr else ""
        
        if verbose:
            print(f"[+] Output captured: stdout={len(stdout_text)} chars, stderr={len(stderr_text)} chars")
        
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
        # Only print errors if verbose mode is enabled
        if any(auth_err in error_str for auth_err in [
            "logon_failure", "access_denied", "status_logon_failure",
            "bad password", "wrong password", "invalid credentials",
            "authentication", "unauthorized", "rejected", "access is denied"
        ]):
            raise SMBAuthenticationError(f"Authentication failed for {username}@{target_ip}: {e}")
        
        # Check if the exception indicates a connection failure.
        if any(conn_err in error_str for conn_err in [
            "connection", "timeout", "refused", "unreachable", "reset",
            "cannot connect", "failed to connect"
        ]):
            raise SMBConnectionError(f"Connection failed to {target_ip}: {e}")
        
        # For any other exception, re-raise silently unless verbose
        if verbose:
            print(f"[!] SMB execution failed: {e}")
        raise
    finally:
        # Ensure cleanup happens even if an error occurs
        try:
            if 'client' in locals():
                try:
                    client.remove_service()
                except Exception:
                    pass
                try:
                    client.disconnect()
                except Exception:
                    pass
            
            # Clean up uploaded script file BEFORE deleting the session
            if 'script_name' in locals() and 'share' in locals() and 'remote_path' in locals():
                try:
                    script_unc_path = _make_unc_path(target_ip, share, remote_path)
                    smb_remove(script_unc_path)
                    if verbose:
                        print(f"[*] Cleaned up script file: {share}\\{remote_path}")
                except Exception:
                    pass
            
            # Clean up SMB session after removing the file
            if 'script_path' in locals():
                try:
                    smbclient.delete_session(target_ip)
                except Exception:
                    pass
        except Exception:
            pass


@contextmanager
def _smb_connect(target_ip, username, password, domain="", verbose=False, encrypt=None):
    """
    Context manager that handles SMB session registration for smbclient.
    
    Manages the shared boilerplate for SMB operations: domain extraction from
    username, connectivity pre-check, session registration, authentication,
    error classification, and guaranteed cleanup.
    
    Args:
        target_ip: The IP address or hostname of the remote Windows machine.
        username: The username for authentication (can be in DOMAIN\\username format).
        password: The password for authentication.
        domain: Optional domain name for domain-joined authentication.
        verbose: If True, enable detailed logging.
        encrypt: Optional SMB encryption setting (True, False, or None to let server decide).
    
    Yields:
        A tuple of (target_ip, username, domain) for use in subsequent SMB operations.
    
    Raises:
        SMBConnectionError: If port 445 is not reachable or the connection fails.
        SMBAuthenticationError: If authentication fails due to invalid credentials.
    """
    # Extract domain from username if in DOMAIN\username format
    if '\\' in username:
        domain, username = username.split('\\', 1)

    # Perform a quick connectivity check before attempting SMB
    if not check_port_open(target_ip, 445, timeout=5):
        raise SMBConnectionError(f"Port 445 not reachable on {target_ip}")

    # Build full username with domain if provided
    if domain:
        full_username = f"{domain}\\{username}"
    else:
        full_username = username

    try:
        if verbose:
            logging.info(f"Connecting to {target_ip}...")
            logging.info(f"Authenticating as {full_username}...")

        # Register SMB session with smbclient
        # This doesn't actually connect yet - connection happens on first operation
        smbclient.register_session(
            target_ip,
            username=full_username,
            password=password,
            port=445,
            encrypt=encrypt,
            connection_timeout=DEFAULT_CONNECTION_TIMEOUT
        )

        yield target_ip, username, domain

    except Exception as e:
        error_msg = str(e).lower()
        auth_error_patterns = [
            "logon_failure", "access_denied", "status_logon_failure",
            "bad password", "wrong password", "invalid credentials",
            "authentication", "unauthorized", "rejected", "logon failure"
        ]
        if any(pattern in error_msg for pattern in auth_error_patterns):
            raise SMBAuthenticationError(f"Authentication failed: {e}")
        raise SMBConnectionError(f"Connection failed to {target_ip}: {e}")
    finally:
        # Clean up the registered session to avoid leaving it in the global registry
        try:
            smbclient.delete_session(target_ip)
        except Exception:
            pass


def run_smb_copy(target_ip, username, password, domain="", source="", dest="", verbose=False, status_callback=None):
    """
    Copy a local file or directory to a remote Windows host using SMB.
    
    This function establishes an SMB connection and uploads a file or directory
    from the local system to a specified path on the remote host. If the source
    is a directory, it recursively copies all files and subdirectories.
    
    Args:
        target_ip: The IP address or hostname of the remote Windows machine.
        username: The username for authentication (can be in DOMAIN\\username format).
        password: The password for authentication.
        domain: Optional domain name for domain-joined authentication.
        source: Path to the local file or directory to copy.
        dest: Remote destination as a local Windows path (e.g., "C:\\Windows\\Temp\\folder").
        verbose: If True, print detailed status messages during execution.
        status_callback: Optional callable(message) to report execution progress.
    
    Returns:
        A string containing a success message with files/bytes transferred.
    
    Raises:
        SMBConnectionError: If the connection to the target host fails.
        SMBAuthenticationError: If authentication fails due to invalid credentials.
        FileNotFoundError: If the source file/directory does not exist.
        ValueError: If the destination path format is invalid.
    """
    
    # Extract domain from username early so log messages are accurate
    if '\\' in username:
        domain, username = username.split('\\', 1)
    
    if verbose:
        logging.info(f"Preparing to copy to {target_ip} as {domain}\\{username}")
    
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
    
    if verbose:
        print(f"[*] Share: {share}, Remote base path: {remote_base_path}")
    
    with _smb_connect(target_ip, username, password, domain, verbose) as (server, username, domain):
        # Check if source is a file or directory
        if os.path.isfile(source):
            # Single file copy
            if status_callback:
                status_callback("Copying 1 file...")
            file_size = os.path.getsize(source)
            remote_path = remote_base_path if remote_base_path else os.path.basename(source)
            
            if verbose:
                print(f"[*] Uploading {source} ({file_size} bytes) to \\\\{server}\\{share}\\{remote_path}...")
            
            remote_unc_path = _make_unc_path(server, share, remote_path)
            with open(source, 'rb') as local_file:
                with smb_open(remote_unc_path, mode='wb') as remote_file:
                    _copy_file_chunked(local_file, remote_file)
            
            if status_callback:
                status_callback("Copying 1/1 files...")
            
            if verbose:
                print(f"[+] File copied successfully: {file_size} bytes")
            
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
                        if verbose:
                            print(f"[*] Created directory: \\\\{server}\\{share}\\{remote_dir}")
                    except smbclient.SMBException as e:
                        # Ignore only "already exists" errors; re-raise others
                        msg = str(e).lower()
                        if "already exists" in msg or "status_object_name_collision" in msg:
                            if verbose:
                                print(f"[*] Directory already exists: \\\\{server}\\{share}\\{remote_dir}")
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
                    
                    if verbose:
                        print(f"[*] Uploading {local_file_path} ({file_size} bytes) to \\\\{server}\\{share}\\{remote_file_path}...")
                    
                    remote_file_unc = _make_unc_path(server, share, remote_file_path)
                    with open(local_file_path, 'rb') as local_file:
                        with smb_open(remote_file_unc, mode='wb') as remote_file:
                            _copy_file_chunked(local_file, remote_file)
                    
                    total_files += 1
                    total_bytes += file_size
                    
                    if status_callback:
                        status_callback(f"Copying {total_files}/{total_file_count} files...")
            
            if verbose:
                print(f"[+] Directory copied successfully: {total_files} files, {total_bytes} bytes")
            
            return f"Copied {total_files} file(s) ({total_bytes} bytes) to \\\\{server}\\{share}\\{remote_base_path}"


def run_smb_download(target_ip, username, password, domain="", source="", dest="", verbose=False, status_callback=None):
    """
    Download a file or directory from a remote Windows host to the local system using SMB.
    
    This function establishes an SMB connection and downloads a file or directory
    from the remote host to a specified local path. If the source is a directory,
    it recursively downloads all files and subdirectories.
    
    Args:
        target_ip: The IP address or hostname of the remote Windows machine.
        username: The username for authentication (can be in DOMAIN\\username format).
        password: The password for authentication.
        domain: Optional domain name for domain-joined authentication.
        source: Remote source as a local Windows path (e.g., "C:\\Windows\\Temp\\file.exe").
        dest: Path to the local destination file or directory.
        verbose: If True, print detailed status messages during execution.
        status_callback: Optional callable(message) to report execution progress.
    
    Returns:
        A string containing a success message with files/bytes transferred.
    
    Raises:
        SMBConnectionError: If the connection to the target host fails.
        SMBAuthenticationError: If authentication fails due to invalid credentials.
        ValueError: If the source path format is invalid.
    """
    
    # Extract domain from username early so log messages are accurate
    if '\\' in username:
        domain, username = username.split('\\', 1)
    
    if verbose:
        logging.info(f"Preparing to download from {target_ip} as {domain}\\{username}")
    
    # Parse source as a remote Windows path (e.g., "C:\Windows\Temp\file.exe")
    # Convert to SMB path using C$ share
    source_normalized = source.replace('/', '\\')
    source_normalized = source_normalized.lstrip('\\')
    
    if len(source_normalized) < 3 or source_normalized[1] != ':':
        raise ValueError(f"Invalid source format. Expected Windows path like 'C:\\path\\to\\file', got: {source}")
    
    # Use admin share corresponding to the drive letter (e.g., C$, D$, etc.)
    share = f"{source_normalized[0]}$"
    remote_base_path = source_normalized[3:] if len(source_normalized) > 3 else ""
    
    if verbose:
        logging.info(f"Share: {share}, Remote base path: {remote_base_path}")
    
    with _smb_connect(target_ip, username, password, domain, verbose) as (server, username, domain):
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
            
            if verbose:
                logging.info(f"Downloading \\\\{server}\\{share}\\{remote_base_path} to {dest}...")
            
            with smb_open(remote_unc_path, mode='rb') as remote_file:
                with open(dest, 'wb') as local_file:
                    _copy_file_chunked(remote_file, local_file)
            
            file_size = os.path.getsize(dest)
            
            if status_callback:
                status_callback("Downloading 1/1 files...")
            
            if verbose:
                logging.info(f"File downloaded successfully: {file_size} bytes")
            
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
                    
                    if verbose:
                        logging.info(f"Downloading {remote_file_path} to {local_file_path}...")
                    
                    with smb_open(remote_file_path, mode='rb') as remote_file:
                        with open(local_file_path, 'wb') as local_file:
                            _copy_file_chunked(remote_file, local_file)
                    
                    file_size = os.path.getsize(local_file_path)
                    total_files += 1
                    total_bytes += file_size
                    
                    if status_callback:
                        status_callback(f"Downloaded {total_files} file(s)...")
            
            if verbose:
                logging.info(f"Directory downloaded successfully: {total_files} files, {total_bytes} bytes")
            
            return f"Downloaded {total_files} file(s) ({total_bytes} bytes) from \\\\{server}\\{share}\\{remote_base_path}"
