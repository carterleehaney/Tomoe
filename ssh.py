import os
import socket
import random
import string
import paramiko


class SSHAuthenticationError(Exception):
    """Raised when SSH authentication fails due to invalid credentials."""
    pass


class SSHConnectionError(Exception):
    """Raised when an SSH connection cannot be established to the target host."""
    pass


def check_port_open(host, port=22, timeout=5):
    """
    Perform a quick TCP connectivity check to determine if a port is open.
    
    This function attempts to establish a TCP connection to the specified host
    and port. It is used as a pre-flight check before attempting SSH operations
    to avoid long timeout delays when the target is unreachable.
    
    Args:
        host: The hostname or IP address to check.
        port: The TCP port number to test (default is 22 for SSH).
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


def _create_ssh_client(target_ip, auth_username, password, verbose=False):
    """
    Create and return a connected paramiko SSHClient.
    
    Args:
        target_ip: The IP address or hostname of the remote host.
        auth_username: The username for authentication (may include DOMAIN\\user).
        password: The password for authentication.
        verbose: If True, print detailed status messages.
    
    Returns:
        A connected paramiko.SSHClient instance.
    
    Raises:
        SSHAuthenticationError: If authentication fails.
        SSHConnectionError: If the connection cannot be established.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(
            hostname=target_ip,
            port=22,
            username=auth_username,
            password=password,
            timeout=30,
            allow_agent=False,
            look_for_keys=False,
        )
    except paramiko.AuthenticationException as e:
        if verbose:
            print(f"[!] SSH authentication failed: {e}")
        raise SSHAuthenticationError(f"Authentication failed for {auth_username}@{target_ip}: {e}")
    except (paramiko.SSHException, socket.error, OSError) as e:
        if verbose:
            print(f"[!] SSH connection failed: {e}")
        raise SSHConnectionError(f"Connection failed to {target_ip}: {e}")
    
    return client


def run_ssh(target_ip, username, password, domain="", script_path=None, command=None, script_args="", verbose=False, status_callback=None, target_os="windows"):
    """
    Execute a script or command on a remote host using SSH.
    
    This function uses paramiko to establish an SSH connection and execute
    commands or scripts on a remote host running OpenSSH. For Windows targets,
    commands are wrapped in powershell.exe. For Linux targets, commands are
    passed directly to the default shell.
    
    For script execution, the script is uploaded via SFTP to a temporary
    location, executed, and then cleaned up.
    
    Args:
        target_ip: The IP address or hostname of the remote machine.
        username: The username for authentication.
        password: The password for authentication.
        domain: Optional domain name for domain-joined authentication (Windows only).
        script_path: Path to a local script file to execute remotely.
        command: A command string to execute (mutually exclusive with script_path).
        script_args: Arguments to pass to the script when using script_path.
        verbose: If True, print detailed status messages during execution.
        status_callback: Optional callable(message) to report execution progress.
        target_os: The remote host OS, either "windows" or "linux" (default "windows").
    
    Returns:
        A string containing the combined output from stdout and stderr.
    
    Raises:
        SSHConnectionError: If the connection to the target host fails.
        SSHAuthenticationError: If authentication fails due to invalid credentials.
        ValueError: If neither script_path nor command is provided.
    """
    
    is_linux = target_os == "linux"
    
    # Perform a quick connectivity check before attempting SSH.
    # This prevents long timeout delays when the target is unreachable.
    if not check_port_open(target_ip, 22, timeout=5):
        raise SSHConnectionError(f"Port 22 not reachable on {target_ip}")
    
    # Construct the authentication username.
    # Domain prefixing only applies to Windows (Active Directory) environments.
    if domain and not is_linux:
        auth_username = f"{domain}\\{username}"
    else:
        auth_username = username
    
    client = _create_ssh_client(target_ip, auth_username, password, verbose)
    
    # SSH connected successfully - authentication has passed.
    if status_callback:
        status_callback("Authenticated, preparing command...")
    
    remote_script_path = None
    
    try:
        if script_path:
            # Upload the script to a temporary location via SFTP, then execute it.
            if verbose:
                print(f"[*] Reading local script: {script_path}")
            
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
                if verbose:
                    print(f"[*] Uploaded script to {remote_script_path}")
            finally:
                sftp.close()
            
            # Build the execution command.
            if is_linux:
                cmd_args = f'bash "{remote_script_path}" {script_args}'
            else:
                cmd_args = f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{remote_script_path}" {script_args}'
            
        elif command:
            # For simple commands, invoke directly (Linux) or via PowerShell (Windows).
            if verbose:
                print(f"[*] Executing command: {command}")
            
            if is_linux:
                cmd_args = command
            else:
                cmd_args = f'powershell.exe -NoProfile -NonInteractive -Command "{command}"'
            
        else:
            raise ValueError("Either --script or --command must be provided.")
        
        if verbose:
            print(f"[*] Executing on {target_ip} via SSH...")
        
        # Execute the command on the remote host.
        if status_callback:
            status_callback("Executing...")
        
        stdin, stdout, stderr = client.exec_command(cmd_args, timeout=300)
        
        # Read stdout and stderr.
        stdout_text = stdout.read().decode('utf-8', errors='replace').replace('\r', '').strip()
        stderr_text = stderr.read().decode('utf-8', errors='replace').replace('\r', '').strip()
        exit_code = stdout.channel.recv_exit_status()
        
        if verbose:
            print(f"[+] Command executed, exit code: {exit_code}")
            print(f"[+] stdout: {len(stdout_text)} chars, stderr: {len(stderr_text)} chars")
        
        # Clean up the temporary script file if one was uploaded.
        if remote_script_path:
            try:
                sftp = client.open_sftp()
                try:
                    sftp.remove(remote_script_path)
                    if verbose:
                        print(f"[*] Cleaned up remote script: {remote_script_path}")
                finally:
                    sftp.close()
            except Exception:
                # Best-effort cleanup; don't fail the operation if cleanup fails.
                if verbose:
                    print(f"[!] Failed to clean up remote script: {remote_script_path}")
        
        # Validate command execution and provide meaningful error messages.
        if stderr_text and ("is not recognized" in stderr_text or "cannot be loaded" in stderr_text):
            if verbose:
                print(f"[!] Command execution failed: {stderr_text}")
            return f"ERROR: {stderr_text}"
        
        if not stdout_text and not stderr_text and exit_code != 0:
            error_msg = f"Command failed with exit code {exit_code}"
            if verbose:
                print(f"[!] {error_msg}")
            return error_msg
        
        # Return combined output: stdout first, then stderr.
        if stdout_text and stderr_text:
            return stdout_text + "\n" + stderr_text
        if stdout_text:
            return stdout_text
        if stderr_text:
            return stderr_text
        return f"Command executed with exit code {exit_code}"
    
    except (SSHAuthenticationError, SSHConnectionError):
        raise
    except Exception as e:
        error_str = str(e).lower()
        
        # Check if the exception indicates an authentication failure.
        if any(auth_err in error_str for auth_err in [
            "authentication", "auth", "login failed",
            "invalid credentials", "access denied", "permission denied",
            "unauthorized", "rejected"
        ]):
            if verbose:
                print(f"[!] SSH authentication failed: {e}")
            raise SSHAuthenticationError(f"Authentication failed for {auth_username}@{target_ip}: {e}")
        
        # Check if the exception indicates a connection failure.
        if any(conn_err in error_str for conn_err in [
            "connection", "timeout", "refused", "unreachable", "reset", "eof"
        ]):
            if verbose:
                print(f"[!] SSH connection failed: {e}")
            raise SSHConnectionError(f"Connection failed to {target_ip}: {e}")
        
        if verbose:
            print(f"[!] SSH execution failed: {e}")
        raise
    finally:
        client.close()


def run_ssh_copy(target_ip, username, password, domain="", source="", dest="", verbose=False, status_callback=None, target_os="windows"):
    """
    Copy a local file or directory to a remote host using SSH/SFTP.
    
    This function uses paramiko to establish an SSH connection and upload
    files via SFTP. It supports both single file uploads and recursive
    directory uploads. Path handling adapts to the target OS.
    
    Args:
        target_ip: The IP address or hostname of the remote machine.
        username: The username for authentication.
        password: The password for authentication.
        domain: Optional domain name for domain-joined authentication (Windows only).
        source: Path to the local file or directory to copy.
        dest: Remote destination path (Windows: "C:\\Temp\\file.exe", Linux: "/tmp/file").
        verbose: If True, print detailed status messages during execution.
        status_callback: Optional callable(message) to report execution progress.
        target_os: The remote host OS, either "windows" or "linux" (default "windows").
    
    Returns:
        A string containing a success message with files/bytes transferred.
    
    Raises:
        SSHConnectionError: If the connection to the target host fails.
        SSHAuthenticationError: If authentication fails due to invalid credentials.
        FileNotFoundError: If the source file/directory does not exist.
    """
    
    is_linux = target_os == "linux"
    sep = "/" if is_linux else "\\"
    
    # Perform a quick connectivity check before attempting SSH.
    if not check_port_open(target_ip, 22, timeout=5):
        raise SSHConnectionError(f"Port 22 not reachable on {target_ip}")
    
    # Validate source exists.
    if not os.path.exists(source):
        raise FileNotFoundError(f"Source not found: {source}")
    
    # Construct the authentication username.
    # Domain prefixing only applies to Windows (Active Directory) environments.
    if domain and not is_linux:
        auth_username = f"{domain}\\{username}"
    else:
        auth_username = username
    
    client = _create_ssh_client(target_ip, auth_username, password, verbose)
    
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
                
                if verbose:
                    print(f"[*] Uploading {source} ({file_size} bytes) to {target_ip}:{remote_path}...")
                
                sftp.put(source, remote_path)
                
                if status_callback:
                    status_callback("Copying 1/1 files...")
                
                if verbose:
                    print(f"[+] File copied successfully: {file_size} bytes")
                
                return f"Copied {os.path.basename(source)} ({file_size} bytes) to {target_ip}:{remote_path}"
            
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
                        if verbose:
                            print(f"[*] Created directory: {remote_dir}")
                    except IOError:
                        # Directory may already exist, or we need to create parent dirs.
                        # Fall back to creating via SSH command for nested paths.
                        try:
                            if is_linux:
                                mkdir_cmd = f'mkdir -p "{remote_dir}"'
                            else:
                                mkdir_cmd = f'powershell.exe -NoProfile -NonInteractive -Command "New-Item -ItemType Directory -Path \'{remote_dir}\' -Force | Out-Null"'
                            stdin, stdout, stderr = client.exec_command(mkdir_cmd, timeout=30)
                            stdout.channel.recv_exit_status()
                            if verbose:
                                print(f"[*] Created directory (via cmd): {remote_dir}")
                        except Exception:
                            pass
                
                # Copy each file.
                total_file_count = len(files_to_copy)
                if status_callback:
                    status_callback(f"Copying 0/{total_file_count} files...")
                
                for local_file_path, remote_file_path in files_to_copy:
                    file_size = os.path.getsize(local_file_path)
                    
                    if verbose:
                        print(f"[*] Uploading {local_file_path} ({file_size} bytes) to {target_ip}:{remote_file_path}...")
                    
                    sftp.put(local_file_path, remote_file_path)
                    
                    total_files += 1
                    total_bytes += file_size
                    
                    if status_callback:
                        status_callback(f"Copying {total_files}/{total_file_count} files...")
                
                if verbose:
                    print(f"[+] Directory copied successfully: {total_files} files, {total_bytes} bytes")
                
                return f"Copied {total_files} file(s) ({total_bytes} bytes) to {target_ip}:{dest_normalized}"
            
            else:
                raise ValueError(f"Source '{source}' exists but is neither a regular file nor a directory")
        
        finally:
            sftp.close()
    
    except (SSHAuthenticationError, SSHConnectionError):
        raise
    except Exception as e:
        error_str = str(e).lower()
        
        # Check if this is a file/path access error (not an auth error).
        if "no such file" in error_str or "permission denied" in error_str and "sftp" not in error_str:
            if verbose:
                print(f"[!] SSH copy failed: {e}")
            raise
        
        # Check if the exception indicates an authentication failure.
        if any(auth_err in error_str for auth_err in [
            "authentication", "auth failed", "login failed",
            "invalid credentials", "access denied", "unauthorized", "rejected"
        ]):
            if verbose:
                print(f"[!] SSH authentication failed: {e}")
            raise SSHAuthenticationError(f"Authentication failed for {auth_username}@{target_ip}: {e}")
        
        # Check if the exception indicates a connection failure.
        if any(conn_err in error_str for conn_err in [
            "connection", "timeout", "refused", "unreachable", "reset", "eof"
        ]):
            if verbose:
                print(f"[!] SSH connection failed: {e}")
            raise SSHConnectionError(f"Connection failed to {target_ip}: {e}")
        
        if verbose:
            print(f"[!] SSH copy failed: {e}")
        raise
    finally:
        client.close()
