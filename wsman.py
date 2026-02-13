import os
import socket
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan
from pypsrp.client import Client


class WinRMAuthenticationError(Exception):
    """Raised when WinRM authentication fails due to invalid credentials."""
    pass


class WinRMConnectionError(Exception):
    """Raised when a WinRM connection cannot be established to the target host."""
    pass


def check_port_open(host, port=5985, timeout=5):
    """
    Perform a quick TCP connectivity check to determine if a port is open.
    
    This function attempts to establish a TCP connection to the specified host
    and port. It is used as a pre-flight check before attempting WinRM operations
    to avoid long timeout delays when the target is unreachable.
    
    Args:
        host: The hostname or IP address to check.
        port: The TCP port number to test (default is 5985 for WinRM HTTP).
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


def run_winrm(target_ip, username, password, domain="", script_path=None, command=None, script_args="", verbose=False, status_callback=None):
    """
    Execute a PowerShell script or command on a remote Windows host using WinRM.
    
    This function uses the pypsrp library to establish a PowerShell Remoting Protocol
    (PSRP) connection over WS-Management. Unlike the older pywinrm library, pypsrp
    properly implements the PSRP protocol, which allows for streaming large scripts
    without hitting command line length limits and provides access to all PowerShell
    output streams (Output, Error, Warning, Information, etc.).
    
    Args:
        target_ip: The IP address or hostname of the remote Windows machine.
        username: The username for authentication.
        password: The password for authentication.
        domain: Optional domain name for domain-joined authentication.
        script_path: Path to a local PowerShell script file to execute remotely.
        command: A PowerShell command string to execute (mutually exclusive with script_path).
        script_args: Arguments to pass to the script when using script_path.
        verbose: If True, print detailed status messages during execution.
        status_callback: Optional callable(message) to report execution progress.
    
    Returns:
        A string containing the combined output from all PowerShell streams.
    
    Raises:
        WinRMConnectionError: If the connection to the target host fails.
        WinRMAuthenticationError: If authentication fails due to invalid credentials.
        ValueError: If neither script_path nor command is provided.
    """
    
    # Perform a quick connectivity check before attempting WinRM.
    # This prevents long timeout delays when the target is unreachable.
    if not check_port_open(target_ip, 5985, timeout=5):
        raise WinRMConnectionError(f"Port 5985 not reachable on {target_ip}")

    # Construct the authentication username.
    # If a domain is specified, use the DOMAIN\username format for NTLM authentication.
    if domain:
        auth_username = f"{domain}\\{username}"
    else:
        auth_username = username

    try:
        # Create a WS-Management connection using NTLM authentication.
        # The WSMan class handles the underlying HTTP transport and SOAP envelope creation.
        wsman = WSMan(
            server=target_ip,
            port=5985,
            username=auth_username,
            password=password,
            ssl=False,
            auth="ntlm",
            encryption="auto",
            connection_timeout=30,
            read_timeout=30,
        )
        
        # Open a RunspacePool, which represents a PowerShell execution environment.
        # The context manager ensures proper cleanup of the remote session.
        with RunspacePool(wsman) as pool:
            # RunspacePool opened successfully - authentication has passed.
            if status_callback:
                status_callback("Authenticated, preparing command...")
            
            # Create a PowerShell pipeline to execute commands within the runspace.
            ps = PowerShell(pool)
            
            if script_path:
                # Read the script content from the local file system.
                if verbose:
                    print(f"[*] Reading local script: {script_path}")
                with open(script_path, 'r') as file:
                    script_content = file.read()
                
                # Wrap the script in a scriptblock and invoke it with arguments.
                # The syntax "& { <script> } <args>" creates an anonymous scriptblock
                # and immediately invokes it with the provided arguments.
                if script_args:
                    full_script = f"& {{{script_content}}} {script_args}"
                else:
                    full_script = script_content
                
                # Add the script to the PowerShell pipeline.
                # pypsrp streams the script content properly directly into the pipeline.
                ps.add_script(full_script)
                
            elif command:
                # For simple commands, add them directly to the pipeline.
                if verbose:
                    print(f"[*] Executing command: {command}")
                ps.add_script(command)
            else:
                raise ValueError("Either --script or --command must be provided.")
            
            if verbose:
                print(f"[*] Executing on {target_ip} via WinRM (pypsrp)...")
            
            # Execute the PowerShell pipeline on the remote host.
            # This blocks until the script completes or an error occurs.
            if status_callback:
                status_callback("Executing...")
            ps.invoke()
            
            if verbose:
                print(f"[+] Command executed, had_errors: {ps.had_errors}")
            
            # Collect output from all PowerShell streams.
            # PowerShell has multiple output streams for different types of messages.
            output_lines = []
            
            # The main Output stream contains objects written with Write-Output
            # or returned from the script (implicit output).
            for item in ps.output:
                output_lines.append(str(item))
            
            # The Information stream (PowerShell 5.0+) contains messages from Write-Host.
            # Prior to PS5, Write-Host went directly to the console and was not capturable.
            if hasattr(ps, 'streams') and ps.streams.information:
                for info in ps.streams.information:
                    output_lines.append(str(info.message_data))
            
            # The Warning stream contains messages from Write-Warning.
            if hasattr(ps, 'streams') and ps.streams.warning:
                for warning in ps.streams.warning:
                    output_lines.append(f"WARNING: {warning}")
            
            # The Error stream contains non-terminating errors from Write-Error
            # and other error conditions that did not halt script execution.
            if hasattr(ps, 'streams') and ps.streams.error:
                for error in ps.streams.error:
                    output_lines.append(f"ERROR: {error}")
            
            if verbose:
                print(f"[+] Output: {output_lines}")
            
            # Return all collected output as a single newline-separated string.
            return "\n".join(output_lines)
            
    except Exception as e:
        error_str = str(e).lower()
        
        # Check if the exception indicates an authentication failure.
        # These patterns cover common authentication error messages from WinRM.
        if any(auth_err in error_str for auth_err in [
            "unauthorized", "401", "authentication", "logon_failure",
            "access_denied", "invalid credentials", "kerberos", "ntlm",
            "denied", "rejected"
        ]):
            if verbose:
                print(f"[!] WinRM authentication failed: {e}")
            raise WinRMAuthenticationError(f"Authentication failed for {username}@{target_ip}: {e}")
        
        # Check if the exception indicates a connection failure.
        # These patterns cover network-level errors.
        if any(conn_err in error_str for conn_err in [
            "connection", "timeout", "refused", "unreachable", "reset"
        ]):
            if verbose:
                print(f"[!] WinRM connection failed: {e}")
            raise WinRMConnectionError(f"Connection failed to {target_ip}: {e}")
        
        # For any other exception, log it in verbose mode and re-raise.
        if verbose:
            print(f"[!] WinRM execution failed: {e}")
        raise


def run_winrm_copy(target_ip, username, password, domain="", source="", dest="", verbose=False, status_callback=None):
    """
    Copy a local file or directory to a remote Windows host using WinRM/PSRP.
    
    This function uses the pypsrp library's Client class to upload files via
    the PowerShell Remoting Protocol. It supports both single file uploads
    and recursive directory uploads.
    
    Args:
        target_ip: The IP address or hostname of the remote Windows machine.
        username: The username for authentication (can be in DOMAIN\\username format).
        password: The password for authentication.
        domain: Optional domain name for domain-joined authentication.
        source: Path to the local file or directory to copy.
        dest: Remote destination as a local Windows path (e.g., "C:\\Windows\\Temp\\file.exe").
        verbose: If True, print detailed status messages during execution.
        status_callback: Optional callable(message) to report execution progress.
    
    Returns:
        A string containing a success message with files/bytes transferred.
    
    Raises:
        WinRMConnectionError: If the connection to the target host fails.
        WinRMAuthenticationError: If authentication fails due to invalid credentials.
        FileNotFoundError: If the source file/directory does not exist.
    """
    
    # Perform a quick connectivity check before attempting WinRM.
    if not check_port_open(target_ip, 5985, timeout=5):
        raise WinRMConnectionError(f"Port 5985 not reachable on {target_ip}")
    
    # Validate source exists
    if not os.path.exists(source):
        raise FileNotFoundError(f"Source not found: {source}")
    
    # Construct the authentication username.
    if domain:
        auth_username = f"{domain}\\{username}"
    else:
        auth_username = username
    
    try:
        # Create a pypsrp Client for file operations - must use as context manager
        with Client(
            target_ip,
            username=auth_username,
            password=password,
            port=5985,
            ssl=False,
            auth="ntlm",
            encryption="auto",
            connection_timeout=30,
            read_timeout=30,
        ) as client:
            # Check if source is a file or directory
            if os.path.isfile(source):
                # Single file copy - mimic SMB behavior
                if status_callback:
                    status_callback("Copying 1 file...")
                file_size = os.path.getsize(source)
                
                # Normalize destination path and parse like SMB does
                dest_normalized = dest.replace('/', '\\').lstrip('\\')
                
                # Extract drive letter and path (e.g., "C:\path" -> drive="C:", path="path")
                if len(dest_normalized) >= 2 and dest_normalized[1] == ':':
                    drive = dest_normalized[:2]  # "C:"
                    path_after_drive = dest_normalized[3:] if len(dest_normalized) > 3 else ""
                    
                    # If path after drive is empty (just "C:\"), use source filename
                    # This mimics SMB behavior: remote_path = remote_base_path if remote_base_path else os.path.basename(source)
                    if path_after_drive:
                        remote_path = dest_normalized
                    else:
                        remote_path = drive + '\\' + os.path.basename(source)
                else:
                    # No drive letter, use as-is
                    remote_path = dest_normalized if dest_normalized else os.path.basename(source)
                
                if verbose:
                    print(f"[*] Uploading {source} ({file_size} bytes) to {target_ip}:{remote_path}...")
                
                # client.copy() takes file paths as strings, not file objects
                client.copy(source, remote_path)
                
                if status_callback:
                    status_callback("Copying 1/1 files...")
                
                if verbose:
                    print(f"[+] File copied successfully: {file_size} bytes")
                
                return f"Copied {os.path.basename(source)} ({file_size} bytes) to {target_ip}:{remote_path}"
            
            else:
                # Directory copy - recursive
                # Note: pypsrp Client doesn't maintain connection well across multiple copy() calls
                # So we handle directory copy outside the context manager
                pass
        
        # Directory copy - need to handle separately due to pypsrp connection issues
        if os.path.isdir(source):
            if status_callback:
                status_callback("Scanning directory...")
            
            total_files = 0
            total_bytes = 0
            
            # Normalize destination path
            dest_normalized = dest.replace('/', '\\').rstrip('\\')
            
            # Collect all directories to create and files to copy
            dirs_to_create = []
            files_to_copy = []
            
            for root, dirs, files in os.walk(source):
                rel_root = os.path.relpath(root, source)
                if rel_root == ".":
                    rel_root = ""
                
                if rel_root:
                    remote_dir = dest_normalized + "\\" + rel_root.replace('/', '\\')
                else:
                    remote_dir = dest_normalized
                
                if remote_dir and remote_dir not in dirs_to_create:
                    dirs_to_create.append(remote_dir)
                
                for filename in files:
                    local_file_path = os.path.join(root, filename)
                    if remote_dir:
                        remote_file_path = remote_dir + "\\" + filename
                    else:
                        remote_file_path = filename
                    files_to_copy.append((local_file_path, remote_file_path))
            
            # Create all directories first with a single client connection
            if status_callback:
                status_callback(f"Creating directories, 0/{len(files_to_copy)} files copied...")
            if dirs_to_create:
                with Client(
                    target_ip,
                    username=auth_username,
                    password=password,
                    port=5985,
                    ssl=False,
                    auth="ntlm",
                    encryption="auto",
                    connection_timeout=30,
                    read_timeout=30,
                ) as client:
                    for remote_dir in dirs_to_create:
                        remote_dir_escaped = remote_dir.replace("'", "''")
                        mkdir_script = f"New-Item -ItemType Directory -Path '{remote_dir_escaped}' -Force | Out-Null"
                        try:
                            client.execute_ps(mkdir_script)
                            if verbose:
                                print(f"[*] Created directory: {remote_dir}")
                        except Exception:
                            pass
            
            # Copy each file with a fresh client connection
            total_file_count = len(files_to_copy)
            if status_callback:
                status_callback(f"Copying 0/{total_file_count} files...")
            for local_file_path, remote_file_path in files_to_copy:
                file_size = os.path.getsize(local_file_path)
                
                if verbose:
                    print(f"[*] Uploading {local_file_path} ({file_size} bytes) to {target_ip}:{remote_file_path}...")
                
                with Client(
                    target_ip,
                    username=auth_username,
                    password=password,
                    port=5985,
                    ssl=False,
                    auth="ntlm",
                    encryption="auto",
                    connection_timeout=30,
                    read_timeout=30,
                ) as client:
                    client.copy(local_file_path, remote_file_path)
                
                total_files += 1
                total_bytes += file_size
                
                if status_callback:
                    status_callback(f"Copying {total_files}/{total_file_count} files...")
            
            if verbose:
                print(f"[+] Directory copied successfully: {total_files} files, {total_bytes} bytes")
            
            return f"Copied {total_files} file(s) ({total_bytes} bytes) to {target_ip}:{dest_normalized}"
        
        # Source exists but is neither a file nor a directory (e.g., socket, FIFO, device file)
        raise ValueError(f"Source '{source}' exists but is neither a regular file nor a directory")
    
    except Exception as e:
        error_str = str(e).lower()
        
        # Check if this is a file/path access error (not an auth error)
        # These errors occur after successful authentication
        if "failed to copy file" in error_str or "access to the path" in error_str:
            if verbose:
                print(f"[!] WinRM copy failed: {e}")
            raise
        
        # Check if the exception indicates an authentication failure.
        # Be specific to avoid misclassifying file access errors
        if any(auth_err in error_str for auth_err in [
            "failed to authenticate", "unauthorized", "401", "logon_failure",
            "invalid credentials", "credentials were rejected"
        ]):
            if verbose:
                print(f"[!] WinRM authentication failed: {e}")
            raise WinRMAuthenticationError(f"Authentication failed for {username}@{target_ip}: {e}")
        
        # Check if the exception indicates a connection failure.
        if any(conn_err in error_str for conn_err in [
            "connection", "timeout", "refused", "unreachable", "reset"
        ]):
            if verbose:
                print(f"[!] WinRM connection failed: {e}")
            raise WinRMConnectionError(f"Connection failed to {target_ip}: {e}")
        
        # For any other exception, log it in verbose mode and re-raise.
        if verbose:
            print(f"[!] WinRM copy failed: {e}")
        raise


def run_winrm_download(target_ip, username, password, domain="", source="", dest="", verbose=False, status_callback=None):
    """
    Download a file or directory from a remote Windows host to the local system using WinRM/PSRP.
    
    This function uses the pypsrp library's Client class to download files via
    the PowerShell Remoting Protocol. It supports both single file downloads
    and recursive directory downloads.
    
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
        WinRMConnectionError: If the connection to the target host fails.
        WinRMAuthenticationError: If authentication fails due to invalid credentials.
    """
    
    # Perform a quick connectivity check before attempting WinRM.
    if not check_port_open(target_ip, 5985, timeout=5):
        raise WinRMConnectionError(f"Port 5985 not reachable on {target_ip}")
    
    # Construct the authentication username.
    if domain:
        auth_username = f"{domain}\\{username}"
    else:
        auth_username = username
    
    # Normalize the remote source path
    source_normalized = source.replace('/', '\\')
    
    try:
        # First, determine if the remote source is a file or directory using PowerShell
        if status_callback:
            status_callback("Checking remote path...")
        
        with Client(
            target_ip,
            username=auth_username,
            password=password,
            port=5985,
            ssl=False,
            auth="ntlm",
            encryption="auto",
            connection_timeout=30,
            read_timeout=30,
        ) as client:
            # Check if the remote path is a directory
            # Escape single quotes for safe embedding in PowerShell single-quoted strings
            source_escaped = source_normalized.replace("'", "''")
            check_script = f"if (Test-Path -LiteralPath '{source_escaped}' -PathType Container) {{ 'DIRECTORY' }} elseif (Test-Path -LiteralPath '{source_escaped}' -PathType Leaf) {{ 'FILE' }} else {{ 'NOTFOUND' }}"
            output, streams, had_errors = client.execute_ps(check_script)
            path_type = output.strip()
        
        if path_type == 'NOTFOUND':
            raise FileNotFoundError(f"Remote path not found: {source}")
        
        if path_type == 'FILE':
            # Single file download
            if status_callback:
                status_callback("Downloading 0/1 files...")
            
            # If dest is an existing directory, append the source filename
            if os.path.isdir(dest):
                dest = os.path.join(dest, os.path.basename(source_normalized))
            
            # Ensure local destination directory exists
            dest_dir = os.path.dirname(dest)
            if dest_dir:
                os.makedirs(dest_dir, exist_ok=True)
            
            if verbose:
                print(f"[*] Downloading {target_ip}:{source_normalized} to {dest}...")
            
            with Client(
                target_ip,
                username=auth_username,
                password=password,
                port=5985,
                ssl=False,
                auth="ntlm",
                encryption="auto",
                connection_timeout=30,
                read_timeout=30,
            ) as client:
                client.fetch(source_normalized, dest)
            
            file_size = os.path.getsize(dest)
            
            if status_callback:
                status_callback("Downloading 1/1 files...")
            
            if verbose:
                print(f"[+] File downloaded successfully: {file_size} bytes")
            
            return f"Downloaded {os.path.basename(source_normalized)} ({file_size} bytes) from {target_ip}:{source_normalized}"
        
        else:
            # Directory download - recursive
            if status_callback:
                status_callback("Enumerating remote directory...")
            
            # Use PowerShell to enumerate all files and directories recursively
            # Returns tab-separated lines: RelativePath\tType (File or Directory)
            # Escape single quotes for safe embedding in PowerShell single-quoted strings
            source_escaped = source_normalized.replace("'", "''")
            enum_script = (
                f"Get-ChildItem -LiteralPath '{source_escaped}' -Recurse -Force | "
                f"ForEach-Object {{ "
                f"$rel = $_.FullName.Substring('{source_escaped}'.Length).TrimStart('\\'); "
                f"$type = if ($_.PSIsContainer) {{ 'D' }} else {{ 'F' }}; "
                f"\"$rel`t$type\" }}"
            )
            
            with Client(
                target_ip,
                username=auth_username,
                password=password,
                port=5985,
                ssl=False,
                auth="ntlm",
                encryption="auto",
                connection_timeout=30,
                read_timeout=30,
            ) as client:
                output, streams, had_errors = client.execute_ps(enum_script)
            
            # Check for PowerShell errors during enumeration
            if had_errors:
                error_messages = []
                if streams and streams.error:
                    error_messages = [str(err) for err in streams.error]
                error_detail = "; ".join(error_messages) if error_messages else "Unknown error"
                raise RuntimeError(f"Failed to enumerate remote directory '{source_normalized}': {error_detail}")
            
            # Parse enumeration results
            dirs_to_create = []
            files_to_download = []
            
            if output and output.strip():
                for line in output.strip().split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split('\t')
                    if len(parts) != 2:
                        continue
                    rel_path, entry_type = parts[0].strip(), parts[1].strip()
                    if entry_type == 'D':
                        dirs_to_create.append(rel_path)
                    elif entry_type == 'F':
                        files_to_download.append(rel_path)
            
            if not dirs_to_create and not files_to_download:
                if verbose:
                    print(f"[*] Remote directory is empty: {source_normalized}")
                return f"Remote directory is empty: {target_ip}:{source_normalized}"
            
            # Create local directory structure
            os.makedirs(dest, exist_ok=True)
            for rel_dir in dirs_to_create:
                local_dir = os.path.join(dest, rel_dir)
                os.makedirs(local_dir, exist_ok=True)
                if verbose:
                    print(f"[*] Created local directory: {local_dir}")
            
            # Download each file
            total_files = 0
            total_bytes = 0
            total_file_count = len(files_to_download)
            
            if status_callback:
                status_callback(f"Downloading 0/{total_file_count} files...")
            
            # Normalize source path to avoid duplicate backslashes when joining
            source_normalized = source_normalized.rstrip('\\')
            
            for rel_file in files_to_download:
                remote_file_path = source_normalized + '\\' + rel_file
                local_file_path = os.path.join(dest, rel_file)
                
                # Ensure parent directory exists
                local_file_dir = os.path.dirname(local_file_path)
                if local_file_dir:
                    os.makedirs(local_file_dir, exist_ok=True)
                
                if verbose:
                    print(f"[*] Downloading {target_ip}:{remote_file_path} to {local_file_path}...")
                
                with Client(
                    target_ip,
                    username=auth_username,
                    password=password,
                    port=5985,
                    ssl=False,
                    auth="ntlm",
                    encryption="auto",
                    connection_timeout=30,
                    read_timeout=30,
                ) as client:
                    client.fetch(remote_file_path, local_file_path)
                
                file_size = os.path.getsize(local_file_path)
                total_files += 1
                total_bytes += file_size
                
                if status_callback:
                    status_callback(f"Downloading {total_files}/{total_file_count} files...")
            
            if verbose:
                print(f"[+] Directory downloaded successfully: {total_files} files, {total_bytes} bytes")
            
            return f"Downloaded {total_files} file(s) ({total_bytes} bytes) from {target_ip}:{source_normalized}"
    
    except Exception as e:
        error_str = str(e).lower()
        
        # Check if this is a file/path access error (not an auth error)
        if "failed to fetch file" in error_str or "access to the path" in error_str:
            if verbose:
                print(f"[!] WinRM download failed: {e}")
            raise
        
        # Check if the exception indicates an authentication failure.
        if any(auth_err in error_str for auth_err in [
            "failed to authenticate", "unauthorized", "401", "logon_failure",
            "invalid credentials", "credentials were rejected"
        ]):
            if verbose:
                print(f"[!] WinRM authentication failed: {e}")
            raise WinRMAuthenticationError(f"Authentication failed for {username}@{target_ip}: {e}")
        
        # Check if the exception indicates a connection failure.
        if any(conn_err in error_str for conn_err in [
            "connection", "timeout", "refused", "unreachable", "reset"
        ]):
            if verbose:
                print(f"[!] WinRM connection failed: {e}")
            raise WinRMConnectionError(f"Connection failed to {target_ip}: {e}")
        
        # For any other exception, log it in verbose mode and re-raise.
        if verbose:
            print(f"[!] WinRM download failed: {e}")
        raise
