import socket
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan


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


def run_winrm(target_ip, username, password, domain="", script_path=None, command=None, script_args="", verbose=False):
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
