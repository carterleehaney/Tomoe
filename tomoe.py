import argparse
import logging
import os
import time
from os.path import isfile, isdir, exists
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from threading import Lock, Thread, Event
from dataclasses import dataclass
from typing import Optional
from rich.console import Console
from rich.live import Live
from rich.table import Table

from smb import run_psexec, run_smb_copy, run_smb_download
from wsman import run_winrm, run_winrm_copy, run_winrm_download
from ssh import run_ssh, run_ssh_copy, run_ssh_download


@dataclass
class HostResult:
    """Result of execution on a single host."""
    host: str
    success: bool
    username: Optional[str] = None
    message: str = ""
    output: str = ""


@dataclass
class HostStatus:
    """Current status of execution on a host."""
    host: str
    status: str  # "pending", "trying", "success", "failed"
    current_user: str = "-"
    message: str = "Waiting..."


def parse_target_or_file(value: str) -> list[str]:
    """Parse argument as file path or literal value.
    
    If the value is a path to an existing file, read each line as a separate entry.
    Otherwise, treat the value as a literal string.
    """
    if isfile(value):
        with open(value, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    return [value]


def create_status_table(host_statuses: dict[str, HostStatus]) -> Table:
    """Create a Rich table showing current status of all hosts."""
    table = Table(title="Tomoe")
    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("Status", style="bold")
    table.add_column("Username", style="magenta")
    table.add_column("Message", style="dim")
    
    for host, status in host_statuses.items():
        if status.status == "success":
            status_style = "[green]Success[/green]"
        elif status.status == "failed":
            status_style = "[red]Failed[/red]"
        elif status.status == "trying":
            status_style = "[yellow]Trying...[/yellow]"
        else:
            status_style = "[dim]Pending[/dim]"
        
        table.add_row(
            status.host,
            status_style,
            status.current_user,
            status.message
        )
    
    return table


def execute_on_host(
    host: str,
    usernames: list[str],
    passwords: list[str],
    domain: str,
    protocol: str,
    script_path: Optional[str],
    command: Optional[str],
    script_args: str,
    verbose: bool,
    host_statuses: dict[str, HostStatus],
    status_lock: Lock,
    source: Optional[str] = None,
    dest: Optional[str] = None,
    target_os: str = "windows",
    download: bool = False,
    shell_type: str = "powershell",
    encrypt: bool = True
) -> HostResult:
    """Execute command on a single host, trying credential permutations until success."""
    
    def update_status(status: str, user: str = "-", message: str = ""):
        with status_lock:
            host_statuses[host] = HostStatus(
                host=host,
                status=status,
                current_user=user,
                message=message
            )
    
    update_status("trying", "-", "Starting...")
    
    for username in usernames:
        for password in passwords:
            update_status("trying", username, f"Authenticating...")
            
            # Create a status callback that updates the live display with
            # progress messages from the protocol functions.
            def make_status_callback(user):
                def callback(message):
                    update_status("trying", user, message)
                return callback
            
            status_callback = make_status_callback(username)
            
            try:
                # Download operation (remote -> local)
                if protocol == "smb" and source and dest and download:
                    output = run_smb_download(
                        target_ip=host,
                        username=username,
                        password=password,
                        domain=domain,
                        source=source,
                        dest=dest,
                        verbose=verbose,
                        status_callback=status_callback,
                    )
                    update_status("success", username, "File downloaded.")
                    return HostResult(
                        host=host,
                        success=True,
                        username=username,
                        message="File downloaded successfully.",
                        output=output
                    )
                elif protocol == "winrm" and source and dest and download:
                    output = run_winrm_download(
                        target_ip=host,
                        username=username,
                        password=password,
                        domain=domain,
                        source=source,
                        dest=dest,
                        verbose=verbose,
                        status_callback=status_callback,
                    )
                    update_status("success", username, "File downloaded.")
                    return HostResult(
                        host=host,
                        success=True,
                        username=username,
                        message="File downloaded successfully.",
                        output=output
                    )
                # Upload operation (local -> remote)
                elif protocol == "smb" and source and dest:
                    output = run_smb_copy(
                        target_ip=host,
                        username=username,
                        password=password,
                        domain=domain,
                        source=source,
                        dest=dest,
                        verbose=verbose,
                        status_callback=status_callback,
                    )
                    update_status("success", username, "File uploaded.")
                    return HostResult(
                        host=host,
                        success=True,
                        username=username,
                        message="File uploaded successfully.",
                        output=output
                    )
                elif protocol == "smb":
                    output = run_psexec(
                        target_ip=host,
                        username=username,
                        password=password,
                        domain=domain,
                        script_path=script_path,
                        command=command,
                        script_args=script_args,
                        verbose=verbose,
                        status_callback=status_callback,
                        shell_type=shell_type,
                        encrypt=encrypt
                    )
                elif protocol == "winrm" and source and dest:
                    output = run_winrm_copy(
                        target_ip=host,
                        username=username,
                        password=password,
                        domain=domain,
                        source=source,
                        dest=dest,
                        verbose=verbose,
                        status_callback=status_callback,
                    )
                    update_status("success", username, "File uploaded.")
                    return HostResult(
                        host=host,
                        success=True,
                        username=username,
                        message="File uploaded successfully.",
                        output=output
                    )
                elif protocol == "winrm":
                    output = run_winrm(
                        target_ip=host,
                        username=username,
                        password=password,
                        domain=domain,
                        script_path=script_path,
                        command=command,
                        script_args=script_args,
                        verbose=verbose,
                        status_callback=status_callback,
                    )
                elif protocol == "ssh" and source and dest and download:
                    output = run_ssh_download(
                        target_ip=host,
                        username=username,
                        password=password,
                        domain=domain,
                        source=source,
                        dest=dest,
                        verbose=verbose,
                        status_callback=status_callback,
                        target_os=target_os,
                    )
                    update_status("success", username, "File downloaded.")
                    return HostResult(
                        host=host,
                        success=True,
                        username=username,
                        message="File downloaded successfully.",
                        output=output
                    )
                elif protocol == "ssh" and source and dest:
                    output = run_ssh_copy(
                        target_ip=host,
                        username=username,
                        password=password,
                        domain=domain,
                        source=source,
                        dest=dest,
                        verbose=verbose,
                        status_callback=status_callback,
                        target_os=target_os,
                    )
                    update_status("success", username, "File copied.")
                    return HostResult(
                        host=host,
                        success=True,
                        username=username,
                        message="File copied successfully.",
                        output=output
                    )
                elif protocol == "ssh":
                    output = run_ssh(
                        target_ip=host,
                        username=username,
                        password=password,
                        domain=domain,
                        script_path=script_path,
                        command=command,
                        script_args=script_args,
                        verbose=verbose,
                        status_callback=status_callback,
                        target_os=target_os,
                    )
                
                # Success!
                update_status("success", username, "Command executed.")
                return HostResult(
                    host=host,
                    success=True,
                    username=username,
                    message="Command executed successfully.",
                    output=output
                )
                
            except Exception as e:
                error_msg = str(e).lower()
                # Check if it's an authentication error - try next credential. This might need to include more in the future.
                auth_error_patterns = [
                    "logon_failure", "access_denied", "authentication", 
                    "login failed", "invalid credentials", "unauthorized",
                    "status_logon_failure", "kerberos", "credentials were rejected",
                    "bad password", "wrong password", "access is denied",
                    "rejected", "401"
                ]
                if any(auth_err in error_msg for auth_err in auth_error_patterns):
                    update_status("trying", username, f"Authentication failed, trying next.")
                    continue
                else:
                    # Non-auth error - report and stop trying this host.
                    update_status("failed", username, str(e)[:50])
                    return HostResult(
                        host=host,
                        success=False,
                        username=username,
                        message=str(e)
                    )
    
    # All credentials exhausted.
    update_status("failed", "-", "Invalid credentials.")
    return HostResult(
        host=host,
        success=False,
        message="Invalid credentials."
    )


def run_concurrent_execution(
    hosts: list[str],
    usernames: list[str],
    passwords: list[str],
    domain: str,
    protocol: str,
    script_path: Optional[str],
    command: Optional[str],
    script_args: str,
    verbose: bool,
    max_workers: int = 10,
    source: Optional[str] = None,
    dest: Optional[str] = None,
    target_os: str = "windows",
    download: bool = False,
    shell_type: str = "powershell",
    encrypt: bool = True
) -> list[HostResult]:
    """Run execution concurrently across all hosts with live status display."""
    
    console = Console()
    status_lock = Lock()
    stop_event = Event()
    
    # Initialize status for all hosts.
    host_statuses: dict[str, HostStatus] = {
        host: HostStatus(host=host, status="pending", message="Waiting...")
        for host in hosts
    }
    
    results: list[HostResult] = []
    
    def update_display(live: Live):
        """Background thread to continuously update the display."""
        while not stop_event.is_set():
            with status_lock:
                live.update(create_status_table(host_statuses))
            time.sleep(0.25)
    
    with Live(create_status_table(host_statuses), console=console, refresh_per_second=4) as live:
        # Start background display updater.
        display_thread = Thread(target=update_display, args=(live,), daemon=True)
        display_thread.start()
        
        try:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(hosts))) as executor:
                # For multi-host downloads, create per-host subdirectories
                # to prevent files from overwriting each other.
                use_host_subdirs = download and source and dest and len(hosts) > 1
                
                if use_host_subdirs:
                    for host in hosts:
                        os.makedirs(os.path.join(dest, host), exist_ok=True)
                
                # Submit all host tasks.
                future_to_host = {
                    executor.submit(
                        execute_on_host,
                        host,
                        usernames,
                        passwords,
                        domain,
                        protocol,
                        script_path,
                        command,
                        script_args,
                        verbose,
                        host_statuses,
                        status_lock,
                        source,
                        os.path.join(dest, host) if use_host_subdirs else dest,
                        target_os,
                        download,
                        shell_type,
                        encrypt
                    ): host
                    for host in hosts
                }
                
                # Wait for all futures with polling to allow keyboard interrupt.
                pending = set(future_to_host.keys())
                while pending:
                    done, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                    for future in done:
                        host = future_to_host[future]
                        try:
                            result = future.result()
                            results.append(result)
                        except Exception as e:
                            # Handle unexpected errors.
                            with status_lock:
                                host_statuses[host] = HostStatus(
                                    host=host,
                                    status="failed",
                                    message=f"Unexpected error: {str(e)[:40]}"
                                )
                            results.append(HostResult(
                                host=host,
                                success=False,
                                message=f"Unexpected error: {e}"
                            ))
        finally:
            stop_event.set()
            display_thread.join(timeout=1)
            # Final update to show completed states.
            live.update(create_status_table(host_statuses))
    
    return results


def print_results(results: list[HostResult], console: Console):
    """Print final results after execution."""
    console.print("\nExecution Results\n")
    
    for result in results:
        if result.success:
            console.print(f"[green]✓[/green] [cyan]{result.host}[/cyan] - Success (user: {result.username})")
            if result.output:
                console.print(f"  [dim]Output:[/dim]")
                for line in result.output.strip().split('\n'):
                    console.print(f"    {line}")
                console.print()
        else:
            console.print(f"[red]✗[/red] [cyan]{result.host}[/cyan] - Failed: {result.message}")
    
    # Summary.
    success_count = sum(1 for r in results if r.success)
    console.print(f"\n[bold]Summary:[/bold] {success_count}/{len(results)} hosts successful")


def write_output_files(results: list[HostResult], output_dir: str, console: Console):
    """Write output files for successful hosts to the specified directory."""
    import os
    
    os.makedirs(output_dir, exist_ok=True)
    
    written_count = 0
    for result in results:
        if result.success and result.output:
            file_path = os.path.join(output_dir, f"{result.host}.txt")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(result.output)
            written_count += 1
    
    console.print(f"[bold]Output:[/bold] Wrote {written_count} file(s) to {output_dir}/")


if __name__ == "__main__":
    # Parse arguments.
    parser = argparse.ArgumentParser(
        usage="tomoe.py {smb, winrm, ssh} -i <ip/file> -u <username/file> -p <password/file> [--script <script> | --command <command> | --upload <source> <dest> | --download <source> <dest>]",
        description="Tomoe is a python utility for remote administration over multiple protocols in case of fail-over."
    )
    parser.add_argument("protocol", choices=["smb", "winrm", "ssh"], help="protocol to use for remote administration")
    parser.add_argument("-i", metavar="IP", required=True, help="target host IP/hostname or path to file with targets (one per line)")
    parser.add_argument("-d", "--domain", default="", help="domain of selected user")
    parser.add_argument("-u", "--username", required=True, help="username or path to file with usernames (one per line)")
    parser.add_argument("-p", "--password", required=True, help="password or path to file with passwords (one per line)")

    parser.add_argument("--os", choices=["windows", "linux"], default="windows", dest="target_os",
                        help="target host OS (default: windows). Only applies to SSH protocol.")

    # Script or Command; but never both.
    exec_group = parser.add_mutually_exclusive_group(required=False)
    exec_group.add_argument("-s", "--script", help="local path to script to execute (PowerShell on Windows, bash on Linux)")
    exec_group.add_argument("-c", "--command", help="command to execute (PowerShell on Windows, shell on Linux)")
    
    # File transfer (mutually exclusive: --upload or --download, each takes source + dest).
    transfer_group = parser.add_mutually_exclusive_group(required=False)
    transfer_group.add_argument("--upload", nargs=2, metavar=("SOURCE", "DEST"), help="upload local SOURCE to remote DEST")
    transfer_group.add_argument("--download", nargs=2, metavar=("SOURCE", "DEST"), help="download remote SOURCE to local DEST")
    
    # Arguments to pass to the script.
    parser.add_argument("-a", "--args", default="", help="arguments to pass to the script")
    parser.add_argument("--shell", choices=["powershell", "cmd"], default="powershell", help="shell type for SMB protocol (default: powershell)")
    parser.add_argument("--no-encrypt", dest="encrypt", action="store_false", default=True, help="disable SMB encryption (encryption is enabled by default)")
    parser.add_argument("-v", "--verbose", action="store_true", help="show verbose status messages")
    parser.add_argument("-t", "--threads", type=int, default=10, help="maximum concurrent threads (default: 10)")
    parser.add_argument("-o", "--output", metavar="DIR", help="output directory to create for per-host result files")

    args = parser.parse_args()
    
    # Validate --os is only used with ssh protocol.
    if args.target_os == "linux" and args.protocol != "ssh":
        parser.error("--os linux is only supported with the ssh protocol")
    
    # Validate protocol-specific arguments.
    if args.protocol != "smb" and args.shell != "powershell":
        parser.error("--shell is only supported when --protocol smb; for winrm and ssh, PowerShell is always used")
    
    # Extract source/dest and download flag from the parsed arguments.
    source = None
    dest = None
    is_download = False
    
    if args.upload:
        source, dest = args.upload
        if args.script or args.command:
            parser.error("--upload cannot be used with --script or --command")
        if not exists(source):
            parser.error(f"local source not found: {source}")
    elif args.download:
        source, dest = args.download
        is_download = True
        if args.script or args.command:
            parser.error("--download cannot be used with --script or --command")
        # Validate the local destination's parent directory exists
        dest_parent = os.path.dirname(os.path.abspath(dest))
        if not exists(dest_parent):
            parser.error(f"local destination parent directory not found: {dest_parent}")
    else:
        # Command execution mode
        if not args.script and not args.command:
            parser.error("either --script, --command, --upload, or --download is required")
    
    # Set logging level based on verbose flag.
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.CRITICAL)

    # Parse targets, usernames, and passwords (file or literal).
    hosts = parse_target_or_file(args.i)
    usernames = parse_target_or_file(args.username)
    passwords = parse_target_or_file(args.password)
    
    # Validate that we have at least one host, username, and password.
    if not hosts:
        parser.error(f"no hosts found in '{args.i}' (file is empty or contains only whitespace)")
    if not usernames:
        parser.error(f"no usernames found in '{args.username}' (file is empty or contains only whitespace)")
    if not passwords:
        parser.error(f"no passwords found in '{args.password}' (file is empty or contains only whitespace)")
    
    console = Console()
    console.print()
    console.print(f"  Targets: {len(hosts)} host(s)")
    console.print(f"  Credentials: {len(usernames)} user(s) x {len(passwords)} password(s)")
    console.print(f"  Protocol: {args.protocol}")
    if args.upload:
        console.print(f"  Operation: Upload {source} -> {dest}")
    elif args.download:
        console.print(f"  Operation: Download {source} -> {dest}")
        if len(hosts) > 1:
            console.print(f"  Note: Per-host subdirectories will be created under {dest}")
    console.print()

    # Run concurrent execution.
    results = run_concurrent_execution(
        hosts=hosts,
        usernames=usernames,
        passwords=passwords,
        domain=args.domain,
        protocol=args.protocol,
        script_path=args.script,
        command=args.command,
        script_args=args.args,
        verbose=args.verbose,
        max_workers=args.threads,
        source=source,
        dest=dest,
        target_os=args.target_os,
        download=is_download,
        shell_type=args.shell,
        encrypt=args.encrypt
    )
    
    # Print final results.
    print_results(results, console)
    
    # Write output files if output directory specified.
    if args.output:
        write_output_files(results, args.output, console)
