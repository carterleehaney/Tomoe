import argparse
import ipaddress
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
from rich.text import Text
from rich.panel import Panel

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


def expand_target(value: str) -> list[str]:
    """Expand a single target value into a list of IP addresses.

    Supports CIDR notation (e.g. 192.168.1.0/24) and IP ranges using a dash
    in the last octet (e.g. 192.168.1.1-50). Plain hostnames and single IPs
    are returned as-is.
    """
    # CIDR notation (e.g. 192.168.1.0/24)
    if '/' in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
            # For /32 or /128 (single host), just return the address
            if network.num_addresses <= 1:
                return [str(network.network_address)]
            # Return all usable host addresses (excludes network and broadcast)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            pass  # Not a valid CIDR — treat as literal (could be a path)

    # Dash-range in last octet (e.g. 192.168.1.1-50)
    if '-' in value:
        parts = value.rsplit('.', 1)
        if len(parts) == 2 and '-' in parts[1]:
            try:
                prefix = parts[0]
                start_str, end_str = parts[1].split('-', 1)
                start, end = int(start_str), int(end_str)
                if 0 <= start <= 255 and 0 <= end <= 255 and start <= end:
                    # Validate that the prefix forms a valid base
                    ipaddress.ip_address(f"{prefix}.{start}")
                    return [f"{prefix}.{i}" for i in range(start, end + 1)]
            except (ValueError, IndexError):
                pass  # Not a valid range — treat as literal

    return [value]


def parse_target_or_file(value: str) -> list[str]:
    """Parse argument as file path or literal value.

    If the value is a path to an existing file, read each line as a separate entry.
    Otherwise, treat the value as a literal string.

    Each entry is then expanded for CIDR notation or IP ranges.
    """
    if isfile(value):
        with open(value, 'r') as f:
            entries = [line.strip() for line in f if line.strip()]
    else:
        entries = [value]

    # Expand any CIDR or range notation in each entry
    result = []
    for entry in entries:
        result.extend(expand_target(entry))
    return result


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


def create_compact_display(host_statuses: dict[str, HostStatus]) -> Panel:
    """Create a compact display showing a progress bar and status counts.

    Used when the number of hosts exceeds the terminal height.
    """
    total = len(host_statuses)
    counts = {"success": 0, "failed": 0, "trying": 0, "pending": 0}

    for status in host_statuses.values():
        counts[status.status] = counts.get(status.status, 0) + 1

    completed = counts["success"] + counts["failed"]
    bar_width = 30
    filled = int((completed / total) * bar_width) if total > 0 else 0
    bar = f"[green]{'█' * filled}[/green][dim]{'░' * (bar_width - filled)}[/dim]"

    summary = (
        f"  {bar}  [{completed}/{total}]  "
        f"[green]{counts['success']} success[/green] · "
        f"[red]{counts['failed']} failed[/red] · "
        f"[yellow]{counts['trying']} active[/yellow] · "
        f"[dim]{counts['pending']} pending[/dim]"
    )

    from rich.console import Group
    content = Group(Text(""), Text.from_markup(summary), Text(""))
    return Panel(content, title="Tomoe", border_style="bold")


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
) -> tuple[list[HostResult], bool]:
    """Run execution concurrently across all hosts with live status display.

    Returns a tuple of (results, compact_mode) so callers know which display
    mode was used.
    """

    console = Console()
    status_lock = Lock()
    stop_event = Event()

    # Determine display mode: compact when hosts exceed terminal height.
    # Table overhead: title + header + top/mid/bottom borders + padding ~ 7 lines.
    TABLE_OVERHEAD = 7
    terminal_height = console.size.height
    compact_mode = (len(hosts) + TABLE_OVERHEAD) > terminal_height

    # Initialize status for all hosts.
    host_statuses: dict[str, HostStatus] = {
        host: HostStatus(host=host, status="pending", message="Waiting...")
        for host in hosts
    }

    results: list[HostResult] = []

    def make_display():
        """Create the appropriate display based on mode."""
        if compact_mode:
            return create_compact_display(host_statuses)
        return create_status_table(host_statuses)

    def update_display(live: Live):
        """Background thread to continuously update the display."""
        while not stop_event.is_set():
            with status_lock:
                live.update(make_display())
            time.sleep(0.25)

    first_log = [True]  # Mutable so the closure can modify it.

    def log_completion(live: Live, result: HostResult):
        """In compact mode, print completed hosts above the live display.

        Only successes are shown by default; failures require --verbose.
        """
        if not compact_mode:
            return

        should_print = result.success or verbose
        if not should_print:
            return

        # Print a blank line before the first logged host.
        if first_log[0]:
            live.console.print()
            first_log[0] = False

        if result.success:
            live.console.print(
                f"  [green]✓[/green] [cyan]{result.host}[/cyan] "
                f"[dim](user: {result.username})[/dim]"
            )
        else:
            live.console.print(
                f"  [red]✗[/red] [cyan]{result.host}[/cyan] "
                f"[dim]{result.message[:60]}[/dim]"
            )

    with Live(make_display(), console=console, refresh_per_second=4) as live:
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
                            log_completion(live, result)
                        except Exception as e:
                            # Handle unexpected errors.
                            with status_lock:
                                host_statuses[host] = HostStatus(
                                    host=host,
                                    status="failed",
                                    message=f"Unexpected error: {str(e)[:40]}"
                                )
                            error_result = HostResult(
                                host=host,
                                success=False,
                                message=f"Unexpected error: {e}"
                            )
                            results.append(error_result)
                            log_completion(live, error_result)
        finally:
            stop_event.set()
            display_thread.join(timeout=1)
            # Add spacing between scrolling log and final panel.
            if compact_mode and not first_log[0]:
                live.console.print()
            # Final update to show completed states.
            live.update(make_display())

    return results, compact_mode


def print_results(results: list[HostResult], console: Console,
                   compact_mode: bool = False, verbose: bool = False):
    """Print final results after execution.

    In compact mode, failures are hidden from the results unless --verbose is set
    since they would dominate the output on large host lists.
    """
    console.print("\nExecution Results\n")

    show_failures = not compact_mode or verbose

    for result in results:
        if result.success:
            console.print(f"[green]✓[/green] [cyan]{result.host}[/cyan] - Success (user: {result.username})")
            if result.output:
                console.print(f"  [dim]Output:[/dim]")
                for line in result.output.strip().split('\n'):
                    console.print(f"    {line}")
                console.print()
        elif show_failures:
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
        usage="tomoe.py {smb, winrm, ssh} <ip/file> -u <username/file> -p <password/file> [--script <script> | --command <command> | --upload <source> <dest> | --download <source> <dest>]",
        description="Tomoe is a python utility for remote administration over multiple protocols in case of fail-over."
    )
    parser.add_argument("protocol", choices=["smb", "winrm", "ssh"], help="protocol to use for remote administration")
    parser.add_argument("target", metavar="IP", help="target host IP/hostname or path to file with targets (one per line)")
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
    hosts = parse_target_or_file(args.target)
    usernames = parse_target_or_file(args.username)
    passwords = parse_target_or_file(args.password)
    
    # Validate that we have at least one host, username, and password.
    if not hosts:
        parser.error(f"no hosts found in '{args.target}' (file is empty or contains only whitespace)")
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

    # Determine if compact mode will be used (same logic as run_concurrent_execution).
    TABLE_OVERHEAD = 7
    compact_mode = (len(hosts) + TABLE_OVERHEAD) > console.size.height

    # Run concurrent execution.
    results, _ = run_concurrent_execution(
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
    print_results(results, console, compact_mode=compact_mode, verbose=args.verbose)
    
    # Write output files if output directory specified.
    if args.output:
        write_output_files(results, args.output, console)
