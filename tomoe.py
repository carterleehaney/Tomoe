import argparse
import logging
import time
from os.path import isfile, isdir, exists
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from threading import Lock, Thread, Event
from dataclasses import dataclass
from typing import Optional
from rich.console import Console
from rich.live import Live
from rich.table import Table

from smb import run_psexec, run_smb_copy
from wsman import run_winrm, run_winrm_copy


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
    dest: Optional[str] = None
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
            
            try:
                # Check if this is a file copy operation (smb with --source/--dest)
                if protocol == "smb" and source and dest:
                    output = run_smb_copy(
                        target_ip=host,
                        username=username,
                        password=password,
                        domain=domain,
                        source=source,
                        dest=dest,
                        verbose=verbose,
                    )
                    update_status("success", username, "File copied.")
                    return HostResult(
                        host=host,
                        success=True,
                        username=username,
                        message="File copied successfully.",
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
                    )
                    update_status("success", username, "File copied.")
                    return HostResult(
                        host=host,
                        success=True,
                        username=username,
                        message="File copied successfully.",
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
    dest: Optional[str] = None
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
                        dest
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
        usage="tomoe.py {smb, winrm} -i <ip/file> -u <username/file> -p <password/file> [--script <script> | --command <command> | --source <file> --dest <path>] -v",
        description="Tomoe is a python utility for cross-platform windows administration over multiple protocols in case of fail-over."
    )
    parser.add_argument("protocol", choices=["smb", "winrm"], help="protocol to use for remote administration")
    parser.add_argument("-i", metavar="IP", required=True, help="target host IP/hostname or path to file with targets (one per line)")
    parser.add_argument("-d", "--domain", default="", help="domain of selected user")
    parser.add_argument("-u", "--username", required=True, help="username or path to file with usernames (one per line)")
    parser.add_argument("-p", "--password", required=True, help="password or path to file with passwords (one per line)")

    # Script or Command; but never both.
    exec_group = parser.add_mutually_exclusive_group(required=False)
    exec_group.add_argument("-s", "--script", help="local path to PowerShell script to execute")
    exec_group.add_argument("-c", "--command", help="powershell command to execute")
    
    # File copy arguments (for smb/winrm protocol file transfer).
    parser.add_argument("--source", help="local path to file or directory to copy (use with --dest)")
    parser.add_argument("--dest", help="remote destination as local Windows path, e.g. C:\\Windows\\Temp\\file.exe (use with --source)")
    
    # Arguments to pass to the script.
    parser.add_argument("-a", "--args", default="", help="arguments to pass to the script")
    parser.add_argument("-v", "--verbose", action="store_true", help="show verbose status messages")
    parser.add_argument("-t", "--threads", type=int, default=10, help="maximum concurrent threads (default: 10)")
    parser.add_argument("-o", "--output", metavar="DIR", help="output directory to create for per-host result files")

    args = parser.parse_args()
    
    # Validate arguments based on protocol and operation mode.
    if args.source or args.dest:
        # File/directory copy mode
        if not args.source or not args.dest:
            parser.error("both --source and --dest are required for file copy")
        if not exists(args.source):
            parser.error(f"source not found: {args.source}")
        if args.script or args.command:
            parser.error("--source/--dest cannot be used with --script or --command")
    else:
        # Command execution mode
        if not args.script and not args.command:
            parser.error("either --script, --command, or --source/--dest is required")
    
    # Set logging level based on verbose flag.
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.CRITICAL)

    # Parse targets, usernames, and passwords (file or literal).
    hosts = parse_target_or_file(args.i)
    usernames = parse_target_or_file(args.username)
    passwords = parse_target_or_file(args.password)
    
    console = Console()
    console.print()
    console.print(f"  Targets: {len(hosts)} host(s)")
    console.print(f"  Credentials: {len(usernames)} user(s) x {len(passwords)} password(s)")
    console.print(f"  Protocol: {args.protocol}")
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
        source=args.source,
        dest=args.dest
    )
    
    # Print final results.
    print_results(results, console)
    
    # Write output files if output directory specified.
    if args.output:
        write_output_files(results, args.output, console)
