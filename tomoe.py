import argparse
import ipaddress
import logging
import os
import queue
import time
from collections import deque
from os.path import isfile, isdir, exists
from threading import Lock, Thread, Event
from dataclasses import dataclass
from typing import Optional
from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.markup import escape

LOG_STYLE = {
    logging.DEBUG: "dim",
    logging.INFO: "dim",
    logging.WARNING: "yellow",
    logging.ERROR: "red",
    logging.CRITICAL: "bold red",
}


class LiveLogHandler(logging.Handler):
    """Logging handler that routes messages through a Rich Live display.

    This avoids raw stderr writes that would corrupt the Live panel.
    Messages are printed above the panel via live.console.print().
    """

    def __init__(self, live: Live):
        super().__init__()
        self.live = live

    def emit(self, record):
        try:
            msg = self.format(record)
            style = LOG_STYLE.get(record.levelno, "dim")
            text = Text(f"  {msg}", style=style)
            self.live.console.print(text)
        except Exception:
            self.handleError(record)


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

    Supports CIDR notation down to /26 (e.g. 192.168.1.0/24) and IP ranges
    using a dash in the last octet (e.g. 192.168.1.1-50). Plain hostnames and
    single IPs are returned as-is.
    """
    # CIDR notation is restricted to /24, /25, and /26 IPv4 networks.
    if '/' in value:
        network = ipaddress.ip_network(value, strict=False)
        if network.version != 4 or network.prefixlen not in {24, 25, 26}:
            raise ValueError(f"only /24, /25, and /26 IPv4 subnets are supported: {value}")
        # Return all usable host addresses (excludes network and broadcast)
        return [str(ip) for ip in network.hosts()]

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


def parse_target_or_file(value: str, expand_entries: bool = True) -> list[str]:
    """Parse argument as file path or literal value.

    If the value is a path to an existing file, read each line as a separate entry.
    Otherwise, treat the value as a literal string.

    Target entries can optionally be expanded for CIDR notation or IP ranges.
    """
    if isfile(value):
        with open(value, 'r') as f:
            entries = [line.strip() for line in f if line.strip()]
    else:
        entries = [value]

    if not expand_entries:
        return entries

    # Expand any CIDR or range notation in each entry.
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
            escape(status.host),
            status_style,
            escape(str(status.current_user)),
            escape(str(status.message))
        )

    return table


def create_compact_display(
    host_statuses: dict[str, HostStatus],
    recent_completions: list[Text] | None = None
):
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

    panel = Panel(
        Group(Text(""), Text.from_markup(summary), Text("")),
        title="Tomoe",
        border_style="bold"
    )

    if recent_completions:
        return Group(*recent_completions, panel)

    return panel


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
    encrypt: bool = True,
    shutdown_event: Optional[Event] = None
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
            if shutdown_event and shutdown_event.is_set():
                update_status("failed", "-", "Interrupted by user.")
                return HostResult(
                    host=host,
                    success=False,
                    message="Interrupted by user."
                )

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
                        encrypt=encrypt,
                        shutdown_event=shutdown_event
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
            except KeyboardInterrupt:
                update_status("failed", username, "Interrupted by user.")
                return HostResult(
                    host=host,
                    success=False,
                    username=username,
                    message="Interrupted by user."
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
    encrypt: bool = True,
    console: Console | None = None,
    show_failures: bool = False
) -> tuple[list[HostResult], bool]:
    """Run execution concurrently across all hosts with live status display.

    Returns a tuple of (results, compact_mode) so callers know which display
    mode was used.
    """

    if console is None:
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
    recent_completions: deque[Text] = deque(maxlen=8)

    results: list[HostResult] = []
    result_queue: queue.Queue[HostResult] = queue.Queue()
    shutdown_requested = False

    def make_display():
        """Create the appropriate display based on mode."""
        if compact_mode:
            return create_compact_display(host_statuses, list(recent_completions))
        return create_status_table(host_statuses)

    def update_display(live: Live):
        """Background thread to continuously update the display."""
        while not stop_event.is_set():
            with status_lock:
                live.update(make_display())
            time.sleep(0.25)

    def log_completion(live: Live, result: HostResult):
        """Track completed hosts in compact mode without printing outside Live."""
        if not compact_mode:
            return

        if result.success:
            recent_completions.append(
                Text.from_markup(
                    f"  [green]✓[/green] [cyan]{escape(result.host)}[/cyan] "
                    f"[dim](user: {escape(str(result.username))})[/dim]"
                )
            )
        elif verbose or show_failures:
            recent_completions.append(
                Text.from_markup(
                    f"  [red]✗[/red] [cyan]{escape(result.host)}[/cyan] "
                    f"[dim]{escape(str(result.message)[:60])}[/dim]"
                )
            )

    with Live(make_display(), console=console, refresh_per_second=4) as live:
        # Route logging through the Live display so log lines appear above
        # the panel instead of corrupting it.
        root_logger = logging.getLogger()
        live_handler = LiveLogHandler(live)
        live_handler.setLevel(logging.DEBUG)
        original_handlers = root_logger.handlers[:]
        # Preserve existing log formatting by copying the formatter from
        # the first original handler, if one is configured.
        if original_handlers:
            first_handler = original_handlers[0]
            if first_handler.formatter is not None:
                live_handler.setFormatter(first_handler.formatter)
        for h in original_handlers:
            root_logger.removeHandler(h)
        root_logger.addHandler(live_handler)

        # Start background display updater.
        display_thread = Thread(target=update_display, args=(live,), daemon=True)
        display_thread.start()

        try:
            # For multi-host downloads, create per-host subdirectories
            # to prevent files from overwriting each other.
            use_host_subdirs = download and source and dest and len(hosts) > 1

            if use_host_subdirs:
                for host in hosts:
                    os.makedirs(os.path.join(dest, host), exist_ok=True)

            work_queue: queue.Queue[tuple[str, Optional[str]] | None] = queue.Queue()
            completed_hosts = set()

            for host in hosts:
                per_host_dest = os.path.join(dest, host) if use_host_subdirs else dest
                work_queue.put((host, per_host_dest))

            def worker():
                while True:
                    item = work_queue.get()
                    if item is None:
                        work_queue.task_done()
                        break

                    host, worker_dest = item
                    try:
                        if stop_event.is_set():
                            with status_lock:
                                if host_statuses[host].status in ("pending", "trying"):
                                    host_statuses[host] = HostStatus(
                                        host=host,
                                        status="failed",
                                        message="Interrupted by user."
                                    )
                            result_queue.put(HostResult(
                                host=host,
                                success=False,
                                message="Interrupted by user."
                            ))
                        else:
                            result = execute_on_host(
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
                                worker_dest,
                                target_os,
                                download,
                                shell_type,
                                encrypt,
                                stop_event
                            )
                            result_queue.put(result)
                    except KeyboardInterrupt:
                        with status_lock:
                            host_statuses[host] = HostStatus(
                                host=host,
                                status="failed",
                                message="Interrupted by user."
                            )
                        result_queue.put(HostResult(
                            host=host,
                            success=False,
                            message="Interrupted by user."
                        ))
                    except Exception as e:
                        with status_lock:
                            host_statuses[host] = HostStatus(
                                host=host,
                                status="failed",
                                message=f"Unexpected error: {str(e)[:40]}"
                            )
                        result_queue.put(HostResult(
                            host=host,
                            success=False,
                            message=f"Unexpected error: {e}"
                        ))
                    finally:
                        work_queue.task_done()

            worker_count = min(max_workers, len(hosts))
            workers = []
            for _ in range(worker_count):
                thread = Thread(target=worker, daemon=True)
                thread.start()
                workers.append(thread)

            while len(completed_hosts) < len(hosts):
                try:
                    result = result_queue.get(timeout=0.25)
                except queue.Empty:
                    continue
                except KeyboardInterrupt:
                    shutdown_requested = True
                    stop_event.set()
                    with status_lock:
                        for host in hosts:
                            current_status = host_statuses[host]
                            if host not in completed_hosts and current_status.status in ("pending", "trying"):
                                host_statuses[host] = HostStatus(
                                    host=host,
                                    status="failed",
                                    current_user=current_status.current_user,
                                    message="Interrupted by user."
                                )
                    break

                if result.host not in completed_hosts:
                    results.append(result)
                    completed_hosts.add(result.host)
                    log_completion(live, result)

            while True:
                try:
                    result = result_queue.get_nowait()
                except queue.Empty:
                    break

                if result.host not in completed_hosts:
                    results.append(result)
                    completed_hosts.add(result.host)
                    log_completion(live, result)

            for _ in workers:
                work_queue.put(None)

            if shutdown_requested:
                with status_lock:
                    for host in hosts:
                        if host not in completed_hosts and host_statuses[host].status == "pending":
                            host_statuses[host] = HostStatus(
                                host=host,
                                status="failed",
                                message="Interrupted by user."
                            )
        finally:
            stop_event.set()
            display_thread.join(timeout=1)
            # Final update to show completed states before Live exits.
            live.update(make_display())

            # Restore original log handlers.
            root_logger.removeHandler(live_handler)
            for h in original_handlers:
                root_logger.addHandler(h)

    return results, compact_mode


def print_results(results: list[HostResult], console: Console):
    """Print final results after execution."""
    console.print("\nExecution Results\n")

    successes = [r for r in results if r.success]
    failures = [r for r in results if not r.success]

    if failures:
        console.print(f"[red]Failed ({len(failures)}):[/red]")
        for result in failures:
            console.print(f"  [red]✗[/red] [cyan]{escape(result.host)}[/cyan] [dim]{escape(str(result.message))}[/dim]")
        console.print()

    for result in successes:
        console.print(f"[green]✓[/green] [cyan]{escape(result.host)}[/cyan] - Success (user: {escape(str(result.username))})")
        if result.output:
            console.print(f"  [dim]Output:[/dim]")
            for line in result.output.strip().split('\n'):
                console.print(f"    {line}")
            console.print()

    # Summary.
    summary = f"\n[bold]Summary:[/bold] {len(successes)}/{len(results)} hosts successful"
    if failures:
        summary += f" ([red]{len(failures)} failed[/red])"
    console.print(summary)


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
    parser.add_argument("--show-failures", action="store_true", help="show failed hosts in the compact-mode completion log")
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
    try:
        hosts = parse_target_or_file(args.target)
    except ValueError as exc:
        parser.error(str(exc))

    usernames = parse_target_or_file(args.username, expand_entries=False)
    passwords = parse_target_or_file(args.password, expand_entries=False)
    
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

    # Run concurrent execution.
    results, compact_mode = run_concurrent_execution(
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
        encrypt=args.encrypt,
        console=console,
        show_failures=args.show_failures
    )

    # Print final results.
    print_results(results, console)
    
    # Write output files if output directory specified.
    if args.output:
        write_output_files(results, args.output, console)
