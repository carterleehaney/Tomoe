import logging
import os
import queue
import time
from collections import deque
from dataclasses import dataclass
from threading import Lock, Thread, Event
from typing import Optional

from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from tomoe.common import AuthenticationError
from tomoe.config import Credential, RunOptions
from tomoe.connections import get_connection

LOG_STYLE = {
    logging.DEBUG: "dim",
    logging.INFO: "dim",
    logging.WARNING: "yellow",
    logging.ERROR: "red",
    logging.CRITICAL: "bold red",
}


class LiveLogHandler(logging.Handler):
    """Routes log messages through a Rich Live display."""

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


@dataclass
class HostResult:
    host: str
    success: bool
    username: Optional[str] = None
    message: str = ""
    output: str = ""


@dataclass
class HostStatus:
    host: str
    status: str  # "pending", "trying", "success", "failed"
    current_user: str = "-"
    message: str = "Waiting..."


def create_status_table(host_statuses: dict[str, HostStatus]) -> Table:
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
    download: bool = False,
    shutdown_event: Optional[Event] = None,
    options: Optional[RunOptions] = None,
) -> HostResult:
    """Execute an operation on a single host, trying credential permutations until success."""

    connection_cls = get_connection(protocol)
    options = options or RunOptions(verbose=verbose)

    def update_status(status: str, user: str = "-", message: str = ""):
        with status_lock:
            host_statuses[host] = HostStatus(
                host=host, status=status, current_user=user, message=message
            )

    update_status("trying", "-", "Starting...")

    for username in usernames:
        for password in passwords:
            if shutdown_event and shutdown_event.is_set():
                update_status("failed", "-", "Interrupted by user.")
                return HostResult(host=host, success=False, message="Interrupted by user.")

            update_status("trying", username, "Authenticating...")

            def make_status_callback(user):
                def callback(message):
                    update_status("trying", user, message)
                return callback

            status_callback = make_status_callback(username)
            credential = Credential(username=username, password=password, domain=domain)
            conn = connection_cls(host, credential, options)

            try:
                if source and dest and download:
                    output = conn.get_file(source, dest, status_callback=status_callback)
                    update_status("success", username, "File downloaded.")
                    return HostResult(
                        host=host, success=True, username=username,
                        message="File downloaded successfully.", output=output,
                    )
                elif source and dest:
                    output = conn.put_file(source, dest, status_callback=status_callback)
                    update_status("success", username, "File uploaded.")
                    return HostResult(
                        host=host, success=True, username=username,
                        message="File uploaded successfully.", output=output,
                    )
                else:
                    result = conn.execute(
                        command, script_path=script_path, script_args=script_args,
                        status_callback=status_callback, shutdown_event=shutdown_event,
                    )
                    update_status("success", username, "Command executed.")
                    return HostResult(
                        host=host, success=True, username=username,
                        message="Command executed successfully.", output=result.output,
                    )

            except KeyboardInterrupt:
                update_status("failed", username, "Interrupted by user.")
                return HostResult(
                    host=host, success=False, username=username,
                    message="Interrupted by user.",
                )
            except AuthenticationError:
                update_status("trying", username, "Authentication failed, trying next.")
                continue
            except Exception as e:
                update_status("failed", username, str(e)[:50])
                return HostResult(
                    host=host, success=False, username=username, message=str(e),
                )

    update_status("failed", "-", "Invalid credentials.")
    return HostResult(host=host, success=False, message="Invalid credentials.")


def run_interactive_shell(host, usernames, passwords, domain, verbose, console, protocol="winrm") -> int:
    """Try credentials against a single host; on first auth success, drop into interactive REPL."""
    connection_cls = get_connection(protocol)
    options = RunOptions(verbose=verbose)

    if not connection_cls.SUPPORTS_INTERACTIVE:
        console.print(f"[red]Error: {protocol} does not support interactive shells[/red]")
        return 1

    for username in usernames:
        for password in passwords:
            console.print(f"[dim]Authenticating as {username}@{host}...[/dim]")
            credential = Credential(username=username, password=password, domain=domain)
            conn = connection_cls(host, credential, options)
            try:
                conn.interactive()
                return 0
            except AuthenticationError:
                console.print(f"[yellow]Auth failed for {username}, trying next...[/yellow]")
                continue
            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted.[/yellow]")
                return 130
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                return 1

    console.print("[red]All credentials failed.[/red]")
    return 2


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
    download: bool = False,
    console: Console | None = None,
    show_failures: bool = False,
    options: Optional[RunOptions] = None,
) -> tuple[list[HostResult], bool]:
    """Run execution concurrently across all hosts with live status display."""

    if console is None:
        console = Console()
    status_lock = Lock()
    stop_event = Event()

    TABLE_OVERHEAD = 7
    terminal_height = console.size.height
    compact_mode = (len(hosts) + TABLE_OVERHEAD) > terminal_height

    host_statuses: dict[str, HostStatus] = {
        host: HostStatus(host=host, status="pending", message="Waiting...")
        for host in hosts
    }
    recent_completions: deque[Text] = deque(maxlen=8)

    results: list[HostResult] = []
    result_queue: queue.Queue[HostResult] = queue.Queue()
    shutdown_requested = False

    def make_display():
        if compact_mode:
            return create_compact_display(host_statuses, list(recent_completions))
        return create_status_table(host_statuses)

    def update_display(live: Live):
        while not stop_event.is_set():
            with status_lock:
                live.update(make_display())
            time.sleep(0.25)

    def log_completion(live: Live, result: HostResult):
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
        root_logger = logging.getLogger()
        live_handler = LiveLogHandler(live)
        live_handler.setLevel(logging.DEBUG)
        original_handlers = root_logger.handlers[:]
        if original_handlers:
            first_handler = original_handlers[0]
            if first_handler.formatter is not None:
                live_handler.setFormatter(first_handler.formatter)
        for h in original_handlers:
            root_logger.removeHandler(h)
        root_logger.addHandler(live_handler)

        display_thread = Thread(target=update_display, args=(live,), daemon=True)
        display_thread.start()

        try:
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
                                        host=host, status="failed",
                                        message="Interrupted by user.",
                                    )
                            result_queue.put(HostResult(
                                host=host, success=False,
                                message="Interrupted by user.",
                            ))
                        else:
                            result = execute_on_host(
                                host, usernames, passwords, domain, protocol,
                                script_path, command, script_args, verbose,
                                host_statuses, status_lock,
                                source, worker_dest, download, stop_event,
                                options=options,
                            )
                            result_queue.put(result)
                    except KeyboardInterrupt:
                        with status_lock:
                            host_statuses[host] = HostStatus(
                                host=host, status="failed",
                                message="Interrupted by user.",
                            )
                        result_queue.put(HostResult(
                            host=host, success=False,
                            message="Interrupted by user.",
                        ))
                    except Exception as e:
                        with status_lock:
                            host_statuses[host] = HostStatus(
                                host=host, status="failed",
                                message=f"Unexpected error: {str(e)[:40]}",
                            )
                        result_queue.put(HostResult(
                            host=host, success=False,
                            message=f"Unexpected error: {e}",
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
                                    host=host, status="failed",
                                    current_user=current_status.current_user,
                                    message="Interrupted by user.",
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
                                host=host, status="failed",
                                message="Interrupted by user.",
                            )
        finally:
            stop_event.set()
            display_thread.join(timeout=1)
            live.update(make_display())

            root_logger.removeHandler(live_handler)
            for h in original_handlers:
                root_logger.addHandler(h)

    return results, compact_mode
