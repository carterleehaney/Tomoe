import argparse
import ipaddress
import logging
import os
from os.path import isfile, exists
from typing import Optional

from rich.console import Console
from rich.markup import escape

from tomoe.config import RunOptions
from tomoe.orchestrator import (
    run_concurrent_execution,
    run_interactive_shell,
    HostResult,
)


def expand_target(value: str) -> list[str]:
    """Expand a single target value into a list of IP addresses."""
    if '/' in value:
        network = ipaddress.ip_network(value, strict=False)
        if network.version != 4 or network.prefixlen not in {24, 25, 26}:
            raise ValueError(f"only /24, /25, and /26 IPv4 subnets are supported: {value}")
        return [str(ip) for ip in network.hosts()]

    if '-' in value:
        parts = value.rsplit('.', 1)
        if len(parts) == 2 and '-' in parts[1]:
            try:
                prefix = parts[0]
                start_str, end_str = parts[1].split('-', 1)
                start, end = int(start_str), int(end_str)
                if 0 <= start <= 255 and 0 <= end <= 255 and start <= end:
                    ipaddress.ip_address(f"{prefix}.{start}")
                    return [f"{prefix}.{i}" for i in range(start, end + 1)]
            except (ValueError, IndexError):
                pass

    return [value]


def parse_target_or_file(value: str, expand_entries: bool = True) -> list[str]:
    """Parse argument as file path or literal value."""
    if isfile(value):
        with open(value, 'r') as f:
            entries = [line.strip() for line in f if line.strip()]
    else:
        entries = [value]

    if not expand_entries:
        return entries

    result = []
    for entry in entries:
        result.extend(expand_target(entry))
    return result


def print_results(results: list[HostResult], console: Console):
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

    summary = f"\n[bold]Summary:[/bold] {len(successes)}/{len(results)} hosts successful"
    if failures:
        summary += f" ([red]{len(failures)} failed[/red])"
    console.print(summary)


def write_output_files(results: list[HostResult], output_dir: str, console: Console):
    os.makedirs(output_dir, exist_ok=True)

    written_count = 0
    for result in results:
        if result.success and result.output:
            file_path = os.path.join(output_dir, f"{result.host}.txt")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(result.output)
            written_count += 1

    console.print(f"[bold]Output:[/bold] Wrote {written_count} file(s) to {output_dir}/")


def build_parser() -> argparse.ArgumentParser:
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("target", metavar="IP", help="target host IP/hostname or path to file with targets (one per line)")
    shared.add_argument("-d", "--domain", default="", help="domain of selected user")
    shared.add_argument("-u", "--username", required=True, help="username or path to file with usernames (one per line)")

    exec_group = shared.add_mutually_exclusive_group(required=False)
    exec_group.add_argument("-s", "--script", help="local path to a script to execute on the remote host")
    exec_group.add_argument("-c", "--command", help="command to execute on the remote host")

    transfer_group = shared.add_mutually_exclusive_group(required=False)
    transfer_group.add_argument("--upload", nargs=2, metavar=("SOURCE", "DEST"), help="upload local SOURCE to remote DEST")
    transfer_group.add_argument("--download", nargs=2, metavar=("SOURCE", "DEST"), help="download remote SOURCE to local DEST")

    shared.add_argument("-a", "--args", default="", help="arguments to pass to the script")
    shared.add_argument("-v", "--verbose", action="store_true", help="show verbose status messages")
    shared.add_argument("--show-failures", action="store_true", help="show failed hosts in the compact-mode completion log")
    shared.add_argument("-t", "--threads", type=int, default=10, help="maximum concurrent threads (default: 10)")
    shared.add_argument("-o", "--output", metavar="DIR", help="output directory to create for per-host result files")

    epilog = (
        "Common options (accepted by every protocol):\n"
        "  IP                  target host — IP, hostname, CIDR (/24-/26),\n"
        "                      dash-range (e.g. 10.0.0.1-50), or file with one per line\n"
        "  -u USERNAME         username or path to file with usernames\n"
        "  -d DOMAIN           domain of selected user\n"
        "  -c COMMAND          command to execute        (mutually exclusive with -s)\n"
        "  -s SCRIPT           local script path         (mutually exclusive with -c)\n"
        "  --upload SRC DST    upload SRC to remote DST\n"
        "  --download SRC DST  download remote SRC to local DST\n"
        "  -a ARGS             arguments to pass to the script\n"
        "  -t THREADS          maximum concurrent threads (default: 10)\n"
        "  -o DIR              per-host output directory\n"
        "  -v                  verbose status messages\n"
        "  --show-failures     show failed hosts in compact-mode log\n"
        "\n"
        "Run 'tomoe {smb,winrm,ssh} -h' for protocol-specific options."
    )

    parser = argparse.ArgumentParser(
        prog="tomoe",
        description="Tomoe is a python utility for remote administration over multiple protocols in case of fail-over.",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="protocol", required=True, metavar="{smb,winrm,ssh}")

    smb_parser = subparsers.add_parser("smb", parents=[shared], help="SMB/PsExec remote execution (runs as NT AUTHORITY\\SYSTEM)")
    smb_parser.add_argument("-p", "--password", required=True, help="password or path to file with passwords (one per line)")
    smb_parser.add_argument("--shell", choices=["powershell", "cmd"], default="powershell", help="shell type for SMB protocol (default: powershell)")
    smb_parser.add_argument("--no-encrypt", dest="encrypt", action="store_false", default=True, help="disable SMB encryption (encryption is enabled by default)")
    smb_parser.set_defaults(target_os="windows", interactive=False)

    winrm_parser = subparsers.add_parser("winrm", parents=[shared], help="WinRM remote execution (PowerShell)")
    winrm_parser.add_argument("-p", "--password", required=True, help="password or path to file with passwords (one per line)")
    winrm_parser.add_argument("-i", "--interactive", action="store_true", help="drop into an interactive PowerShell session on the remote host (single host only)")
    winrm_parser.set_defaults(target_os="windows", shell="powershell", encrypt=True)

    ssh_parser = subparsers.add_parser("ssh", parents=[shared], help="SSH remote execution (Windows or Linux targets)")
    ssh_parser.add_argument("-p", "--password", default=None, help="password or path to file with passwords (one per line). Optional: if omitted, SSH key-based auth is used (agent + ~/.ssh/ keys).")
    ssh_parser.add_argument("--os", choices=["windows", "linux"], default="windows", dest="target_os", help="target host OS (default: windows)")
    ssh_parser.set_defaults(shell="powershell", encrypt=True, interactive=False)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.interactive and (args.command or args.script or args.upload or args.download):
        parser.error("--interactive cannot be combined with --command, --script, --upload, or --download")

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
        dest_parent = os.path.dirname(os.path.abspath(dest))
        if not exists(dest_parent):
            parser.error(f"local destination parent directory not found: {dest_parent}")
    else:
        if not args.script and not args.command and not args.interactive:
            parser.error("either --script, --command, --upload, --download, or --interactive is required")

    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.CRITICAL)

    try:
        hosts = parse_target_or_file(args.target)
    except ValueError as exc:
        parser.error(str(exc))

    if args.interactive and len(hosts) > 1:
        parser.error(f"--interactive requires a single target host (got {len(hosts)})")

    usernames = parse_target_or_file(args.username, expand_entries=False)

    if args.password is None:
        passwords = [None]
    else:
        passwords = parse_target_or_file(args.password, expand_entries=False)

    if not hosts:
        parser.error(f"no hosts found in '{args.target}' (file is empty or contains only whitespace)")
    if not usernames:
        parser.error(f"no usernames found in '{args.username}' (file is empty or contains only whitespace)")
    if not passwords:
        parser.error(f"no passwords found in '{args.password}' (file is empty or contains only whitespace)")

    console = Console()
    console.print()
    console.print(f"  Targets: {len(hosts)} host(s)")
    if args.password is None and args.protocol == "ssh":
        console.print(f"  Credentials: {len(usernames)} user(s) x SSH key auth")
    else:
        console.print(f"  Credentials: {len(usernames)} user(s) x {len(passwords)} password(s)")
    console.print(f"  Protocol: {args.protocol}")
    if args.upload:
        console.print(f"  Operation: Upload {source} -> {dest}")
    elif args.download:
        console.print(f"  Operation: Download {source} -> {dest}")
        if len(hosts) > 1:
            console.print(f"  Note: Per-host subdirectories will be created under {dest}")
    console.print()

    if args.interactive:
        exit_code = run_interactive_shell(
            host=hosts[0], usernames=usernames, passwords=passwords,
            domain=args.domain, verbose=args.verbose, console=console,
            protocol=args.protocol,
        )
        raise SystemExit(exit_code)

    # Build the RunOptions object from CLI args; this is what replaces the
    # old ad hoc kwargs dict that used to get splatted into
    # protocol-module calls.
    options = RunOptions(
        shell_type=getattr(args, "shell", "powershell"),
        encrypt=getattr(args, "encrypt", True),
        target_os=getattr(args, "target_os", "windows"),
        threads=args.threads,
        verbose=args.verbose,
    )

    results, compact_mode = run_concurrent_execution(
        hosts=hosts, usernames=usernames, passwords=passwords,
        domain=args.domain, protocol=args.protocol,
        script_path=args.script, command=args.command,
        script_args=args.args, verbose=args.verbose,
        max_workers=args.threads, source=source, dest=dest,
        download=is_download, console=console,
        show_failures=args.show_failures, options=options,
    )

    print_results(results, console)

    if args.output:
        write_output_files(results, args.output, console)


if __name__ == "__main__":
    main()
