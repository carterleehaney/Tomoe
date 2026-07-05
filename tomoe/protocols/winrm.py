import logging
import os
import shlex

from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan
from pypsrp.client import Client

from tomoe.common import AuthenticationError, ConnectionError, check_port_open, build_auth_username

# Importing readline enables arrow-key line editing and history for input().
# Not available on stock Windows Python; harmless to skip there.
try:
    import readline  # noqa: F401
except ImportError:
    pass

logger = logging.getLogger(__name__)


def _wsman_kwargs(host, auth_username, password):
    """Return shared kwargs for WSMan() instantiation."""
    return dict(
        server=host, port=5985, username=auth_username, password=password,
        ssl=False, auth="ntlm", encryption="auto",
        connection_timeout=30, read_timeout=30,
    )


def _client_kwargs(host, auth_username, password):
    """Return shared kwargs for Client() instantiation (host as positional arg)."""
    return dict(
        username=auth_username, password=password,
        port=5985, ssl=False, auth="ntlm", encryption="auto",
        connection_timeout=30, read_timeout=30,
    )


def execute(host, username, password, domain="", script_path=None, command=None, script_args="", verbose=False, status_callback=None, shutdown_event=None):
    """Execute a PowerShell script or command on a remote host via WinRM."""
    if not check_port_open(host, 5985, timeout=5):
        raise ConnectionError(f"Port 5985 not reachable on {host}")

    auth_username = build_auth_username(username, domain)

    try:
        wsman = WSMan(**_wsman_kwargs(host, auth_username, password))

        with RunspacePool(wsman) as pool:
            if status_callback:
                status_callback("Authenticated, preparing command...")

            ps = PowerShell(pool)

            if script_path:
                logger.debug("Reading local script: %s", script_path)
                with open(script_path, 'r') as file:
                    script_content = file.read()

                if script_args:
                    full_script = f"& {{{script_content}}} {script_args}"
                else:
                    full_script = script_content

                ps.add_script(full_script)

            elif command:
                logger.debug("Executing command: %s", command)
                ps.add_script(command)
            else:
                raise ValueError("Either --script or --command must be provided.")

            logger.debug("Executing on %s via WinRM (pypsrp)...", host)

            if status_callback:
                status_callback("Executing...")
            ps.invoke()

            logger.debug("Command executed, had_errors: %s", ps.had_errors)

            output_lines = []

            for item in ps.output:
                output_lines.append(str(item))

            if hasattr(ps, 'streams') and ps.streams.information:
                for info in ps.streams.information:
                    output_lines.append(str(info.message_data))

            if hasattr(ps, 'streams') and ps.streams.warning:
                for warning in ps.streams.warning:
                    output_lines.append(f"WARNING: {warning}")

            if hasattr(ps, 'streams') and ps.streams.error:
                for error in ps.streams.error:
                    output_lines.append(f"ERROR: {error}")

            logger.debug("Output: %s", output_lines)

            return "\n".join(output_lines)

    except Exception as e:
        error_str = str(e).lower()

        if any(auth_err in error_str for auth_err in [
            "unauthorized", "401", "authentication", "logon_failure",
            "access_denied", "invalid credentials", "kerberos", "ntlm",
            "denied", "rejected"
        ]):
            logger.debug("WinRM authentication failed: %s", e)
            raise AuthenticationError(f"Authentication failed for {username}@{host}: {e}")

        if any(conn_err in error_str for conn_err in [
            "connection", "timeout", "refused", "unreachable", "reset"
        ]):
            logger.debug("WinRM connection failed: %s", e)
            raise ConnectionError(f"Connection failed to {host}: {e}")

        logger.debug("WinRM execution failed: %s", e)
        raise


def interactive(host, username, password, domain="", verbose=False):
    """Open an interactive PowerShell REPL on a remote host via WinRM."""
    if not check_port_open(host, 5985, timeout=5):
        raise ConnectionError(f"Port 5985 not reachable on {host}")

    auth_username = build_auth_username(username, domain)

    try:
        wsman = WSMan(**_wsman_kwargs(host, auth_username, password))

        local_cwd = os.getcwd()

        with RunspacePool(wsman) as pool:
            _repl_loop(pool, host=host, username=username,
                       password=password, domain=domain, verbose=verbose,
                       local_cwd=local_cwd)

    except Exception as e:
        error_str = str(e).lower()

        if any(auth_err in error_str for auth_err in [
            "unauthorized", "401", "authentication", "logon_failure",
            "access_denied", "invalid credentials", "kerberos", "ntlm",
            "denied", "rejected"
        ]):
            logger.debug("WinRM authentication failed: %s", e)
            raise AuthenticationError(f"Authentication failed for {username}@{host}: {e}")

        if any(conn_err in error_str for conn_err in [
            "connection", "timeout", "refused", "unreachable", "reset"
        ]):
            logger.debug("WinRM connection failed: %s", e)
            raise ConnectionError(f"Connection failed to {host}: {e}")

        logger.debug("WinRM shell failed: %s", e)
        raise


def _handle_transfer(line, remote_cwd, local_cwd, host, username, password, domain, verbose):
    """Parse and dispatch a single 'upload' or 'download' built-in line."""
    try:
        tokens = shlex.split(line, posix=False)
    except ValueError as e:
        print(f"ERROR: could not parse arguments: {e}")
        return

    cmd = tokens[0].lower()
    args = tokens[1:]

    if cmd == "upload":
        if len(args) != 1:
            print("Usage: upload <local>")
            return
        local = args[0]
        if not os.path.exists(local):
            print(f"ERROR: local source not found: {local}")
            return
        remote_name = os.path.basename(local.rstrip("/\\")) or os.path.basename(local)
        if not remote_cwd:
            print("ERROR: remote cwd unknown; cannot resolve upload destination")
            return
        remote_dest = remote_cwd.rstrip("\\") + "\\" + remote_name
        try:
            output = upload(
                host=host, username=username, password=password,
                domain=domain, source=local, dest=remote_dest,
                verbose=verbose,
            )
            print(output)
        except Exception as e:
            print(f"ERROR: upload failed: {e}")
        return

    # download
    if len(args) != 1:
        print("Usage: download <remote>")
        return
    remote = args[0]
    remote_normalized = remote.replace("/", "\\")
    is_absolute = (len(remote_normalized) >= 2 and remote_normalized[1] == ":") or remote_normalized.startswith("\\\\")
    if is_absolute:
        remote_resolved = remote
    else:
        if not remote_cwd:
            print("ERROR: remote cwd unknown; pass an absolute path")
            return
        remote_resolved = remote_cwd.rstrip("\\") + "\\" + remote_normalized.lstrip("\\")
    local_name = os.path.basename(remote_resolved.replace("\\", "/").rstrip("/")) or "downloaded_file"
    local_dest = os.path.join(local_cwd, local_name)
    try:
        output = download(
            host=host, username=username, password=password,
            domain=domain, source=remote_resolved, dest=local_dest,
            verbose=verbose,
        )
        print(output)
    except Exception as e:
        print(f"ERROR: download failed: {e}")


def _get_remote_cwd(pool):
    """Query the remote runspace for its current location."""
    try:
        ps = PowerShell(pool)
        ps.add_script("(Get-Location).Path")
        ps.invoke()
        for item in ps.output:
            text = str(item).strip()
            if text:
                return text
    except Exception:
        pass
    return None


def _repl_loop(pool, host, username, password, domain, verbose, local_cwd):
    """Read-eval-print loop against an open RunspacePool."""
    while True:
        cwd = _get_remote_cwd(pool)
        prompt = f"PS {cwd}> " if cwd else "PS> "
        try:
            line = input(prompt)
        except EOFError:
            print()
            return
        except KeyboardInterrupt:
            print()
            continue

        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower() in ("exit", "quit"):
            return

        first_token = stripped.split(None, 1)[0].lower()
        if first_token in ("upload", "download"):
            _handle_transfer(stripped, remote_cwd=cwd, local_cwd=local_cwd,
                             host=host, username=username,
                             password=password, domain=domain, verbose=verbose)
            continue

        ps = PowerShell(pool)
        ps.add_script(". { " + line + " } | Out-String -Stream")

        try:
            ps.invoke()
        except KeyboardInterrupt:
            try:
                ps.stop()
            except Exception:
                pass
            print("^C")
            continue
        except Exception as e:
            print(f"ERROR: {e}")
            continue

        for item in ps.output:
            if item is None:
                continue
            print(item)
        if hasattr(ps, "streams"):
            for info in ps.streams.information or []:
                print(info.message_data)
            for warning in ps.streams.warning or []:
                print(f"WARNING: {warning}")
            for error in ps.streams.error or []:
                print(f"ERROR: {error}")


def upload(host, username, password, domain="", source="", dest="", verbose=False, status_callback=None):
    """Copy a local file or directory to a remote host via WinRM."""
    if not check_port_open(host, 5985, timeout=5):
        raise ConnectionError(f"Port 5985 not reachable on {host}")

    if not os.path.exists(source):
        raise FileNotFoundError(f"Source not found: {source}")

    auth_username = build_auth_username(username, domain)

    try:
        with Client(host, **_client_kwargs(host, auth_username, password)) as client:
            if os.path.isfile(source):
                if status_callback:
                    status_callback("Copying 1 file...")
                file_size = os.path.getsize(source)

                dest_normalized = dest.replace('/', '\\').lstrip('\\')

                if len(dest_normalized) >= 2 and dest_normalized[1] == ':':
                    drive = dest_normalized[:2]
                    path_after_drive = dest_normalized[3:] if len(dest_normalized) > 3 else ""

                    if path_after_drive:
                        remote_path = dest_normalized
                    else:
                        remote_path = drive + '\\' + os.path.basename(source)
                else:
                    remote_path = dest_normalized if dest_normalized else os.path.basename(source)

                logger.debug("Uploading %s (%d bytes) to %s:%s...", source, file_size, host, remote_path)

                client.copy(source, remote_path)

                if status_callback:
                    status_callback("Copying 1/1 files...")

                logger.debug("File copied successfully: %d bytes", file_size)

                return f"Copied {os.path.basename(source)} ({file_size} bytes) to {host}:{remote_path}"

            else:
                pass

        # Directory copy - need to handle separately due to pypsrp connection issues
        if os.path.isdir(source):
            if status_callback:
                status_callback("Scanning directory...")

            total_files = 0
            total_bytes = 0

            dest_normalized = dest.replace('/', '\\').rstrip('\\')

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

            if status_callback:
                status_callback(f"Creating directories, 0/{len(files_to_copy)} files copied...")
            if dirs_to_create:
                with Client(host, **_client_kwargs(host, auth_username, password)) as client:
                    for remote_dir in dirs_to_create:
                        remote_dir_escaped = remote_dir.replace("'", "''")
                        mkdir_script = f"New-Item -ItemType Directory -Path '{remote_dir_escaped}' -Force | Out-Null"
                        try:
                            client.execute_ps(mkdir_script)
                            logger.debug("Created directory: %s", remote_dir)
                        except Exception:
                            pass

            total_file_count = len(files_to_copy)
            if status_callback:
                status_callback(f"Copying 0/{total_file_count} files...")
            for local_file_path, remote_file_path in files_to_copy:
                file_size = os.path.getsize(local_file_path)

                logger.debug("Uploading %s (%d bytes) to %s:%s...", local_file_path, file_size, host, remote_file_path)

                with Client(host, **_client_kwargs(host, auth_username, password)) as client:
                    client.copy(local_file_path, remote_file_path)

                total_files += 1
                total_bytes += file_size

                if status_callback:
                    status_callback(f"Copying {total_files}/{total_file_count} files...")

            logger.debug("Directory copied successfully: %d files, %d bytes", total_files, total_bytes)

            return f"Copied {total_files} file(s) ({total_bytes} bytes) to {host}:{dest_normalized}"

        # Source exists but is neither a file nor a directory
        raise ValueError(f"Source '{source}' exists but is neither a regular file nor a directory")

    except Exception as e:
        error_str = str(e).lower()

        if "failed to copy file" in error_str or "access to the path" in error_str:
            logger.debug("WinRM copy failed: %s", e)
            raise

        if any(auth_err in error_str for auth_err in [
            "failed to authenticate", "unauthorized", "401", "logon_failure",
            "invalid credentials", "credentials were rejected"
        ]):
            logger.debug("WinRM authentication failed: %s", e)
            raise AuthenticationError(f"Authentication failed for {username}@{host}: {e}")

        if any(conn_err in error_str for conn_err in [
            "connection", "timeout", "refused", "unreachable", "reset"
        ]):
            logger.debug("WinRM connection failed: %s", e)
            raise ConnectionError(f"Connection failed to {host}: {e}")

        logger.debug("WinRM copy failed: %s", e)
        raise


def download(host, username, password, domain="", source="", dest="", verbose=False, status_callback=None):
    """Download a file or directory from a remote host via WinRM."""
    if not check_port_open(host, 5985, timeout=5):
        raise ConnectionError(f"Port 5985 not reachable on {host}")

    auth_username = build_auth_username(username, domain)

    source_normalized = source.replace('/', '\\')

    try:
        if status_callback:
            status_callback("Checking remote path...")

        with Client(host, **_client_kwargs(host, auth_username, password)) as client:
            source_escaped = source_normalized.replace("'", "''")
            check_script = f"if (Test-Path -LiteralPath '{source_escaped}' -PathType Container) {{ 'DIRECTORY' }} elseif (Test-Path -LiteralPath '{source_escaped}' -PathType Leaf) {{ 'FILE' }} else {{ 'NOTFOUND' }}"
            output, streams, had_errors = client.execute_ps(check_script)
            path_type = output.strip()

        if path_type == 'NOTFOUND':
            raise FileNotFoundError(f"Remote path not found: {source}")

        if path_type == 'FILE':
            if status_callback:
                status_callback("Downloading 0/1 files...")

            if os.path.isdir(dest):
                dest = os.path.join(dest, os.path.basename(source_normalized))

            dest_dir = os.path.dirname(dest)
            if dest_dir:
                os.makedirs(dest_dir, exist_ok=True)

            logger.debug("Downloading %s:%s to %s...", host, source_normalized, dest)

            with Client(host, **_client_kwargs(host, auth_username, password)) as client:
                client.fetch(source_normalized, dest)

            file_size = os.path.getsize(dest)

            if status_callback:
                status_callback("Downloading 1/1 files...")

            logger.debug("File downloaded successfully: %d bytes", file_size)

            return f"Downloaded {os.path.basename(source_normalized)} ({file_size} bytes) from {host}:{source_normalized}"

        else:
            # Directory download - recursive
            if status_callback:
                status_callback("Enumerating remote directory...")

            source_escaped = source_normalized.replace("'", "''")
            enum_script = (
                f"Get-ChildItem -LiteralPath '{source_escaped}' -Recurse -Force | "
                f"ForEach-Object {{ "
                f"$rel = $_.FullName.Substring('{source_escaped}'.Length).TrimStart('\\'); "
                f"$type = if ($_.PSIsContainer) {{ 'D' }} else {{ 'F' }}; "
                f"\"$rel`t$type\" }}"
            )

            with Client(host, **_client_kwargs(host, auth_username, password)) as client:
                output, streams, had_errors = client.execute_ps(enum_script)

            if had_errors:
                error_messages = []
                if streams and streams.error:
                    error_messages = [str(err) for err in streams.error]
                error_detail = "; ".join(error_messages) if error_messages else "Unknown error"
                raise RuntimeError(f"Failed to enumerate remote directory '{source_normalized}': {error_detail}")

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
                logger.debug("Remote directory is empty: %s", source_normalized)
                return f"Remote directory is empty: {host}:{source_normalized}"

            os.makedirs(dest, exist_ok=True)
            for rel_dir in dirs_to_create:
                local_dir = os.path.join(dest, rel_dir)
                os.makedirs(local_dir, exist_ok=True)
                logger.debug("Created local directory: %s", local_dir)

            total_files = 0
            total_bytes = 0
            total_file_count = len(files_to_download)

            if status_callback:
                status_callback(f"Downloading 0/{total_file_count} files...")

            source_normalized = source_normalized.rstrip('\\')

            for rel_file in files_to_download:
                remote_file_path = source_normalized + '\\' + rel_file
                local_file_path = os.path.join(dest, rel_file)

                local_file_dir = os.path.dirname(local_file_path)
                if local_file_dir:
                    os.makedirs(local_file_dir, exist_ok=True)

                logger.debug("Downloading %s:%s to %s...", host, remote_file_path, local_file_path)

                with Client(host, **_client_kwargs(host, auth_username, password)) as client:
                    client.fetch(remote_file_path, local_file_path)

                file_size = os.path.getsize(local_file_path)
                total_files += 1
                total_bytes += file_size

                if status_callback:
                    status_callback(f"Downloading {total_files}/{total_file_count} files...")

            logger.debug("Directory downloaded successfully: %d files, %d bytes", total_files, total_bytes)

            return f"Downloaded {total_files} file(s) ({total_bytes} bytes) from {host}:{source_normalized}"

    except Exception as e:
        error_str = str(e).lower()

        if "failed to fetch file" in error_str or "access to the path" in error_str:
            logger.debug("WinRM download failed: %s", e)
            raise

        if any(auth_err in error_str for auth_err in [
            "failed to authenticate", "unauthorized", "401", "logon_failure",
            "invalid credentials", "credentials were rejected"
        ]):
            logger.debug("WinRM authentication failed: %s", e)
            raise AuthenticationError(f"Authentication failed for {username}@{host}: {e}")

        if any(conn_err in error_str for conn_err in [
            "connection", "timeout", "refused", "unreachable", "reset"
        ]):
            logger.debug("WinRM connection failed: %s", e)
            raise ConnectionError(f"Connection failed to {host}: {e}")

        logger.debug("WinRM download failed: %s", e)
        raise
