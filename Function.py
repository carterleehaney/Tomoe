import winrm
from psexec import PSEXEC

def run_psexec(target_ip, username, password, domain="", script_path=None, command=None, script_args="", verbose=False):
    # Determine what to execute
    if script_path:
        if verbose:
            print(f"[*] Reading local script: {script_path}")
        copy_file = script_path
        # Pass args as a named parameter to the script, quoted properly
        if script_args:
            cmd_args = f"{script_args}"
        else:
            cmd_args = ""
    elif command:
        if verbose:
            print(f"[*] Executing command: {command}")
        copy_file = None
        cmd_args = f'powershell.exe -Command "{command}"'
    else:
        raise ValueError("Either --script or --command must be provided")

    executer = PSEXEC(
        command=cmd_args,
        path=None,
        exeFile=None,
        copyFile=copy_file,
        port=445,
        serviceName="RunBetterService",             #! CHANGE THIS WITH NEW NAME
        remoteBinaryName="RunBetter.exe",
        domain=domain,
        username=username,
        password=password,
        capture_output=True,
        verbose=verbose,
    )

    # Run it
    if verbose:
        print(f"[*] Executing on {target_ip}...")
    try:
        result = executer.run(remoteName=target_ip, remoteHost=target_ip)
        # result is (error_code, return_code, stdout, stderr)
        if result is None:
            return ""
        errcode, retcode, out, err = result
        if verbose:
            print(f"[+] Remote ErrorCode: {errcode}")
            print(f"[+] Remote ReturnCode: {retcode}")
        # return straight stdout
        return out or ""
    except Exception as e:
        if verbose:
            print(f"[!] PsExec Failed: {e}")
        raise

def run_winrm(target_ip, username, password, domain="", script_path=None, command=None, script_args="", verbose=False):
    # Create a WinRM session
    if domain:
        session = winrm.Session(f'http://{target_ip}:5985/wsman', auth=(f'{domain}\\{username}', password))
    else:
        session = winrm.Session(f'http://{target_ip}:5985/wsman', auth=(username, password))

    # Determine what to execute
    if script_path:
        if verbose:
            print(f"[*] Reading local script: {script_path}")
        with open(script_path, 'r') as file:
            script_content = file.read()
        cmd = f'powershell.exe -Command "{script_content} {script_args}"'
    elif command:
        if verbose:
            print(f"[*] Executing command: {command}")
        cmd = f'powershell.exe -Command "{command}"'
    else:
        raise ValueError("Either --script or --command must be provided")

    # Execute the command
    if verbose:
        print(f"[*] Executing on {target_ip} via WinRM...")
    try:
        result = session.run_cmd(cmd)
        if verbose:
            print(f"[+] Command executed with status code: {result.status_code}")
            print(f"[+] Stdout: {result.std_out.decode()}")
            print(f"[+] Stderr: {result.std_err.decode()}")
    except Exception as e:
        if verbose:
            print(f"[!] WinRM execution failed: {e}")
        raise

    return result.std_out.decode() or ""