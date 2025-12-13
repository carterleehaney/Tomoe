import winrm

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

