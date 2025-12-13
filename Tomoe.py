import argparse
import logging

from Function import run_psexec
from Function import run_winrm


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Run a PowerShell script or command remotely via PsExec over SMB.")
    parser.add_argument("--protocol", choices=["psexec", "winrm"], default="psexec", help="Protocol to use for remote execution (only 'psexec' and 'winrm' are supported currently)")
    parser.add_argument("-i", "--IP", metavar="IP", required=True, help="Target host IP or hostname")
    parser.add_argument("-d", "--domain", metavar="Domain", default="", help="Domain of the target user (optional)")
    parser.add_argument("-u", "--Username", metavar="Username", required=True, help="Username with rights to execute remotely")
    parser.add_argument("-p", "--Password", metavar="Password", required=True, help="Password for the remote user")

    # Script or command options (mutually exclusive)
    exec_group = parser.add_mutually_exclusive_group(required=True)
    exec_group.add_argument("--script", metavar="Script", help="Path to the local PowerShell script to run")
    exec_group.add_argument("--command", metavar="Command", help="PowerShell command to execute directly")
    
    parser.add_argument("--args", metavar="Args", default="", help="Arguments to pass to the script")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose status messages")

    args = parser.parse_args()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.CRITICAL)

    if args.protocol == "psexec":
        output = run_psexec(
            target_ip=args.IP,
            username=args.Username,
            password=args.Password,
            domain=args.domain,
            script_path=args.script,
            command=args.command,
            script_args=args.args,
            verbose=args.verbose,
        )
    elif args.protocol == "winrm":
        output = run_winrm(
            target_ip=args.IP,
            username=args.Username,
            password=args.Password,
            domain=args.domain,
            script_path=args.script,
            command=args.command,
            script_args=args.args,
            verbose=args.verbose,
        )

    print("[*] Output:")
    print(output)