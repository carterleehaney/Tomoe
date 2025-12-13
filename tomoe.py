import argparse
import logging

from smb import run_psexec
from wsman import run_winrm


if __name__ == "__main__":
    # Parse arguments.
    parser = argparse.ArgumentParser(usage="tomoe.py {winrm, smb} -i <ip> -u <username> -p <password> --script <script> --command <command> --args <args> -v", description="Tomoe is a python utility for cross-platform windows administration over multiple protocols in case of fail-over.")
    parser.add_argument("protocol", choices=["smb", "winrm"], help="protocol to use for remote administration")
    parser.add_argument("-i", metavar="IP", required=True, help="target host IP or hostname")
    parser.add_argument("-d", "--domain", default="", help="domain of selected user")
    parser.add_argument("-u", "--username", required=True, help="username for selected user")
    parser.add_argument("-p", "--password", required=True, help="password for selected user")

    # Script or Command; but never both.
    exec_group = parser.add_mutually_exclusive_group(required=True)
    exec_group.add_argument("--script", help="local path to PowerShell script to execute")
    exec_group.add_argument("--command", help="powershell command to execute")
    
    # Arguments to pass to the script.
    parser.add_argument("--args", default="", help="arguments to pass to the script")
    parser.add_argument("-v", "--verbose", action="store_true", help="show verbose status messages")

    args = parser.parse_args()
    
    # Set logging level based on verbose flag.
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.CRITICAL)

    # Execute the command or script based on the protocol. Probably will move to switch statement later.
    if args.protocol == "smb":
        output = run_psexec(
            target_ip=args.i,
            username=args.username,
            password=args.password,
            domain=args.domain,
            script_path=args.script,
            command=args.command,
            script_args=args.args,
            verbose=args.verbose,
        )
    elif args.protocol == "winrm":
        output = run_winrm(
            target_ip=args.i,
            username=args.username,
            password=args.password,
            domain=args.domain,
            script_path=args.script,
            command=args.command,
            script_args=args.args,
            verbose=args.verbose,
        )

    print("[*] Output:")
    print(output)
