## Tomoe

Tomoe is a python utility for remote administration over multiple protocols with credential fail-over across hosts.

- **WinRM** — [pypsrp](https://pypi.org/project/pypsrp/)
- **SMB** — [pypsexec](https://pypi.org/project/pypsexec/)
- **SSH** — [paramiko](https://pypi.org/project/paramiko/)

```PowerShell
PS C:\Users\carte\Documents\GitHub\Tomoe> py .\tomoe.py winrm -i .\Credentials\hosts -u .\Credentials\usernames -p .\Credentials\passwords --command "whoami"

  Targets: 5 host(s)
  Credentials: 4 user(s) x 4 password(s)
  Protocol: winrm

                             Tomoe
┏━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┓
┃ Host          ┃ Status  ┃ Username      ┃ Message           ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━┩
│ 192.168.56.10 │ Success │ Administrator │ Command executed. │
│ 192.168.56.11 │ Success │ Administrator │ Command executed. │
│ 192.168.56.12 │ Success │ Administrator │ Command executed. │
│ 192.168.56.22 │ Success │ Administrator │ Command executed. │
│ 192.168.56.23 │ Success │ Administrator │ Command executed. │
└───────────────┴─────────┴───────────────┴───────────────────┘

Execution Results

✓ 192.168.56.11 - Success (user: Administrator)
  Output:
    north\administrator

✓ 192.168.56.23 - Success (user: Administrator)
  Output:
    braavos\administrator

✓ 192.168.56.12 - Success (user: Administrator)
  Output:
    essos\administrator

✓ 192.168.56.10 - Success (user: Administrator)
  Output:
    sevenkingdoms\administrator

✓ 192.168.56.22 - Success (user: Administrator)
  Output:
    castelblack\administrator


Summary: 5/5 hosts successful
```

## Usage

Ensure you have all requirements installed.

`pip install -r requirements.txt`

```PowerShell
py tomoe.py -h

usage: tomoe.py {smb, winrm, ssh} -i <ip/file> -u <username/file> -p <password/file> [--script <script> | --command <command> | --upload <source> <dest> | --download <source> <dest>]

Tomoe is a python utility for remote administration over multiple protocols in case of fail-over.

positional arguments:
  {smb,winrm,ssh}       protocol to use for remote administration

options:
  -h, --help            show this help message and exit
  -i IP                 target host IP/hostname or path to file with targets (one per line)
  -d, --domain DOMAIN   domain of selected user
  -u, --username USERNAME
                        username or path to file with usernames (one per line)
  -p, --password PASSWORD
                        password or path to file with passwords (one per line)
  --os {windows,linux}  target host OS (default: windows). Only applies to SSH.
  -s, --script SCRIPT   local path to script to execute (PowerShell on Windows, bash on Linux)
  -c, --command COMMAND
                        command to execute (PowerShell on Windows, shell on Linux)
  --upload SOURCE DEST  upload local SOURCE to remote DEST
  --download SOURCE DEST
                        download remote SOURCE to local DEST
  -a, --args ARGS       arguments to pass to the script
  --shell {powershell,cmd}
                        shell type for SMB protocol (default: powershell)
  --no-encrypt          disable SMB encryption (encryption is enabled by default)
  -v, --verbose         show verbose status messages
  -t, --threads THREADS
                        maximum concurrent threads (default: 10)
  -o, --output DIR      output directory to create for per-host result files
  ```

## Features

#### Protocols

- **WinRM** — Remote PowerShell; commands and scripts run in the context of the authenticated user.
- **SMB** — PsExec-style execution; commands and scripts run as `NT Authority\SYSTEM`. Supports `--shell powershell|cmd` and `--no-encrypt` to disable SMB encryption.
- **SSH** — Remote shell and file transfer for Windows or Linux (`--os windows|linux`). Uses Paramiko; PowerShell on Windows, bash on Linux.

#### Command & Script Execution

Tomoe supports command execution and script execution. When using the SMB protocol, commands and scripts run as `NT Authority\SYSTEM`.

```PowerShell
✓ 192.168.56.23 - Success (user: Administrator)
Output:
nt authority\system
```

When using the WinRM protocol option, commands and scripts run in the context of the current user.

```PowerShell
✓ 192.168.56.11 - Success (user: Administrator)
  Output:
    north\administrator
```

Arguments have a small quirk to make note of. When passing arguments to a script, please add a `=` character after your -a/--args argument. For example, the script being executed will execute a command passed to the "-Command" argument. You can wrap your arguments in either `'` or `"` characters, depending on if your arguments for the actual script require one or the other.

```PowerShell
py .\tomoe.py winrm -i .\Credentials\hosts -u .\Credentials\usernames -p .\Credentials\passwords -s .\Scripts\Command.ps1 -a='-Command "whoami"'
```

```PowerShell
✓ 192.168.56.12 - Success (user: Administrator)
  Output:
    essos\administrator
```

#### File Upload

Use `--upload SOURCE DEST` to copy files or directories from your machine to the remote host(s). Supported with WinRM, SMB, and SSH. SMB uses the administrative C$ share by default and is typically faster for Windows targets.

Single file:

```PowerShell
py .\tomoe.py smb -i .\Credentials\hosts -u .\Credentials\usernames -p .\Credentials\passwords --upload .\test.txt C:\test.txt
```

```PowerShell
✓ 192.168.56.12 - Success (user: Administrator)
  Output:
    Copied test.txt (13 bytes) to \\192.168.56.12\C$\test.txt
```

Directory (recursive):

```PowerShell
py .\tomoe.py smb -i .\Credentials\hosts -u .\Credentials\usernames -p .\Credentials\passwords --upload .\Test\ C:\
```

```PowerShell
✓ 192.168.56.22 - Success (user: Administrator)
  Output:
    Copied 2 file(s) (26 bytes) to \\192.168.56.22\C$\
```

Creating a new directory on the remote host (e.g. `C:\Test2`) works with SMB, WinRM, and SSH:

```PowerShell
py .\tomoe.py winrm -i .\Credentials\hosts -u .\Credentials\usernames -p .\Credentials\passwords --upload .\Test\ C:\Test2
```

```PowerShell
✓ 192.168.56.23 - Success (user: Administrator)
  Output:
    Copied 2 file(s) (26 bytes) to 192.168.56.23:C:\Test2
```

#### File Download

Use `--download SOURCE DEST` to pull files or directories from the remote host(s) to your machine. Supported with WinRM, SMB, and SSH. When targeting multiple hosts, Tomoe creates per-host subdirectories under the local `DEST` so results do not overwrite each other.

```PowerShell
py .\tomoe.py winrm -i .\Credentials\hosts -u .\Credentials\usernames -p .\Credentials\passwords --download C:\logs\app.log .\results
```

For SSH on Linux targets, use `--os linux` and remote paths as on the server (e.g. `/var/log/app.log`).

#### Output Files

Use `-o DIR` to write each host's command or script output to a file under `DIR` (e.g. `DIR\<host>.txt`).

<img width="1406" height="791" alt="image" src="https://github.com/user-attachments/assets/47e15031-5cd7-4ac7-b4af-3bcb40e060ec" />

