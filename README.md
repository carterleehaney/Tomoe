## Tomoe

Tomoe is a python utility for cross-platform windows administration over multiple protocols in case of fail-over.

WinRM support is from the [pypsrp](https://pypi.org/project/pypsrp/) project.

SMB (`psexec`) functionality is from the [impacket](https://github.com/fortra/impacket) project.

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

usage: tomoe.py {smb, winrm} -i <ip/file> -u <username/file> -p <password/file> [--script <script> | --command <command> | --source <file> --dest <path>] -v

Tomoe is a python utility for cross-platform windows administration over multiple protocols in case of fail-over.

positional arguments:
  {smb,winrm}           protocol to use for remote administration

options:
  -h, --help            show this help message and exit
  -i IP                 target host IP/hostname or path to file with targets (one per line)
  -d, --domain DOMAIN   domain of selected user
  -u, --username USERNAME
                        username or path to file with usernames (one per line)
  -p, --password PASSWORD
                        password or path to file with passwords (one per line)
  -s, --script SCRIPT   local path to PowerShell script to execute
  -c, --command COMMAND
                        powershell command to execute
  --source SOURCE       local path to file or directory to copy (use with --dest)
  --dest DEST           remote destination as local Windows path, e.g. C:\Windows\Temp\file.exe (use with --source)
  -a, --args ARGS       arguments to pass to the script
  -v, --verbose         show verbose status messages
  -t, --threads THREADS
                        maximum concurrent threads (default: 10)
  -o, --output DIR      output directory to create for per-host result files
  ```

## Features

#### Command & Script Execution

Tomoe supports command execution and PowerShell script execution. When using the SMB protocol option, commands and scripts run as `NT Authority\SYSTEM`.

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
py .\tomoe.py winrm -i .\Credentials\hosts -u .\Credentials\usernames -p .\Credentials\passwords --script .\Scripts\Command.ps1 --args='-Command "whoami"'
```

```PowerShell
✓ 192.168.56.12 - Success (user: Administrator)
  Output:
    essos\administrator
```

#### File Upload

Tomoe supports file upload over both protocols, using different methods. SMB is obviously preferred, but WinRM is also supported, albeit slower. Both have very similar syntax, but there could be unexpected behavior between the two.

To copy one file, you can do the following. SMB is used in this example.

```PowerShell
py .\tomoe.py smb -i .\Credentials\hosts -u .\Credentials\usernames -p .\Credentials\passwords --source .\test.txt --dest C:\test.txt
```

By default, SMB uses the administrative C$ share.

```PowerShell
✓ 192.168.56.12 - Success (user: Administrator)
  Output:
    Copied test.txt (13 bytes) to \\192.168.56.12\C$\test.txt
```

To copy a directory (and it's recursive directories!) to another directory, you can do the following.

```PowerShell
py .\tomoe.py smb -i .\Credentials\hosts -u .\Credentials\usernames -p .\Credentials\passwords --source .\Test\ --dest C:\
```

This will place the contents of that directory in whatever directory you specified. For example, this will place the contents of "Test" into the C:\ directory.

```PowerShell
✓ 192.168.56.22 - Success (user: Administrator)
  Output:
    Copied 2 file(s) (26 bytes) to \\192.168.56.22\C$\
```

<img width="1406" height="791" alt="image" src="https://github.com/user-attachments/assets/47e15031-5cd7-4ac7-b4af-3bcb40e060ec" />


You can also specify a new directory to create to output files to. For example, this will create a new folder "Test2" and put the contents of "Test" inside of it. This works with both protocols.

```PowerShell
py .\tomoe.py winrm -i .\Credentials\hosts -u .\Credentials\usernames -p .\Credentials\passwords --source .\Test\ --dest C:\Test2
```

```PowerShell
✓ 192.168.56.23 - Success (user: Administrator)
  Output:
    Copied 2 file(s) (26 bytes) to 192.168.56.23:C:\Test2
```

