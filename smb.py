import sys
import os
import logging
import time
from threading import Thread, Lock, Event
import random
import string
import socket
from six import PY3

from impacket import smb
from impacket.structure import Structure
from impacket.examples import remcomsvc, serviceinstall
from impacket.dcerpc.v5 import transport
from impacket.smbconnection import SMBConnection

LastDataSent = b""

CODEC = sys.stdout.encoding or 'utf-8'

class SMBAuthenticationError(Exception):
    """Raised when SMB authentication fails due to invalid credentials."""
    pass


class SMBConnectionError(Exception):
    """Raised when an SMB connection cannot be established to the target host."""
    pass

def check_port_open(host, port=445, timeout=5):
    """
    Perform a quick TCP connectivity check to determine if a port is open.
    
    This function attempts to establish a TCP connection to the specified host
    and port. It is used as a pre-flight check before attempting SMB operations
    to avoid long timeout delays when the target is unreachable.
    
    Args:
        host: The hostname or IP address to check.
        port: The TCP port number to test (default is 445 for SMB).
        timeout: The connection timeout in seconds (default is 5 seconds).
    
    Returns:
        True if the port is open and accepting connections, False otherwise.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error:
        return False

class RemComMessage(Structure):
    structure = (
        ('Command','4096s=""'),
        ('WorkingDir','260s=""'),
        ('Priority','<L=0x20'),
        ('ProcessID','<L=0x01'),
        ('Machine','260s=""'),
        ('NoWait','<L=0'),
    )

class RemComResponse(Structure):
    structure = (
        ('ErrorCode','<L=0'),
        ('ReturnCode','<L=0'),
    )

RemComSTDOUT = "RemCom_stdout"
RemComSTDIN = "RemCom_stdin"
RemComSTDERR = "RemCom_stderr"

lock = Lock()

def openPipe(s, tid, pipe, accessMask):
    """
    Wait for a named pipe to become ready and open it.
    Returns the file ID on success, raises exception on timeout.
    """
    pipeReady = False
    tries = 50
    while pipeReady is False and tries > 0:
        try:
            s.waitNamedPipe(tid, pipe)
            pipeReady = True
        except:
            tries -= 1
            time.sleep(2)
            pass

    if tries == 0:
        raise Exception('Pipe not ready, aborting')

    fid = s.openFile(tid, pipe, accessMask, creationOption=0x40, fileAttributes=0x80)
    return fid

def run_psexec(target_ip, username, password, domain="", script_path=None, command=None, script_args="", verbose=False):
    """
    Execute a command or script remotely using impacket's psexec functionality over SMB.
    
    This function uses the impacket library to establish an SMB connection and execute
    PowerShell commands or scripts on a remote Windows host. It uploads a service binary,
    starts it remotely, and captures the output through named pipes.
    
    Args:
        target_ip: The IP address or hostname of the remote Windows machine.
        username: The username for authentication (can be in DOMAIN\\username format).
        password: The password for authentication.
        domain: Optional domain name for domain-joined authentication.
        script_path: Path to a local PowerShell script file to execute remotely.
        command: A PowerShell command string to execute (mutually exclusive with script_path).
        script_args: Arguments to pass to the script when using script_path.
        verbose: If True, print detailed status messages during execution.
    
    Returns:
        A string containing the combined output from stdout and stderr.
    
    Raises:
        SMBConnectionError: If the connection to the target host fails.
        SMBAuthenticationError: If authentication fails due to invalid credentials.
        ValueError: If neither script_path nor command is provided.
    """
    
    # Extract domain from username if in DOMAIN\username format
    if '\\' in username:
        domain, username = username.split('\\', 1)
    
    # Suppress impacket's verbose logging before any operations
    impacket_logger = logging.getLogger('impacket')
    impacket_logger.setLevel(logging.CRITICAL + 1)  # Effectively disable all impacket logging
    
    if verbose:
        logging.info(f"Preparing to execute on {target_ip} as {domain}\\{username}")
        impacket_logger.setLevel(logging.INFO)

    # Perform a quick connectivity check before attempting SMB.
    # This prevents long timeout delays when the target is unreachable.
    if not check_port_open(target_ip, 445, timeout=5):
        raise SMBConnectionError(f"Port 445 not reachable on {target_ip}")
    
    script_name = None
    unInstalled = False

    if verbose:
        logging.basicConfig(level=logging.INFO, force=True)
    else:
        logging.basicConfig(level=logging.ERROR, force=True)

    stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % target_ip
    if verbose:
        logging.debug(f'StringBinding {stringbinding}')
    
    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    rpctransport.set_dport(445)
    rpctransport.setRemoteHost(target_ip)
    
    if hasattr(rpctransport, 'set_credentials'):
        rpctransport.set_credentials(username, password, domain, '', '')

    dce = rpctransport.get_dce_rpc()
    try:
        dce.connect()
    except Exception as e:
        if verbose:
            logging.error(f"Failed to connect to {target_ip} via SMB: {e}")
        raise
    

    try:
        s = rpctransport.get_smb_connection()
        s.setTimeout(100000)

        dialect = s.getDialect()
        
        # Use dynamic service name to avoid conflicts
        service_name = f"TomoeService_{random.randint(10000, 99999)}"
        installService = serviceinstall.ServiceInstall(s, remcomsvc.RemComSvc(), service_name, "TomoeSMB.exe")
        if verbose:
            logging.info(f"Using service name: {service_name}")

        # Clean up any existing service
        if verbose:
            logging.info("Checking for existing TomoeService...")
        try:
            installService.uninstall()
            time.sleep(2)
        except:
            pass

        if verbose:
            logging.info("Installing fresh TomoeService...")
        if not installService.install():
            raise Exception("Failed to install service")

        # Build command
        if command:
            # Format output with full names - no truncation
            cmd_args = f'powershell.exe -NoProfile -NonInteractive -Command "{command} | Format-Table -AutoSize -Wrap | Out-String -Width 4096"'
        elif script_path:
            script_name = os.path.basename(script_path)
            installService.copy_file(script_path, installService.getShare(), script_name)
            
            # Execute directly from SMB share using UNC path
            unc_path = f"\\\\{target_ip}\\{installService.getShare()}\\{script_name}"
            cmd_args = f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{unc_path}" {script_args}'
        else:
            raise ValueError("Either command or script_path is required")

        if verbose:
            logging.info(f"Command to execute: {cmd_args}")

        # Open communication pipe
        tid = s.connectTree('IPC$')
        fid_main = openPipe(s, tid, r'\RemCom_communicaton', 0x12019f)

        # Create packet with command
        packet = RemComMessage()
        packet['Machine'] = ''.join([random.choice(string.ascii_letters) for _ in range(4)])
        packet['WorkingDir'] = ''
        packet['Command'] = cmd_args
        packet['ProcessID'] = os.getpid()

        if verbose:
            logging.info("Starting pipe threads...")

        stdin_pipe = RemoteStdInPipe(rpctransport,
            r'\%s%s%d' % (RemComSTDIN, packet['Machine'], packet['ProcessID']),
            smb.FILE_WRITE_DATA | smb.FILE_APPEND_DATA, installService.getShare(),
            dialect
        )
        stdout_pipe = RemoteStdOutPipe(
            rpctransport,
            r'\%s%s%d' % (RemComSTDOUT, packet['Machine'], packet['ProcessID']),
            smb.FILE_READ_DATA,
            dialect
        )
        stderr_pipe = RemoteStdErrPipe(
            rpctransport,
            r'\%s%s%d' % (RemComSTDERR, packet['Machine'], packet['ProcessID']),
            smb.FILE_READ_DATA,
            dialect
        )
        
        stdin_pipe.start()
        stdout_pipe.start()
        stderr_pipe.start()

        if verbose:
            logging.info("Sending command to RemCom service...")
        s.writeNamedPipe(tid, fid_main, packet.getData())

        # Block until response
        if verbose:
            logging.info("Reading command response...")
        ans = s.readNamedPipe(tid, fid_main, 8)
        
        if len(ans):
            retCode = RemComResponse(ans)
            if verbose:
                logging.info(f"Process finished with ErrorCode: {retCode['ErrorCode']}, ReturnCode: {retCode['ReturnCode']}")
        else:
            retCode = RemComResponse()

        # Adaptively wait for pipes to capture output - detect when output stops flowing
        idle_count = 0
        prev_stdout_len = 0
        prev_stderr_len = 0
        start = time.time()
        max_wait = 10
        
        if verbose:
            logging.info("Waiting for output capture...")
        
        while time.time() - start < max_wait and idle_count < 2:
            curr_stdout = len(stdout_pipe.output)
            curr_stderr = len(stderr_pipe.output)
            if curr_stdout == prev_stdout_len and curr_stderr == prev_stderr_len:
                idle_count += 1
            else:
                idle_count = 0
            prev_stdout_len = curr_stdout
            prev_stderr_len = curr_stderr
            time.sleep(0.5)
        
        if verbose:
            logging.info(f"Output capture complete (waited {time.time() - start:.1f}s)")
        
        # Signal threads to stop
        stdin_pipe.stop.set()
        stdout_pipe.stop.set()
        stderr_pipe.stop.set()
        
        # Give threads a moment to process the stop signal
        time.sleep(0.1)
        
        # Join threads with timeout to ensure proper cleanup
        stdin_pipe.join(5.0)
        stdout_pipe.join(5.0)
        stderr_pipe.join(5.0)
        
        # Collect output from pipes and strip carriage returns
        stdout_text = b"".join(stdout_pipe.output).decode(CODEC, errors="replace").replace('\r', '').strip() if stdout_pipe.output else ""
        stderr_text = b"".join(stderr_pipe.output).decode(CODEC, errors="replace").replace('\r', '').strip() if stderr_pipe.output else ""
        
        if verbose:
            logging.info(f"Output captured: stdout={len(stdout_text)} chars, stderr={len(stderr_text)} chars")

        # Cleanup
        installService.uninstall()
        unInstalled = True
        
        if script_name:
            try:
                s.deleteFile(installService.getShare(), script_name)
            except:
                pass

        # Validate command execution and provide meaningful error messages
        if stderr_text and ("is not recognized" in stderr_text or "cannot be loaded" in stderr_text):
            if verbose:
                logging.error(f"Command execution failed: {stderr_text}")
            return f"ERROR: {stderr_text}"
        
        if not stdout_text and not stderr_text and retCode['ReturnCode'] != 0:
            error_msg = f"Command failed with return code {retCode['ReturnCode']}"
            if verbose:
                logging.error(error_msg)
            return error_msg
        
        # Return combined output: stdout first, then stderr, preserving all streams
        if stdout_text and stderr_text:
            return stdout_text + "\n" + stderr_text
        if stdout_text:
            return stdout_text
        if stderr_text:
            return stderr_text
        return f"Command executed with ErrorCode: {retCode['ErrorCode']}"

    except Exception as e:
        if verbose:
            logging.error(f"SMB execution failed: {e}")
        if not unInstalled:
            try:
                installService.uninstall()
            except:
                pass
            if script_name:
                try:
                    s.deleteFile(installService.getShare(), script_name)
                except:
                    pass
        raise


class Pipes(Thread):
    def __init__(self, transport, pipe, permissions, share=None, dialect=None):
        Thread.__init__(self)
        self.server = 0
        self.transport = transport
        self.credentials = transport.get_credentials()
        self.tid = 0
        self.fid = 0
        self.share = share
        self.port = transport.get_dport()
        self.pipe = pipe
        self.permissions = permissions
        self.daemon = True
        self.stop = Event()
        self.max_runtime = 300  # 5 minute timeout per pipe
        self.start_time = None
        self.dialect = dialect

    def connectPipe(self):
        try:
            lock.acquire()
            try:
                self.server = SMBConnection(self.transport.get_smb_connection().getRemoteName(), self.transport.get_smb_connection().getRemoteHost(),
                                            sess_port=self.port, preferredDialect=self.dialect)
                user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
                if self.transport.get_kerberos() is True:
                    self.server.kerberosLogin(user, passwd, domain, lm, nt, aesKey, kdcHost=self.transport.get_kdcHost(), TGT=TGT, TGS=TGS)
                else:
                    self.server.login(user, passwd, domain, lm, nt)
            finally:
                lock.release()
            self.tid = self.server.connectTree('IPC$')

            # Wait for pipe with retry logic
            pipeReady = False
            tries = 50
            while pipeReady is False and tries > 0:
                try:
                    self.server.waitNamedPipe(self.tid, self.pipe)
                    pipeReady = True
                except:
                    tries -= 1
                    time.sleep(2)
                    pass
            
            if tries == 0:
                logging.error(f'Pipe {self.pipe} not ready after {50*2}s, aborting')
                raise Exception(f'Pipe {self.pipe} not ready, aborting')
            
            self.fid = self.server.openFile(self.tid, self.pipe, self.permissions, creationOption=0x40, fileAttributes=0x80)
            self.server.setTimeout(1000000)
            self.start_time = time.time()
            logging.debug(f"Pipe {self.pipe} connected successfully")
        except Exception as e:
            logging.error(f"Failed to connect to pipe {self.pipe}: {e}")
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            raise



class RemoteStdOutPipe(Pipes):
    def __init__(self, transport, pipe, permisssions, dialect=None):
        Pipes.__init__(self, transport, pipe, permisssions, dialect=dialect)
        self.output = []

    def run(self):
        self.connectPipe()

        if PY3:
            while not self.stop.is_set():
                # Check timeout protection inside the loop
                if self.start_time and (time.time() - self.start_time) > self.max_runtime:
                    logging.warning(f"Pipe {self.pipe} exceeded max runtime of {self.max_runtime}s")
                    break
                try:
                    stdout_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                    if len(stdout_ans) > 0:
                        self.output.append(stdout_ans)
                except Exception as e:
                    logging.debug(f"Exception reading from stdout pipe {self.pipe}: {e}")
                    pass
        else:
            while not self.stop.is_set():
                # Check timeout protection inside the loop
                if self.start_time and (time.time() - self.start_time) > self.max_runtime:
                    logging.warning(f"Pipe {self.pipe} exceeded max runtime of {self.max_runtime}s")
                    break
                try:
                    stdout_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                    if len(stdout_ans) > 0:
                        data = stdout_ans if isinstance(stdout_ans, bytes) else stdout_ans.encode(CODEC)
                        self.output.append(data)
                except Exception as e:
                    logging.debug(f"Exception reading from stdout pipe {self.pipe}: {e}")
                    pass


class RemoteStdErrPipe(Pipes):
    def __init__(self, transport, pipe, permisssions, dialect=None):
        Pipes.__init__(self, transport, pipe, permisssions, dialect=dialect)
        self.output = []

    def run(self):
        self.connectPipe()

        if PY3:
            while not self.stop.is_set():
                # Check timeout protection inside the loop
                if self.start_time and (time.time() - self.start_time) > self.max_runtime:
                    logging.warning(f"Pipe {self.pipe} exceeded max runtime of {self.max_runtime}s")
                    break
                try:
                    stderr_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                    if len(stderr_ans) > 0:
                        self.output.append(stderr_ans)
                except Exception as e:
                    logging.debug(f"Exception reading from stderr pipe {self.pipe}: {e}")
                    pass
        else:
            while not self.stop.is_set():
                # Check timeout protection inside the loop
                if self.start_time and (time.time() - self.start_time) > self.max_runtime:
                    logging.warning(f"Pipe {self.pipe} exceeded max runtime of {self.max_runtime}s")
                    break
                try:
                    stderr_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                    if len(stderr_ans) > 0:
                        data = stderr_ans if isinstance(stderr_ans, bytes) else stderr_ans.encode(CODEC)
                        self.output.append(data)
                except Exception as e:
                    logging.debug(f"Exception reading from stderr pipe {self.pipe}: {e}")
                    pass



class RemoteStdInPipe(Pipes):
    def __init__(self, transport, pipe, permisssions, share=None, dialect=None):
        self.shell = None
        Pipes.__init__(self, transport, pipe, permisssions, share, dialect)

    def run(self):
        self.connectPipe()
        # Non-interactive mode - just keep pipe open
        while not self.stop.is_set():
            time.sleep(1)


def run_smb_copy(target_ip, username, password, domain="", source="", dest="", verbose=False):
    """
    Copy a local file or directory to a remote Windows host using SMB.
    
    This function establishes an SMB connection and uploads a file or directory
    from the local system to a specified path on the remote host. If the source
    is a directory, it recursively copies all files and subdirectories.
    
    Args:
        target_ip: The IP address or hostname of the remote Windows machine.
        username: The username for authentication (can be in DOMAIN\\username format).
        password: The password for authentication.
        domain: Optional domain name for domain-joined authentication.
        source: Path to the local file or directory to copy.
        dest: Remote destination as a local Windows path (e.g., "C:\\Windows\\Temp\\folder").
        verbose: If True, print detailed status messages during execution.
    
    Returns:
        A string containing a success message with files/bytes transferred.
    
    Raises:
        SMBConnectionError: If the connection to the target host fails.
        SMBAuthenticationError: If authentication fails due to invalid credentials.
        FileNotFoundError: If the source file/directory does not exist.
        ValueError: If the destination path format is invalid.
    """
    
    # Extract domain from username if in DOMAIN\username format
    if '\\' in username:
        domain, username = username.split('\\', 1)
    
    # Suppress impacket's verbose logging before any operations
    impacket_logger = logging.getLogger('impacket')
    impacket_logger.setLevel(logging.CRITICAL + 1)
    
    if verbose:
        logging.info(f"Preparing to copy to {target_ip} as {domain}\\{username}")
        impacket_logger.setLevel(logging.INFO)
    
    # Validate source exists
    if not os.path.exists(source):
        raise FileNotFoundError(f"Source not found: {source}")
    
    # Parse destination as a local Windows path (e.g., "C:\Windows\Temp\file.exe")
    # Convert to SMB path using C$ share
    dest_normalized = dest.replace('/', '\\')
    
    # Remove leading backslashes if present
    dest_normalized = dest_normalized.lstrip('\\')
    
    # Expect format like "C:\path\to\file" - extract drive letter and path
    if len(dest_normalized) < 3 or dest_normalized[1] != ':':
        raise ValueError(f"Invalid destination format. Expected Windows path like 'C:\\path\\to\\file', got: {dest}")
    
    # Use C$ admin share
    share = "C$"
    # Remove "C:\" prefix to get the path relative to the share
    remote_base_path = dest_normalized[3:] if len(dest_normalized) > 3 else ""
    
    if verbose:
        logging.info(f"Share: {share}, Remote base path: {remote_base_path}")
    
    # Perform a quick connectivity check before attempting SMB
    if not check_port_open(target_ip, 445, timeout=5):
        raise SMBConnectionError(f"Port 445 not reachable on {target_ip}")
    
    try:
        # Establish SMB connection
        if verbose:
            logging.info(f"Connecting to {target_ip}...")
        
        smb_connection = SMBConnection(target_ip, target_ip, timeout=30)
        
        # Authenticate
        if verbose:
            logging.info(f"Authenticating as {domain}\\{username}...")
        
        try:
            smb_connection.login(username, password, domain)
        except Exception as e:
            error_msg = str(e).lower()
            auth_error_patterns = [
                "logon_failure", "access_denied", "status_logon_failure",
                "bad password", "wrong password", "invalid credentials"
            ]
            if any(pattern in error_msg for pattern in auth_error_patterns):
                raise SMBAuthenticationError(f"Authentication failed for {username}: {e}")
            raise
        
        # Check if source is a file or directory
        if os.path.isfile(source):
            # Single file copy
            file_size = os.path.getsize(source)
            remote_path = remote_base_path if remote_base_path else os.path.basename(source)
            
            if verbose:
                logging.info(f"Uploading {source} ({file_size} bytes) to \\\\{target_ip}\\{share}\\{remote_path}...")
            
            with open(source, 'rb') as local_file:
                smb_connection.putFile(share, remote_path, local_file.read)
            
            smb_connection.close()
            
            if verbose:
                logging.info(f"File copied successfully: {file_size} bytes")
            
            return f"Copied {os.path.basename(source)} ({file_size} bytes) to \\\\{target_ip}\\{share}\\{remote_path}"
        
        else:
            # Directory copy - recursive
            total_files = 0
            total_bytes = 0
            
            # Walk through all files and subdirectories
            for root, dirs, files in os.walk(source):
                # Calculate relative path from source directory
                rel_root = os.path.relpath(root, source)
                if rel_root == ".":
                    rel_root = ""
                
                # Create remote directory path
                if rel_root:
                    remote_dir = remote_base_path + "\\" + rel_root.replace('/', '\\') if remote_base_path else rel_root.replace('/', '\\')
                else:
                    remote_dir = remote_base_path
                
                # Create remote directories (SMB createDirectory for each level)
                if remote_dir:
                    # Create directory hierarchy
                    dir_parts = remote_dir.split('\\')
                    current_path = ""
                    for part in dir_parts:
                        if not part:
                            continue
                        current_path = current_path + "\\" + part if current_path else part
                        try:
                            smb_connection.createDirectory(share, current_path)
                            if verbose:
                                logging.info(f"Created directory: \\\\{target_ip}\\{share}\\{current_path}")
                        except Exception:
                            # Directory may already exist, ignore
                            pass
                
                # Copy each file
                for filename in files:
                    local_file_path = os.path.join(root, filename)
                    if remote_dir:
                        remote_file_path = remote_dir + "\\" + filename
                    else:
                        remote_file_path = filename
                    
                    file_size = os.path.getsize(local_file_path)
                    
                    if verbose:
                        logging.info(f"Uploading {local_file_path} ({file_size} bytes) to \\\\{target_ip}\\{share}\\{remote_file_path}...")
                    
                    with open(local_file_path, 'rb') as f:
                        smb_connection.putFile(share, remote_file_path, f.read)
                    
                    total_files += 1
                    total_bytes += file_size
            
            smb_connection.close()
            
            if verbose:
                logging.info(f"Directory copied successfully: {total_files} files, {total_bytes} bytes")
            
            return f"Copied {total_files} file(s) ({total_bytes} bytes) to \\\\{target_ip}\\{share}\\{remote_base_path}"
    
    except SMBAuthenticationError:
        raise
    except SMBConnectionError:
        raise
    except Exception as e:
        error_msg = str(e).lower()
        auth_error_patterns = [
            "logon_failure", "access_denied", "status_logon_failure",
            "bad password", "wrong password", "invalid credentials",
            "authentication", "unauthorized", "rejected"
        ]
        if any(pattern in error_msg for pattern in auth_error_patterns):
            raise SMBAuthenticationError(f"Authentication failed: {e}")
        raise