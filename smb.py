import sys
import os
import re
import logging
import time
from threading import Thread, Lock, Event
import random
import string
from six import PY3

from impacket import smb
from impacket.structure import Structure
from impacket.examples import remcomsvc, serviceinstall
from impacket.dcerpc.v5 import transport
from impacket.smbconnection import SMBConnection

dialect = None
LastDataSent = b""

CODEC = sys.stdout.encoding

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
    Simplified to match the original psexec.py approach.
    """
    script_name = None
    unInstalled = False

    if verbose:
        logging.basicConfig(level=logging.INFO, force=True)
    else:
        logging.disable(logging.CRITICAL)

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
            logging.critical(str(e))
        raise

    try:
        s = rpctransport.get_smb_connection()
        s.setTimeout(100000)

        global dialect
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
            # Upload script file using installService.copy_file (same as psexec.py)
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

        # Start pipes - they'll print output directly
        stdin_pipe = RemoteStdInPipe(rpctransport,
            r'\%s%s%d' % (RemComSTDIN, packet['Machine'], packet['ProcessID']),
            smb.FILE_WRITE_DATA | smb.FILE_APPEND_DATA, installService.getShare()
        )
        stdout_pipe = RemoteStdOutPipe(
            rpctransport,
            r'\%s%s%d' % (RemComSTDOUT, packet['Machine'], packet['ProcessID']),
            smb.FILE_READ_DATA
        )
        stderr_pipe = RemoteStdErrPipe(
            rpctransport,
            r'\%s%s%d' % (RemComSTDERR, packet['Machine'], packet['ProcessID']),
            smb.FILE_READ_DATA
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
        
        # Return stderr if present, else stdout
        if stderr_text:
            return stderr_text
        return stdout_text if stdout_text else f"Command executed with ErrorCode: {retCode['ErrorCode']}"

    except Exception as e:
        if verbose:
            logging.error(f"PsExec execution failed: {e}")
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
    def __init__(self, transport, pipe, permissions, share=None):
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

    def connectPipe(self):
        try:
            lock.acquire()
            global dialect
            #self.server = SMBConnection('*SMBSERVER', self.transport.get_smb_connection().getRemoteHost(), sess_port = self.port, preferredDialect = SMB_DIALECT)
            self.server = SMBConnection(self.transport.get_smb_connection().getRemoteName(), self.transport.get_smb_connection().getRemoteHost(),
                                        sess_port=self.port, preferredDialect=dialect)
            user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
            if self.transport.get_kerberos() is True:
                self.server.kerberosLogin(user, passwd, domain, lm, nt, aesKey, kdcHost=self.transport.get_kdcHost(), TGT=TGT, TGS=TGS)
            else:
                self.server.login(user, passwd, domain, lm, nt)
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
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)
        self.output = []

    def run(self):
        self.connectPipe()
        
        # Add timeout protection
        if self.start_time and (time.time() - self.start_time) > self.max_runtime:
            logging.warning(f"Pipe {self.pipe} exceeded max runtime of {self.max_runtime}s")
            return

        if PY3:
            while True:
                try:
                    stdout_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                    if len(stdout_ans) > 0:
                        self.output.append(stdout_ans)
                except:
                    pass
        else:
            while True:
                try:
                    stdout_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                    if len(stdout_ans) > 0:
                        data = stdout_ans if isinstance(stdout_ans, bytes) else stdout_ans.encode(CODEC)
                        self.output.append(data)
                except:
                    pass


class RemoteStdErrPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)
        self.output = []

    def run(self):
        self.connectPipe()
        
        # Add timeout protection
        if self.start_time and (time.time() - self.start_time) > self.max_runtime:
            logging.warning(f"Pipe {self.pipe} exceeded max runtime of {self.max_runtime}s")
            return

        if PY3:
            while True:
                try:
                    stderr_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                    if len(stderr_ans) > 0:
                        self.output.append(stderr_ans)
                except:
                    pass
        else:
            while True:
                try:
                    stderr_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                    if len(stderr_ans) > 0:
                        data = stderr_ans if isinstance(stderr_ans, bytes) else stderr_ans.encode(CODEC)
                        self.output.append(data)
                except:
                    pass



class RemoteStdInPipe(Pipes):
    def __init__(self, transport, pipe, permisssions, share=None):
        self.shell = None
        Pipes.__init__(self, transport, pipe, permisssions, share)

    def run(self):
        self.connectPipe()
        # Non-interactive mode - just keep pipe open
        while True:
            time.sleep(1)