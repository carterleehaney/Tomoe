import sys
import os
import re
import logging
import time
from threading import Thread, Lock
import random
import string
from six import PY3

from impacket import version, smb
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
    """
    remote_name = None  # Initialize before try block for exception handler scope

    # if script_path:
    #     if verbose:
    #         print(f"[*] Reading local script: {script_path}")
    #     copy_file = script_path
    #     # Pass args as a named parameter to the script, quoted properly
    #     if script_args:
    #         cmd_args = f"{script_args}"
    #     else:
    #         cmd_args = ""
    # elif command:
    #     if verbose:
    #         print(f"[*] Executing command: {command}")
    #     copy_file = None
    #     cmd_args = f'powershell.exe -Command "{command}"'
    # else:
    #     raise ValueError("Either --script or --command must be provided")

    # Set up logging
    if verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.CRITICAL)

    # Create string binding for RPC transport
    stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % target_ip
    if verbose:
        logging.debug(f'StringBinding {stringbinding}')
    
    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    rpctransport.set_dport(445)
    rpctransport.setRemoteHost(target_ip)
    
    # Set credentials
    if hasattr(rpctransport, 'set_credentials'):
        rpctransport.set_credentials(username, password, domain, '', '')

    # Get DCE RPC connection
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
        
        installService = serviceinstall.ServiceInstall(s, remcomsvc.RemComSvc(), "TomoeService", "TomoeSMB.exe")

        # Clean up any existing service from previous run
        if verbose:
            logging.info("Checking for existing TomoeService...")
        try:
            installService.uninstall()
            time.sleep(2)  # Wait for service to fully stop and remove
            if verbose:
                logging.info("Cleaned up old service")
        except Exception as e:
            if verbose:
                logging.info(f"No existing service to clean up")
            pass

        # Now install fresh
        if verbose:
            logging.info("Installing fresh TomoeService...")
        if not installService.install():
            raise Exception("Failed to install service")

        # For PowerShell commands
        if command:
            # Don't wrap in extra quotes - cmd.exe will handle it
            cmd_args = f'powershell.exe -NoProfile -NonInteractive -Command {command}'
        
        # For PowerShell scripts
        elif script_path:
            with open(script_path, "rb") as fh:
                remote_name = f"Windows\\Temp\\{os.path.basename(script_path)}"
                s.putFile(installService.getShare(), remote_name, fh.read)  # callback, no ()
            cmd_args = f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\\Windows\\Temp\\{os.path.basename(script_path)}" {script_args}'
        else:
            raise ValueError("Either command or script_path is required")

        if verbose:
            logging.info(f"Command to execute: {cmd_args}")

        # Connect to IPC$ share and open RemCom communication pipe
        tid = s.connectTree('IPC$')
        fid_main = openPipe(s, tid, r'\RemCom_communicaton', 0x12019f)

        packet = RemComMessage()
        pid = os.getpid()
        packet['Machine'] = ''.join([random.choice(string.ascii_letters) for _ in range(4)])
        packet['WorkingDir'] = ''
        packet['Command'] = cmd_args
        packet['ProcessID'] = pid

        # Start pipe threads BEFORE sending command - they will wait for pipes to appear
        if verbose:
            logging.info("Starting pipe threads...")

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

        # NOW send command - RemCom will create the pipes and the threads will connect
        if verbose:
            logging.info("Sending command to RemCom service...")
        s.writeNamedPipe(tid, fid_main, packet.getData())

        # Give RemCom time to process and create pipes
        time.sleep(1)

        # Read response
        if verbose:
            logging.info("Reading command response...")
        ans = s.readNamedPipe(tid, fid_main, 8)
        
        if len(ans):
            retCode = RemComResponse(ans)
            if verbose:
                logging.info(f"Process finished with ErrorCode: {retCode['ErrorCode']}, ReturnCode: {retCode['ReturnCode']}")
        
        # Let pipes drain output - give them time to capture everything
        idle_checks = 0
        last_counts = (-1, -1)
        start = time.time()
        while time.time() - start < 15:          # max wait 15s
            counts = (len(stdout_pipe.output), len(stderr_pipe.output))
            if counts == last_counts:
                idle_checks += 1
                if idle_checks >= 3:              # ~1.5s of no new data (0.5s * 3)
                    break
            else:
                idle_checks = 0
                last_counts = counts
            time.sleep(0.5)
        
        # Stop pipe threads by closing their files
        try:
            if stdin_pipe.fid != 0:
                stdin_pipe.server.closeFile(stdin_pipe.tid, stdin_pipe.fid)
        except:
            pass
        try:
            if stdout_pipe.fid != 0:
                stdout_pipe.server.closeFile(stdout_pipe.tid, stdout_pipe.fid)
        except:
            pass
        try:
            if stderr_pipe.fid != 0:
                stderr_pipe.server.closeFile(stderr_pipe.tid, stderr_pipe.fid)
        except:
            pass
        
        # Collect output from pipes
        stdout_text = b"".join(stdout_pipe.output).decode(CODEC, errors="replace") if hasattr(stdout_pipe, 'output') else ""
        stderr_text = b"".join(stderr_pipe.output).decode(CODEC, errors="replace") if hasattr(stderr_pipe, 'output') else ""

        # Log captured output when verbose
        if verbose:
            if stdout_text:
                logging.info("STDOUT:\n%s", stdout_text)
            if stderr_text:
                logging.error("STDERR:\n%s", stderr_text)
        
        if len(ans):
            retCode = RemComResponse(ans)
            if verbose:
                logging.info(f"Process finished with ErrorCode: {retCode['ErrorCode']}, ReturnCode: {retCode['ReturnCode']}")
            
            error_code = retCode['ErrorCode']
            return_code = retCode['ReturnCode']
        else:
            error_code = 1
            return_code = None

        # Cleanup
        if verbose:
            logging.info("Waiting for service to finish...")
        time.sleep(2)  # Give service time to fully complete
        
        if verbose:
            logging.info("Uninstalling TomoeService...")
        installService.uninstall()
        if remote_name:
            try:
                s.deleteFile(installService.getShare(), remote_name)
            except Exception:
                pass

        # Prefer stderr when present so errors surface
        if stderr_text:
            return stderr_text
        return stdout_text

    except Exception as e:
        if verbose:
            logging.error(f"PsExec execution failed: {e}")
        # Try to cleanup on error
        try:
            time.sleep(1)
            if verbose:
                logging.info("Cleaning up after error...")
            installService.uninstall()
            if remote_name:
                try:
                    s.deleteFile(installService.getShare(), remote_name)
                except Exception:
                    pass
        except Exception as cleanup_error:
            if verbose:
                logging.error(f"Cleanup error: {cleanup_error}")
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
                raise Exception(f'Pipe {self.pipe} not ready, aborting')
            
            self.fid = self.server.openFile(self.tid, self.pipe, self.permissions, creationOption=0x40, fileAttributes=0x80)
            self.server.setTimeout(1000000)
        except:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error("Something wen't wrong connecting the pipes(%s), try again" % self.__class__)


class RemoteStdInPipe(Pipes):
    def __init__(self, transport, pipe, permisssions, share=None):
        self.shell = None
        Pipes.__init__(self, transport, pipe, permisssions, share)

    def run(self):
        self.connectPipe()
        # Keep pipe open but don't send anything for non-interactive mode
        while True:
            time.sleep(1)


class RemoteStdOutPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)
        self.output = []  # Capture output instead of printing

    def run(self):
        self.connectPipe()

        global LastDataSent

        if PY3:
            __stdoutOutputBuffer, __stdoutData = b"", b""

            while True:
                try:
                    stdout_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                except:
                    pass
                else:
                    try:
                        if stdout_ans != LastDataSent:
                            if len(stdout_ans) != 0:
                                # Append new data to the buffer while there is data to read
                                __stdoutOutputBuffer += stdout_ans

                        promptRegex = rb'([a-zA-Z]:[\\\/])((([a-zA-Z0-9 -\.]*)[\\\/]?)+(([a-zA-Z0-9 -\.]+))?)?>$'

                        endsWithPrompt = bool(re.match(promptRegex, __stdoutOutputBuffer) is not None)
                        if endsWithPrompt == True:
                            # All data, we shouldn't have encoding errors
                            # Adding a space after the prompt because it's beautiful
                            __stdoutData = __stdoutOutputBuffer + b" "
                            # Remainder data for next iteration
                            __stdoutOutputBuffer = b""

                            # print("[+] endsWithPrompt")
                            # print(" | __stdoutData:",__stdoutData)
                            # print(" | __stdoutOutputBuffer:",__stdoutOutputBuffer)
                        elif b'\n' in __stdoutOutputBuffer:
                            # We have read a line, print buffer if it is not empty
                            lines = __stdoutOutputBuffer.split(b"\n")
                            # All lines, we shouldn't have encoding errors
                            __stdoutData = b"\n".join(lines[:-1]) + b"\n"
                            # Remainder data for next iteration
                            __stdoutOutputBuffer = lines[-1]
                            # print("[+] newline in __stdoutOutputBuffer")
                            # print(" | __stdoutData:",__stdoutData)
                            # print(" | __stdoutOutputBuffer:",__stdoutOutputBuffer)

                        if len(__stdoutData) != 0:
                            # Store data in output buffer
                            self.output.append(__stdoutData)
                            __stdoutData = b""
                        else:
                            # Don't echo the command that was sent, and clear it up
                            LastDataSent = b""
                        # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                        # it will give false positives tho.. we should find a better way to handle this.
                        # if LastDataSent > 10:
                        #     LastDataSent = ''
                    except:
                        pass
        else:
            __stdoutOutputBuffer, __stdoutData = "", ""

            while True:
                try:
                    stdout_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                except:
                    pass
                else:
                    try:
                        if stdout_ans != LastDataSent:
                            if len(stdout_ans) != 0:
                                # Append new data to the buffer while there is data to read
                                __stdoutOutputBuffer += stdout_ans

                        promptRegex = r'([a-zA-Z]:[\\\/])((([a-zA-Z0-9 -\.]*)[\\\/]?)+(([a-zA-Z0-9 -\.]+))?)?>$'

                        endsWithPrompt = bool(re.match(promptRegex, __stdoutOutputBuffer) is not None)
                        if endsWithPrompt:
                            # All data, we shouldn't have encoding errors
                            # Adding a space after the prompt because it's beautiful
                            __stdoutData = __stdoutOutputBuffer + " "
                            # Remainder data for next iteration
                            __stdoutOutputBuffer = ""

                        elif '\n' in __stdoutOutputBuffer:
                            # We have read a line, print buffer if it is not empty
                            lines = __stdoutOutputBuffer.split("\n")
                            # All lines, we shouldn't have encoding errors
                            __stdoutData = "\n".join(lines[:-1]) + "\n"
                            # Remainder data for next iteration
                            __stdoutOutputBuffer = lines[-1]

                        if len(__stdoutData) != 0:
                            # Store data in output buffer
                            self.output.append(__stdoutData if isinstance(__stdoutData, bytes) else __stdoutData.encode(CODEC))
                            __stdoutData = ""
                        else:
                            # Don't echo the command that was sent, and clear it up
                            LastDataSent = ""
                        # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                        # it will give false positives tho.. we should find a better way to handle this.
                        # if LastDataSent > 10:
                        #     LastDataSent = ''
                    except Exception as e:
                        pass


class RemoteStdErrPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)
        self.output = []  # Capture output instead of printing

    def run(self):
        self.connectPipe()

        if PY3:
            __stderrOutputBuffer, __stderrData = b'', b''

            while True:
                try:
                    stderr_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                except:
                    pass
                else:
                    try:
                        if len(stderr_ans) != 0:
                            # Append new data to the buffer while there is data to read
                            __stderrOutputBuffer += stderr_ans

                        if b'\n' in __stderrOutputBuffer:
                            # We have read a line, print buffer if it is not empty
                            lines = __stderrOutputBuffer.split(b"\n")
                            # All lines, we shouldn't have encoding errors
                            __stderrData = b"\n".join(lines[:-1]) + b"\n"
                            # Remainder data for next iteration
                            __stderrOutputBuffer = lines[-1]

                        if len(__stderrData) != 0:
                            # Store data in output buffer
                            self.output.append(__stderrData)
                            __stderrData = b""
                        else:
                            # Don't echo the command that was sent, and clear it up
                            LastDataSent = b""
                        # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                        # it will give false positives tho.. we should find a better way to handle this.
                        # if LastDataSent > 10:
                        #     LastDataSent = ''
                    except Exception as e:
                        pass
        else:
            __stderrOutputBuffer, __stderrData = '', ''

            while True:
                try:
                    stderr_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                except:
                    pass
                else:
                    try:
                        if len(stderr_ans) != 0:
                            # Append new data to the buffer while there is data to read
                            __stderrOutputBuffer += stderr_ans

                        if '\n' in __stderrOutputBuffer:
                            # We have read a line, print buffer if it is not empty
                            lines = __stderrOutputBuffer.split("\n")
                            # All lines, we shouldn't have encoding errors
                            __stderrData = "\n".join(lines[:-1]) + "\n"
                            # Remainder data for next iteration
                            __stderrOutputBuffer = lines[-1]

                        if len(__stderrData) != 0:
                            # Store data in output buffer
                            self.output.append(__stderrData if isinstance(__stderrData, bytes) else __stderrData.encode(CODEC))
                            __stderrData = ""
                        else:
                            # Don't echo the command that was sent, and clear it up
                            LastDataSent = ""
                        # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                        # it will give false positives tho.. we should find a better way to handle this.
                        # if LastDataSent > 10:
                        #     LastDataSent = ''
                    except:
                        pass

if __name__ == "__main__":
    # Test run - modify these parameters for your target
    target_ip = "192.168.1.131"
    username = "Administrator"
    password = "P@ssw0rd!"
    domain = ""
    
    print("[*] Testing SMB PsExec functionality")
    print(f"[*] Target: {target_ip}")
    print(f"[*] User: {username}")
    print("-" * 60)
    
    try:
        # Test with a simple command first to verify pipes work
        print("[+] Testing simple command: whoami")
        result = run_psexec(
            target_ip=target_ip,
            username=username,
            password=password,
            domain=domain,
            command="whoami",
            verbose=True
        )
        print("[+] Command output:")
        print(result)
        print("-" * 60)
        
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
