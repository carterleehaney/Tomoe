import sys
import os
import logging
from impacket.examples import remcomsvc, serviceinstall
from impacket.dcerpc.v5 import transport
from impacket.smbconnection import SMBConnection

def run_psexec(target_ip, username, password, domain="", script_path=None, command=None, script_args="", verbose=False):
    """
    Execute a command or script remotely using impacket's psexec functionality over SMB.
    """
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
        
        # Install the service
        if copy_file:
            try:
                f = open(copy_file, 'rb')
            except Exception as e:
                if verbose:
                    logging.critical(str(e))
                raise
            installService = serviceinstall.ServiceInstall(s, f, "RunBetterService", "RunBetter.exe")
        else:
            installService = serviceinstall.ServiceInstall(s, remcomsvc.RemComSvc(), "RunBetterService", "RunBetter.exe")

        if not installService.install():
            raise Exception("Failed to install service")

        if copy_file:
            f.close()
            # Copy the file to the remote share
            installService.copy_file(copy_file, installService.getShare(), os.path.basename(copy_file))
            # Update command to execute the copied file
            if copy_file.lower().endswith('.ps1'):
                cmd_args = f'powershell.exe -ExecutionPolicy Bypass -file \\\\127.0.0.1\\{installService.getShare()}\\{os.path.basename(copy_file)} "{cmd_args}"'
            else:
                cmd_args = os.path.basename(copy_file) + ' ' + cmd_args

        # Connect to IPC$ share and open RemCom communication pipe
        tid = s.connectTree('IPC$')
        fid_main = s.openFile(tid, r'\RemCom_communicaton', 0x12019f)

        # Create RemCom message
        from impacket.structure import Structure
        
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

        packet = RemComMessage()
        pid = os.getpid()
        import random
        import string
        packet['Machine'] = ''.join([random.choice(string.ascii_letters) for _ in range(4)])
        packet['WorkingDir'] = ''
        packet['Command'] = cmd_args
        packet['ProcessID'] = pid

        # Send command
        s.writeNamedPipe(tid, fid_main, packet.getData())

        # Read response
        ans = s.readNamedPipe(tid, fid_main, 8)
        
        stdout_text = ''
        stderr_text = ''
        
        if len(ans):
            retCode = RemComResponse(ans)
            if verbose:
                logging.info(f"Process {cmd_args} finished with ErrorCode: {retCode['ErrorCode']}, ReturnCode: {retCode['ReturnCode']}")
            
            error_code = retCode['ErrorCode']
            return_code = retCode['ReturnCode']
        else:
            error_code = 1
            return_code = None

        # Cleanup
        installService.uninstall()
        if copy_file:
            try:
                s.deleteFile(installService.getShare(), os.path.basename(copy_file))
            except Exception:
                pass

        # Return stdout (stderr would need pipe handling for full implementation)
        # For now, return empty string as stdout since we're not capturing it via pipes
        return stdout_text or ""

    except Exception as e:
        if verbose:
            logging.error(f"PsExec execution failed: {e}")
        # Try to cleanup on error
        try:
            installService.uninstall()
            if copy_file:
                try:
                    s.deleteFile(installService.getShare(), os.path.basename(copy_file))
                except Exception:
                    pass
        except Exception:
            pass
        raise

