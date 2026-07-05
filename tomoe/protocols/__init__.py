from tomoe.protocols import winrm, smb, ssh

PROTOCOLS = {"winrm": winrm, "smb": smb, "ssh": ssh}


def get_protocol(name):
    return PROTOCOLS[name]
