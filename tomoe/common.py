import socket


class TomoeError(Exception):
    pass


class AuthenticationError(TomoeError):
    pass


class ConnectionError(TomoeError):
    pass


def check_port_open(host, port, timeout=5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error:
        return False


def build_auth_username(username, domain, is_linux=False):
    if domain and not is_linux:
        return f"{domain}\\{username}"
    return username
