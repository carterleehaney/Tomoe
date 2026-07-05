import socket
from threading import Event, Thread


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


def run_interruptible(target, shutdown_event=None, host="", poll_interval=0.25):
    """Run ``target()`` so it can be interrupted by ``shutdown_event`` (Ctrl-C).

    The callable runs in a daemon thread while the caller polls
    ``shutdown_event``. If the event fires before ``target`` finishes, a
    ``KeyboardInterrupt`` is raised in the caller (the daemon thread is
    abandoned; callers clean up their own connection in a ``finally`` block).
    When no event is supplied the target is called inline, so the non-shutdown
    code path is unchanged. The target's return value is returned, and any
    exception it raises is re-raised in the caller.
    """
    if shutdown_event is None:
        return target()

    result = {}
    done = Event()

    def _runner():
        try:
            result["value"] = target()
        except BaseException as exc:  # noqa: BLE001 - re-raised in caller thread
            result["exc"] = exc
        finally:
            done.set()

    Thread(target=_runner, daemon=True).start()

    while not done.wait(timeout=poll_interval):
        if shutdown_event.is_set():
            raise KeyboardInterrupt(f"Interrupted by user while executing on {host}")

    if "exc" in result:
        raise result["exc"]
    return result.get("value")
