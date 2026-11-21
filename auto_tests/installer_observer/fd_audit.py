"""Observe Unix socket descriptor inheritance without guest commands or events.

The positive control deliberately sets an artificial socketpair FD inheritable;
the production subprocess path uses close_fds=True and pass_fds=().
"""

from __future__ import annotations

import os
import socket
import stat
import subprocess
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path

from .evidence import Refusal


def audit_child_fds() -> dict[str, bool]:
    if os.name != "posix":
        raise Refusal("Linux FD audit required")
    with ExitStack() as stack:
        first, second = socket.socketpair(socket.AF_UNIX)
        source = stack.enter_context(first)
        stack.enter_context(second)
        descriptor = source.fileno()
        inode = os.fstat(descriptor).st_ino
        # No RFB or QMP socket is used; the descriptor is synthetic.
        if not stat.S_ISSOCK(os.fstat(descriptor).st_mode):
            raise Refusal("FD audit expected a socket")
        original = os.get_inheritable(descriptor)
        if original:
            raise Refusal("New Python socket unexpectedly lacks FD_CLOEXEC")
        try:
            os.set_inheritable(descriptor, True)
            code = (
                "import os,sys,stat;"
                "fd=int(sys.argv[1]);expected=int(sys.argv[2]);"
                "found=False;"
                "exec('try:\\n s=os.fstat(fd)\\n found=stat.S_ISSOCK(s.st_mode)"
                " and s.st_ino==expected\\nexcept OSError:\\n pass');"
                "sys.exit(0 if found else 11)"
            )
            command = [sys.executable, "-c", code, str(descriptor), str(inode)]

            def inspect(close: bool) -> int:
                return subprocess.run(
                    command,
                    check=False,
                    close_fds=close,
                    pass_fds=(),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                ).returncode

            # Inheritable FD is visible when close_fds=False (positive control).
            if inspect(False) != 0:
                raise Refusal("FD inheritance positive control failed")
            if inspect(True) != 11:
                raise Refusal("close_fds failed to exclude inherited Unix socket")
            return {
                "synthetic_inheritable_fd_positive_control": True,
                "close_fds_excludes_inheritable_socket": True,
                "socket_fd_cloexec_by_default": not original,
                "guest_input_emitted": False,
                **audit_open_connection_survives_permission_revoke(),
            }
        finally:
            os.set_inheritable(descriptor, original)


def audit_open_connection_survives_permission_revoke() -> dict[str, bool]:
    """Prove a *synthetic* connected FD persists after socket chmod(000).

    This is an interference witness, not a mechanism to revoke an existing
    QMP/RFB client. No protocol bytes are sent and the fixture is discarded.
    """
    if os.geteuid() == 0:
        raise Refusal("Unprivileged Unix socket permission audit required")
    with tempfile.TemporaryDirectory(prefix="observer-fd-") as temporary:
        endpoint = Path(temporary) / "fixture.sock"
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(endpoint))
            listener.listen(1)
            with socket.socket(socket.AF_UNIX) as client:
                client.connect(str(endpoint))
                accepted, _ = listener.accept()
                with accepted:
                    endpoint.chmod(0)
                    # The already-connected descriptor remains valid despite
                    # later pathname permission revocation.
                    try:
                        client.getpeername()
                        accepted.getpeername()
                    except OSError as exc:
                        raise Refusal("Existing socket descriptor closed unexpectedly") from exc
                    with socket.socket(socket.AF_UNIX) as outsider:
                        try:
                            outsider.connect(str(endpoint))
                        except PermissionError:
                            denied = True
                        else:
                            denied = False
                    if not denied:
                        raise Refusal("New connection bypassed Unix socket permissions")
                    return {
                        "new_connection_refused_after_chmod": True,
                        "preexisting_connection_survives_chmod": True,
                    }
