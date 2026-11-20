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
from contextlib import ExitStack

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
                "guest_input_emitted": False,
            }
        finally:
            os.set_inheritable(descriptor, original)
