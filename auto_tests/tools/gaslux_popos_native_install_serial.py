#!/usr/bin/env python3
"""Authenticate a full Pop native VM-only installer over a QEMU serial socket."""

import argparse
import re
import socket
import sys
import time
from pathlib import Path

from gaslux_popos_guest_serial import (
    READY,
    ROOT_DEBUG_SHELL,
    SHA,
    GuestProbeError,
    normalized,
    wait_for,
)

# Require a NEWLINE, not a partial chunk containing only the failure prefix.
# Otherwise the controller disconnects before receiving diagnostic details.
RESULT = re.compile(
    rb"(?m)^GASLUX_POP_NATIVE_(?:FULL_INSTALL_COMPLETED=1|INSTALL_FAILURE: [^\r\n]+)\r?\n"
)
SUCCESS = re.compile(rb"(?m)^GASLUX_POP_NATIVE_FULL_INSTALL_COMPLETED=1\r?\n")


def connect(path: Path) -> socket.socket:
    if not path.is_absolute() or path.is_symlink():
        raise GuestProbeError("untrusted or relative QEMU socket")
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    deadline = time.monotonic() + 30
    while True:
        try:
            conn.connect(str(path))
            return conn
        except (FileNotFoundError, ConnectionRefusedError):
            if time.monotonic() >= deadline:
                conn.close()
                raise GuestProbeError("no isolated QEMU socket") from None
            time.sleep(0.2)


def run(path: Path, digest: str, transcript: bytearray) -> None:
    if not SHA.fullmatch(digest):
        raise GuestProbeError("native installer SHA-256 not verified")
    with connect(path) as conn:
        # OVMF/GRUB can print prompt-shaped '#' text BEFORE Linux systemd has
        # completed startup. Never send commands without actual kernel proof.
        wait_for(
            conn,
            transcript,
            re.compile(rb"Linux version|systemd\[1\]"),
            timeout_seconds=180,
        )
        wait_for(conn, transcript, ROOT_DEBUG_SHELL, timeout_seconds=240)
        # Serial debug shells may temporarily lose characters during the noisy
        # live startup. Repeat a nonce-like challenge, never trust a prompt.
        for attempt in range(10):
            ready_start = len(transcript)
            conn.sendall(b"printf 'GASLUX_POP_LIVE_SHELL_READY\\n'\r")
            try:
                wait_for(conn, transcript, READY, timeout_seconds=25, start=ready_start)
            except GuestProbeError as error:
                if "timed out" not in str(error) or attempt == 9:
                    raise
                continue
            break
        command = (
            "mkdir -p /run/gaslux-pop-lab && "
            "mount -t vfat -o ro /dev/disk/by-label/GASLUXLAB "
            "/run/gaslux-pop-lab && "
            "cd /run/gaslux-pop-lab && sha256sum -c lab.sha256 && "
            "bash install.sh " + digest + "\r"
        )
        start = len(transcript)
        conn.sendall(command.encode("ascii"))
        wait_for(conn, transcript, RESULT, timeout_seconds=1500, start=start)
        output = normalized(bytes(transcript[start:]))
        if not SUCCESS.search(output):
            raise GuestProbeError("native installer reported an explicit failure")
        # Installer committed filesystems, installed bootloader and unmounted
        # its targets. Gracefully shut down before restarting from target only.
        conn.sendall(b"sync && systemctl poweroff -i\r")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--distinst-sha256", required=True)
    args = parser.parse_args()
    trace = bytearray()
    try:
        run(args.socket, args.distinst_sha256, trace)
    except (OSError, GuestProbeError) as error:
        print(f"GASLUX_POP_NATIVE_INSTALL_GUEST_REFUSED: {error}", file=sys.stderr)
        print(
            normalized(bytes(trace[-3000:])).decode("utf-8", errors="replace"),
            file=sys.stderr,
        )
        status = 1
    else:
        print("GASLUX_POP_NATIVE_FULL_INSTALL_GUEST_PROVEN=1")
        status = 0
    finally:
        args.trace.write_bytes(trace)
    return status


if __name__ == "__main__":
    sys.exit(main())
