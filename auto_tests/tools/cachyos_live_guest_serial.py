#!/usr/bin/env python3
"""Read-only serial console controller for a DISPOSABLE QEMU CachyOS live ISO.

No host disks, network secrets, firmware APIs, or guest partition writes.
The only guest command is a vetted preflight script on a VM-owned read-only
FAT image. A serial echo of a command is not accepted as a success marker.
"""
from __future__ import annotations

import argparse
import os
import re
import socket
import sys
import time
from pathlib import Path

LOGIN = re.compile(rb"CachyOS login:\s*$", re.M)
PASSWORD = re.compile(rb"Password:\s*$", re.M)
READY = re.compile(rb"(?m)^GASLUX_ROOT_SHELL_READY\r?$")
PASSED = re.compile(rb"(?m)^GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\r?$")
FAILED = re.compile(rb"(?m)^GASLUX_GUEST_PREFLIGHT_FAILURE(?::[^\r\n]*)?\r?$")


class ProbeError(ValueError):
    """The verified CachyOS guest did not complete the non-mutating preflight."""


def wait_for(
    sock: socket.socket,
    transcript: bytearray,
    accepted: tuple[re.Pattern[bytes], ...],
    *,
    timeout_seconds: float,
    failure: re.Pattern[bytes] | None = FAILED,
) -> int:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        for index, pattern in enumerate(accepted):
            if pattern.search(bytes(transcript)):
                return index
        if failure and failure.search(bytes(transcript)):
            raise ProbeError("read-only guest script explicitly failed")
        sock.settimeout(min(1, max(0.1, deadline - time.monotonic())))
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            continue
        if not chunk:
            raise ProbeError("serial connection terminated before guest proof")
        transcript.extend(chunk)
        if len(transcript) > 8_000_000:
            raise ProbeError("serial transcript is unexpectedly large")
    raise ProbeError("read-only guest probe timed out")


def connect_serial(path: Path, *, timeout_seconds: float = 40) -> socket.socket:
    if not path.is_absolute() or path.is_symlink():
        raise ProbeError("serial socket path must be absolute and not a symlink")
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(2)
            conn.connect(str(path))
            return conn
        except (FileNotFoundError, ConnectionRefusedError, socket.timeout):
            conn.close()
            time.sleep(0.2)
        except OSError as error:
            conn.close()
            raise ProbeError("unexpected QEMU serial transport error") from error
    raise ProbeError("QEMU guest serial socket was not created")


def probe(sock: socket.socket, *, boot_timeout: float = 345) -> bytes:
    trace = bytearray()
    # A ttyS0 login is produced only by executing CachyOS's live kernel/init.
    wait_for(sock, trace, (LOGIN,), timeout_seconds=boot_timeout, failure=None)
    sock.sendall(b"root\r")
    # Official disposable live environments may use password-less root;
    # support their guest-test-only default for the serial terminal.
    deadline = time.monotonic() + 14
    prompt_bytes = bytearray()
    while time.monotonic() < deadline:
        sock.settimeout(1)
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            raise ProbeError("serial connection closed during live root login")
        prompt_bytes.extend(chunk)
        trace.extend(chunk)
        if PASSWORD.search(bytes(prompt_bytes)):
            sock.sendall(b"cachyos\r")
            break
        if b"Last login:" in prompt_bytes or re.search(rb"(?m)[^\r\n]*[~\s]#\s*$", prompt_bytes):
            break
        if b"Login incorrect" in prompt_bytes:
            raise ProbeError("the live console refused the root login")
    sock.sendall(b"printf 'GASLUX_ROOT_SHELL_READY\\n'\r")
    wait_for(sock, trace, (READY,), timeout_seconds=20, failure=None)
    # Mounted script files are precisely the read-only, hashed, VM-only FAT
    # fixtures injected by the separate host QEMU smoke script.
    sock.sendall(
        b"mkdir -p /run/gaslux-lab && "
        b"mount -t vfat -o ro /dev/disk/by-label/GASLUXLAB /run/gaslux-lab && "
        b"bash /run/gaslux-lab/probe.sh\r"
    )
    wait_for(sock, trace, (PASSED,), timeout_seconds=45)
    return bytes(trace)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--transcript", type=Path, required=True)
    parser.add_argument("--boot-timeout", type=float, default=345)
    args = parser.parse_args(argv)
    try:
        with connect_serial(args.socket) as sock:
            data = probe(sock, boot_timeout=args.boot_timeout)
        # The script's transcript is diagnostic and not a secret. Its SHA-256
        # is stored by the host QEMU wrapper after the guest has shut down.
        args.transcript.write_bytes(data)
    except (ProbeError, OSError, UnicodeError) as error:
        print(f"GASLUX_GUEST_PROBE_FAILED: {error}", file=sys.stderr)
        return 1
    print("GASLUX_GUEST_PROBE_VERIFIED: live root and guarded --check succeeded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
