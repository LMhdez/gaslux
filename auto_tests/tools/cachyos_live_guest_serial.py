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

# The official 260809 Archiso console wraps commands in systemd OSC 3008
# command-lifecycle markers, and uses CSI bracketed-paste sequences. Strip
# only recognized terminal control codes for matching; the original raw transcript is
# always preserved and SHA-256 hashed separately.
_TERMINAL_CONTROL = re.compile(
    rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    rb"|\x1b\[(?:[0-9;?]*[GHJKmnhl]|!p)"
    rb"|\x1bP[^\x1b]*\x1b\\"
)


def normalized_tty(data: bytes) -> bytes:
    return _TERMINAL_CONTROL.sub(b"", data).replace(b"\r\n", b"\n")



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
        # Permit only known terminal control codes around complete output
        # lines. Never treat an echoed shell command as success.
        text = normalized_tty(bytes(transcript))
        for index, pattern in enumerate(accepted):
            if pattern.search(text):
                return index
        if failure and failure.search(text):
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


def probe(sock: socket.socket, trace: bytearray, *, boot_timeout: float = 345) -> None:
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
        prompt_text = normalized_tty(bytes(prompt_bytes))
        if PASSWORD.search(prompt_text):
            sock.sendall(b"cachyos\r")
            break
        if b"Last login:" in prompt_text or re.search(
            rb"(?m)\[?root@CachyOS[^\r\n]{0,120}\]?#\s*$", prompt_text
        ):
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--transcript", type=Path, required=True)
    parser.add_argument("--boot-timeout", type=float, default=345)
    args = parser.parse_args(argv)
    transcript = bytearray()
    try:
        with connect_serial(args.socket) as sock:
            probe(sock, transcript, boot_timeout=args.boot_timeout)
    except (ProbeError, OSError, UnicodeError) as error:
        print(f"GASLUX_GUEST_PROBE_FAILED: {error}", file=sys.stderr)
        returncode = 1
    else:
        returncode = 0
    finally:
        # Keep failure transcripts as diagnostic evidence too.
        args.transcript.write_bytes(bytes(transcript))
    if returncode:
        return 1
    print("GASLUX_GUEST_PROBE_VERIFIED: live root and guarded --check succeeded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
