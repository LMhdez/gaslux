#!/usr/bin/env python3
"""Drive ONLY read-only commands through a real Pop live debug serial console.

The guest is an isolated hosted-KVM QEMU process with Windows COW attached
read-only. Never send distinst, mkfs, mount-RW, or any partition modification.
"""
from __future__ import annotations

import argparse
import re
import socket
import sys
import time
from pathlib import Path

PROMPT = re.compile(rb"GASLUX_POP_LIVE_WIN10_SHELL_READY=1\r?\n")
MOUNT = re.compile(rb"GASLUX_POP_LIVE_WIN10_CONTROL_RO=1\r?\n")
RESULT = re.compile(rb"GASLUX_POP_LIVE_WIN10_SIX_GPT_READONLY_VERIFIED=1\r?\n")
FAILURE = re.compile(rb"GASLUX_POP_LIVE_WIN10_PREFLIGHT_FAILURE: [^\r\n]+")


class LiveError(Exception):
    pass


def wait_for(conn: socket.socket, trace: bytearray,
             regex: re.Pattern[bytes], seconds: int,
             *, start: int = 0) -> bytes:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        sample = bytes(trace[start:])
        if FAILURE.search(sample):
            raise LiveError("guest refused live GPT preflight")
        found = regex.search(sample)
        if found:
            return found.group(0)
        conn.settimeout(2.0)
        try:
            chunk = conn.recv(32768)
        except (socket.timeout, TimeoutError):
            continue
        if not chunk:
            raise LiveError("guest console disconnected before required proof")
        trace.extend(chunk)
        if len(trace) > 9_000_000:
            raise LiveError("unbounded QEMU serial console transcript")
    raise LiveError("read-only live guest step timed out: " + regex.pattern.decode("ascii", "replace"))


def command(conn: socket.socket, trace: bytearray,
            value: bytes, expected: re.Pattern[bytes], seconds: int) -> None:
    if any(
        marker in value.lower() for marker in (
            b"distinst", b"mkfs", b"parted", b"sgdisk", b"dd ",
            b"mount -o rw", b"mount -w", b"pacstrap", b"wipefs",
        )
    ):
        raise LiveError("disallowed writable native guest console instruction")
    start = len(trace)
    conn.sendall(value + b"\r")
    wait_for(conn, trace, expected, seconds, start=start)


def run(socket_file: Path, trace: bytearray) -> None:
    if not socket_file.is_absolute() or socket_file.is_symlink():
        raise LiveError("unsafe external QEMU console socket")
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    deadline = time.monotonic() + 35
    while True:
        try:
            conn.connect(str(socket_file))
            break
        except (ConnectionRefusedError, FileNotFoundError):
            if time.monotonic() > deadline:
                raise LiveError("QEMU guest serial socket not ready") from None
            time.sleep(.25)
    with conn:
        wait_for(conn, trace, re.compile(rb"Linux version|systemd\[1\]"), 220)
        wait_for(conn, trace, re.compile(rb"Startup finished in"), 330)
        # Console can be noisy; retry a SHORT challenge until accepted.
        for i in range(10):
            try:
                command(
                    conn, trace, b"printf 'GASLUX_POP_LIVE_WIN10_SHELL_READY=1\\n'",
                    PROMPT, 20,
                )
                break
            except LiveError:
                if i == 9:
                    raise
        command(
            conn, trace,
            b"mkdir -p /run/gaslux-pop-lab && mount -L GASLUXLAB -o ro /run/gaslux-pop-lab && printf 'GASLUX_POP_LIVE_WIN10_CONTROL_RO=1\\n'",
            MOUNT, 65,
        )
        command(
            conn, trace,
            b"python3 /run/gaslux-pop-lab/probe.py",
            RESULT, 90,
        )
        # Require complete, distinct success marker; guest audit has run.
        sample = bytes(trace)
        for b in (
            b"GASLUX_POP_LIVE_WIN10_SIX_GPT_READONLY_VERIFIED=1",
            b"GASLUX_POP_LIVE_WIN10_REAL_DUALBOOT_VERIFIED=0",
            b"GASLUX_POP_LIVE_WIN10_DISTINST_EXECUTED=0",
        ):
            if b not in sample:
                # Some subsequent lines can be in flight after the marker.
                wait_for(conn, trace, re.compile(re.escape(b)), 15)
        conn.sendall(b"systemctl poweroff -i\r")
        # QEMU must independently exit cleanly, EOF does not establish that.
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            conn.settimeout(2)
            try:
                data = conn.recv(32768)
            except (socket.timeout, TimeoutError):
                continue
            if not data:
                return
            trace.extend(data)
        raise LiveError("Pop guest never disconnected serial after poweroff")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    args = parser.parse_args()
    trace = bytearray()
    try:
        run(args.socket, trace)
    except (OSError, LiveError) as exc:
        print("GASLUX_POP_WINDOWS_LIVE_SERIAL_REFUSED: " + str(exc),
              file=sys.stderr, flush=True)
        print(bytes(trace[-2800:]).decode("utf-8", "replace"), file=sys.stderr)
        status = 1
    else:
        print("GASLUX_POP_REAL_WINDOWS_COW_LIVE_READONLY_GPT_GUEST_PROVEN=1",
              flush=True)
        status = 0
    finally:
        args.trace.write_bytes(trace)
    return status


if __name__ == "__main__":
    sys.exit(main())
