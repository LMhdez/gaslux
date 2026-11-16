#!/usr/bin/env python3
"""Read-only serial controller for official Pop!_OS 24.04 live QEMU guest."""

import argparse
import re
import socket
import sys
import time
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{64}\Z")
LOGIN = re.compile(rb"(?im)(?:^|[\r\n])[^:\r\n]{0,80}login:\s*$")
PASSWORD = re.compile(rb"(?im)Password:\s*$")
READY = re.compile(rb"(?m)^GASLUX_POP_LIVE_SHELL_READY\r?$")
PASSED = re.compile(rb"(?m)^GASLUX_POP_DISTINST_GUEST_READONLY_PASS=1\r?$")
FAILED = re.compile(rb"GASLUX_POP_GUEST_DISTINST_FAILURE")
CONTROL = re.compile(rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-9;?]*[GHJKmnhl]")


class GuestProbeError(RuntimeError):
    """Guest-native proof is absent or untrustworthy."""


def normalized(data: bytes) -> bytes:
    return CONTROL.sub(b"", data).replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def wait_for(
    conn: socket.socket,
    transcript: bytearray,
    expected: re.Pattern[bytes],
    *,
    timeout_seconds: float,
    start: int = 0,
) -> None:
    until = time.monotonic() + timeout_seconds
    while time.monotonic() < until:
        stream = normalized(bytes(transcript[start:][-250000:]))
        if FAILED.search(stream) or b"Login incorrect" in stream:
            raise GuestProbeError("guest explicitly refused the probe")
        if expected.search(stream):
            return
        conn.settimeout(min(1.0, max(0.1, until - time.monotonic())))
        try:
            data = conn.recv(16384)
        except socket.timeout:
            continue
        if not data:
            raise GuestProbeError("QEMU serial stream terminated")
        transcript.extend(data)
        if len(transcript) > 12000000:
            raise GuestProbeError("serial transcript size exceeded")
    raise GuestProbeError("expected guest proof timed out")


def run(socket_path: Path, transcript: bytearray, trusted_sha: str) -> None:
    if not SHA.fullmatch(trusted_sha):
        raise GuestProbeError("invalid independently pinned agent hash")
    if not socket_path.is_absolute() or socket_path.is_symlink():
        raise GuestProbeError("invalid QEMU console socket")
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                conn.connect(str(socket_path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    raise GuestProbeError("QEMU socket did not appear") from None
                time.sleep(0.25)
        wait_for(conn, transcript, LOGIN, timeout_seconds=300)
        # The verified Pop 24.04 serial getty explicitly requests Password:
        # after the live-user name. Never send shell code into a password prompt.
        login_start = len(transcript)
        conn.sendall(b"pop-os\r")
        wait_for(conn, transcript, PASSWORD, timeout_seconds=25, start=login_start)
        conn.sendall(b"\r")  # Blank password on this isolated live ISO only.
        time.sleep(1)
        ready_start = len(transcript)
        conn.sendall(b"printf 'GASLUX_POP_LIVE_SHELL_READY\\n'\r")
        wait_for(conn, transcript, READY, timeout_seconds=25, start=ready_start)
        cmd = (
            "sudo -n mkdir -p /run/gaslux-pop-lab && "
            "sudo -n mount -t vfat -o ro /dev/disk/by-label/GASLUXLAB "
            "/run/gaslux-pop-lab && "
            "cd /run/gaslux-pop-lab && sha256sum -c probe.sha256 && "
            "sudo -n bash probe.sh " + trusted_sha + "\r"
        )
        start = len(transcript)
        conn.sendall(cmd.encode("ascii"))
        wait_for(conn, transcript, PASSED, timeout_seconds=90, start=start)
    finally:
        conn.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--socket", required=True, type=Path)
    ap.add_argument("--trace", required=True, type=Path)
    ap.add_argument("--distinst-sha256", required=True)
    args = ap.parse_args()
    data = bytearray()
    try:
        run(args.socket, data, args.distinst_sha256)
    except (GuestProbeError, OSError) as error:
        print(f"GASLUX_POP_GUEST_NATIVE_PROBE_FAILED: {error}", file=sys.stderr)
        # Diagnostic data is from a disposable ISO guest only, never user media.
        # Strip terminal color codes; retain the raw transcript in evidence.
        tail = normalized(bytes(data[-1800:])).decode("utf-8", errors="replace")
        print("GASLUX_POP_GUEST_SERIAL_TAIL_START", file=sys.stderr)
        print(tail, file=sys.stderr)
        print("GASLUX_POP_GUEST_SERIAL_TAIL_END", file=sys.stderr)
        code = 1
    else:
        print("GASLUX_POP_NATIVE_DISTINST_GUEST_PROVEN=1")
        code = 0
    finally:
        args.trace.write_bytes(bytes(data))
    return code


if __name__ == "__main__":
    sys.exit(main())
