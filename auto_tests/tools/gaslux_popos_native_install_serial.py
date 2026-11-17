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
PRECHECK_RESULT = re.compile(
    rb"(?m)^GASLUX_POP_NATIVE_(?:INSTALL_PREFLIGHT_OK=1|INSTALL_FAILURE: [^\r\n]+)\r?\n"
)
START_RESULT = re.compile(
    rb"(?m)^GASLUX_POP_NATIVE_(?:INSTALL_DISTINST_STARTED=1|INSTALL_FAILURE: [^\r\n]+)\r?\n"
)


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
        # The debug shell appears early, while kernel/systemd messages still
        # disrupt long serial commands. Require completed live userspace boot
        # before sending ANY filesystem/installer commands.
        wait_for(
            conn,
            transcript,
            re.compile(rb"Startup finished in"),
            timeout_seconds=300,
        )
        wait_for(conn, transcript, ROOT_DEBUG_SHELL, timeout_seconds=60)
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
        # Short, sequential commands prevent the long compound installer
        # invocation from being corrupted by late boot console output. Each
        # stage must emit a distinct line after its previous command succeeded.
        stages = (
            (
                "mkdir -p /run/gaslux-pop-lab && echo GASLUX_POP_LAB_DIR_READY=1",
                re.compile(rb"(?m)^GASLUX_POP_LAB_DIR_READY=1\r?$"),
            ),
            (
                "mount -L GASLUXLAB -o ro /run/gaslux-pop-lab && echo GASLUX_POP_LAB_MOUNT_READY=1",
                re.compile(rb"(?m)^GASLUX_POP_LAB_MOUNT_READY=1\r?$"),
            ),
            (
                "cd /run/gaslux-pop-lab && sha256sum -c lab.sha256 && "
                "echo GASLUX_POP_LAB_CONTROL_VERIFIED=1",
                re.compile(rb"(?m)^GASLUX_POP_LAB_CONTROL_VERIFIED=1\r?$"),
            ),
        )
        for command, marker in stages:
            marker_start = len(transcript)
            conn.sendall((command + "\r").encode("ascii"))
            wait_for(conn, transcript, marker, timeout_seconds=55, start=marker_start)
        # SHA-256 lives in the authenticated read-only VM control disk; never
        # type a 64-byte hash through the boot console.
        start = len(transcript)
        conn.sendall(b"bash install.sh\r")
        wait_for(conn, transcript, PRECHECK_RESULT, timeout_seconds=120, start=start)
        if b"GASLUX_POP_NATIVE_INSTALL_FAILURE:" in normalized(bytes(transcript[start:])):
            raise GuestProbeError("native install guest refused preflight")
        print("GASLUX_POP_NATIVE_INSTALL_GUEST_PREFLIGHT_VERIFIED=1", flush=True)
        wait_for(conn, transcript, START_RESULT, timeout_seconds=60, start=start)
        if b"GASLUX_POP_NATIVE_INSTALL_FAILURE:" in normalized(bytes(transcript[start:])):
            raise GuestProbeError("native installer not invoked after preflight")
        print("GASLUX_POP_NATIVE_DISTINST_INVOCATION_CONFIRMED=1", flush=True)
        wait_for(conn, transcript, RESULT, timeout_seconds=1585, start=start)
        output = normalized(bytes(transcript[start:]))
        if not SUCCESS.search(output):
            raise GuestProbeError("native installer reported an explicit failure")
        # Installer emits its success marker BEFORE the interactive shell
        # returns to its prompt. Do not close the QEMU serial socket with a
        # shutdown command still queued as input to the running installer.
        # The HOST separately requires QEMU's clean exit code and boots again
        # with neither the ISO nor the temporary control disk.
        wait_for(conn, transcript, ROOT_DEBUG_SHELL, timeout_seconds=120, start=start)
        sync_start = len(transcript)
        conn.sendall(b"sync\r")
        wait_for(
            conn, transcript, ROOT_DEBUG_SHELL, timeout_seconds=150, start=sync_start
        )
        conn.sendall(b"systemctl poweroff -i\r")
        # Keep the console alive until the guest actually closes the socket.
        # EOF alone is NOT a proof: the host must still see QEMU exit 0.
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            conn.settimeout(2.0)
            try:
                chunk = conn.recv(16384)
            except TimeoutError:
                continue
            except ConnectionResetError:
                break
            if not chunk:
                break
            transcript.extend(chunk)
            if len(transcript) > 12000000:
                raise GuestProbeError("shutdown transcript exceeded safety bound")
        else:
            raise GuestProbeError("native guest did not close serial after poweroff")


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
