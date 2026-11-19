#!/usr/bin/env python3
"""Drive only a read-only native Pop live six-GPT witness via private COM1.

The separately booted ISO must emit its actual kernel/systemd live proof, an
independent guest measured GPT JSON line and a clean ACPI poweroff. The host
will also independently re-measure both GPT headers and Windows files.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import re
import socket
import sys
import time

from gaslux_popos_guest_serial import (
    GuestProbeError, normalized, wait_for, READY, ROOT_DEBUG_SHELL,
)

MOUNT = re.compile(rb"(?m)^GASLUX_POP_LAB_CONTROL_MOUNTED=1\r?$")
HASHES = re.compile(rb"(?m)^GASLUX_POP_LAB_CONTROL_SHA_VERIFIED=1\r?$")
SUCCESS = re.compile(rb"(?m)^GASLUX_POP_LIVE_GENUINE_WIN10_COW_GPT_VERIFIED=1\r?$")
REFUSED = re.compile(rb"(?m)^GASLUX_POP_LIVE_WINDOWS_GPT_REFUSED=[^\r\n]+\r?$")
RESULT = re.compile(
    rb"(?m)^GASLUX_POP_LIVE_(?:GENUINE_WIN10_COW_GPT_VERIFIED=1|"
    rb"WINDOWS_GPT_REFUSED=[^\r\n]+)\r?$"
)
JSON_MARKER = re.compile(rb"(?m)^GASLUX_POP_LIVE_WINDOWS_GPT_EVIDENCE_JSON=(\{[^\r\n]+\})\r?$")
SYNCDONE = re.compile(rb"(?m)^GASLUX_POP_LIVE_SYNC_DONE=1\r?$")


def run(port: Path, transcript: bytearray) -> bytes:
    if not port.is_absolute() or port.is_symlink():
        raise GuestProbeError("untrusted private QEMU serial path")
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        until = time.monotonic() + 30
        while True:
            try:
                conn.connect(str(port))
                break
            except (ConnectionRefusedError, FileNotFoundError):
                if time.monotonic() > until:
                    raise GuestProbeError("private QEMU serial unavailable") from None
                time.sleep(0.25)
        wait_for(conn, transcript, re.compile(rb"Linux version|systemd\[1\]"),
                 timeout_seconds=180)
        wait_for(conn, transcript, re.compile(rb"Startup finished in"),
                 timeout_seconds=300)
        # The genuine early root debug shell may be noisy at startup.
        # Challenge with repeated short commands, not brittle prompt parsing.
        for attempt in range(10):
            start = len(transcript)
            conn.sendall(b"printf 'GASLUX_POP_LIVE_SHELL_READY\\n'\r")
            try:
                wait_for(conn, transcript, READY, timeout_seconds=22, start=start)
            except GuestProbeError as e:
                if attempt == 9 or "timed out" not in str(e):
                    raise
                continue
            break
        stages = [
            (
                b"mkdir -p /run/gaslux-pop-lab && mount -t vfat -o ro "
                b"/dev/disk/by-label/GASLUXLAB /run/gaslux-pop-lab && "
                b"printf 'GASLUX_POP_LAB_CONTROL_MOUNTED=1\\n'\r",
                MOUNT, 45,
            ),
            (
                b"cd /run/gaslux-pop-lab && sha256sum -c lab.sha256 && "
                b"printf 'GASLUX_POP_LAB_CONTROL_SHA_VERIFIED=1\\n'\r",
                HASHES, 90,
            ),
            (
                b"cd /run/gaslux-pop-lab && "
                b"GASLUX_POP_LIVE_GPT_RO_CONSENT="
                b"I_ACCEPT_DISPOSABLE_GUEST_GPT_READ_ONLY "
                b"python3 -B windows10_popos_genuine_live_guest_probe.py\r",
                RESULT, 190,
            ),
        ]
        for command, expected, secs in stages:
            start = len(transcript)
            conn.sendall(command)
            wait_for(conn, transcript, expected, timeout_seconds=secs, start=start)
            text = normalized(bytes(transcript[start:]))
            if REFUSED.search(text):
                raise GuestProbeError("Pop guest refused Windows GPT identity")
        all_output = normalized(bytes(transcript))
        match = JSON_MARKER.search(all_output)
        if match is None:
            raise GuestProbeError("inside-live-GPT-guest JSON proof absent")
        # Do not rely solely on guest marker: caller independently audits QCOW2
        # before/after, verifies stage COW and the clean virtual poweroff.
        start = len(transcript)
        conn.sendall(b"sync && printf 'GASLUX_POP_LIVE_SYNC_DONE=1\\n'\r")
        wait_for(conn, transcript, SYNCDONE, timeout_seconds=60, start=start)
        conn.sendall(b"systemctl poweroff -i\r")
        until = time.monotonic() + 120
        while time.monotonic() < until:
            conn.settimeout(2)
            try:
                data = conn.recv(16384)
            except TimeoutError:
                continue
            if not data:
                break
            transcript.extend(data)
            if len(transcript) > 12_000_000:
                raise GuestProbeError("unbounded live serial evidence")
        else:
            raise GuestProbeError("Pop live guest did not terminate serial on poweroff")
        return match.group(1)
    finally:
        conn.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--socket", type=Path, required=True)
    ap.add_argument("--trace", type=Path, required=True)
    ap.add_argument("--json-output", type=Path, required=True)
    args = ap.parse_args(argv)
    transcript = bytearray()
    try:
        payload = run(args.socket, transcript)
        args.json_output.write_bytes(payload + b"\n")
        print("GASLUX_POP_LIVE_GENUINE_WIN10_COW_GPT_GUEST_SERIAL_VERIFIED=1",
              flush=True)
        return 0
    except (GuestProbeError, OSError) as error:
        print("GASLUX_POP_LIVE_GUEST_SERIAL_REFUSED: "+str(error),
              file=sys.stderr, flush=True)
        print(normalized(bytes(transcript[-1800:])).decode(
              "utf-8", errors="replace"), file=sys.stderr)
        return 1
    finally:
        args.trace.write_bytes(transcript)


if __name__ == "__main__":
    raise SystemExit(main())
