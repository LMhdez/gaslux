#!/usr/bin/env python3
"""Fail-closed verifier for an installed CachyOS VM serial transcript.

This checks the evidence emitted by a *separately booted installed guest*.
It does not claim that the serial transcript cryptographically proves disk
ownership or Windows coexistence; those require independent guest checks.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT_UUID = "01234567-89ab-cdef-0123-456789abcdef"
MAX_BYTES = 8_000_000
ROOT_LINE = re.compile(rb"^GASLUX_INSTALLED_CACHYOS_ROOT_UUID=([^\r\n]+)$", re.M)
PASS_LINE = re.compile(rb"^GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_PASS=1$", re.M)
FAIL_LINE = re.compile(rb"^GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_FAIL(?::[^\r\n]*)?$", re.M)


class EvidenceError(ValueError):
    """Installed boot evidence is absent, ambiguous or contradictory."""


def verify(data: bytes) -> None:
    if not data or len(data) > MAX_BYTES or b"\x00" in data:
        raise EvidenceError("serial transcript missing, oversized or binary")
    # Normalize terminal line endings but do not remove/ignore any content.
    normalized = data.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        raise EvidenceError("unexpected bare carriage return")
    if FAIL_LINE.search(normalized):
        raise EvidenceError("installed guest explicitly reported failure")
    roots = list(ROOT_LINE.finditer(normalized))
    passes = list(PASS_LINE.finditer(normalized))
    if len(roots) != 1 or len(passes) != 1:
        raise EvidenceError("expected exactly one root identity and one success")
    if roots[0].group(1) != ROOT_UUID.encode():
        raise EvidenceError("unexpected installed root UUID")
    if roots[0].end() >= passes[0].start():
        raise EvidenceError("success preceded root identity")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("serial", type=Path)
    args = parser.parse_args()
    if not args.serial.is_file() or args.serial.is_symlink():
        parser.error("serial must be a regular non-symlink file")
    size = args.serial.stat().st_size
    if not 0 < size <= MAX_BYTES:
        parser.error("serial file is empty or exceeds limit")
    try:
        verify(args.serial.read_bytes())
    except EvidenceError as error:
        parser.error(str(error))
    print("PASS: installed guest serial root UUID and single firstboot proof verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
