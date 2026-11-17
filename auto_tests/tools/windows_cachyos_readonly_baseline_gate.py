#!/usr/bin/env python3
"""Read-only, fail-closed Windows client *candidate* evidence gate for CachyOS labs.

This is not Windows provenance authentication, disk authorization, or dual boot.
The evidence is user-supplied and could be forged. No block devices are opened.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

from windows_x64_qemu_host_gate import EXPECTED, load_catalog

MAX_REPORT = 65536
MAX_SERIAL = 16 * 1024 * 1024
MAX_MANIFEST = 512
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
DVD_START = re.compile(rb'BdsDxe: starting Boot[0-9A-Fa-f]{4} "UEFI QEMU DVD-ROM')


class BaselineGateError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise BaselineGateError(reason)


def read_regular(path: Path, limit: int) -> bytes:
    """Read bounded evidence through O_NOFOLLOW, never from a device or link."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit,
                "missing, oversized or nonregular evidence")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(limit + 1)
        require(len(data) == info.st_size, "evidence changed while reading")
        return data
    finally:
        os.close(fd)


def unique_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def evaluate(profile: str, report: dict, serial: bytes,
             manifest: bytes) -> dict[str, object]:
    """Cross-check supplied two-stage evidence; never authorize any writing."""
    catalog = load_catalog()
    require(profile in EXPECTED and profile in catalog["profiles"],
            "unknown Windows client profile")
    require(type(report) is dict and report.get("profile") == profile,
            "Windows result belongs to another profile")
    for key in ("isoHashVerified", "officialIsoUnmodified",
                "labDerivedIsoOnly", "windowsClientBootVerified"):
        require(report.get(key) is True, "missing Windows lab proof: " + key)
    for key in ("stable", "dualBootVerified", "winReAndBcdRecovered"):
        require(report.get(key) is False,
                "unsupported Windows recovery/stability claim: " + key)
    require(not report.get("error"), "Windows lab reported failure")
    require(report.get("accelerator") == "kvm", "Windows did not run in KVM")
    require(report.get("isoSha256") == EXPECTED[profile],
            "Windows ISO does not match pinned Microsoft digest")
    require(type(report.get("isoSizeBytes")) is int and
            report["isoSizeBytes"] >= 3 * 1024**3 and
            report["isoSizeBytes"] <= 9 * 1024**3,
            "invalid Windows ISO size")
    for key in ("firstLogonScriptSha256", "labDerivedIsoSha256",
                "initialDvdGuestSerialSha256"):
        require(type(report.get(key)) is str and
                SHA256.fullmatch(report[key]) is not None,
                "missing SHA256: " + key)
    require(len(serial) > 0 and len(serial) <= MAX_SERIAL,
            "empty or oversized installed Windows serial")
    require(not DVD_START.search(serial),
            "second-stage Windows serial contains an EFI DVD start")
    require(b"GASLUX_WINDOWS_X64_FIRSTBOOT_FAIL" not in serial,
            "Windows guest signalled firstboot failure")
    try:
        manifest_text = manifest.decode("ascii")
    except UnicodeDecodeError as error:
        raise BaselineGateError("invalid serial digest manifest") from error
    expected_filename = profile + "-serial.log"
    matching = re.fullmatch(r"([0-9a-f]{64})  (" +
                           re.escape(expected_filename) + r")\n?",
                           manifest_text)
    require(matching is not None and
            matching.group(1) == hashlib.sha256(serial).hexdigest(),
            "Windows serial SHA256 does not match owned evidence manifest")
    # The actual installed Windows FirstLogon witness writes one marker per
    # serial line. A textual marker alone is not proof of the guest's origin.
    lines = serial.decode("utf-8", errors="replace").splitlines()
    markers = (
        "GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=" + profile,
        "GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1",
        "GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1",
        "GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1",
        "GASLUX_WINDOWS_X64_WINRE_ENABLED=1",
        "GASLUX_WINDOWS_X64_BCD_ENUMERATED=1",
        "GASLUX_WINDOWS_X64_BOOT_BUILD=" +
        catalog["profiles"][profile]["expectedWindowsBuildPrefix"],
    )
    for marker in markers:
        require(lines.count(marker) == 1,
                "missing/ambiguous installed client witness: " + marker)
    require(all(not line.startswith("GASLUX_WINDOWS_X64_BOOT_BUILD=")
                or line == markers[-1] for line in lines),
            "ambiguous Windows build witness")
    # Never promote a self-reported, SHA-hashed text document to an
    # authenticated Windows guest, safe disk mutation or product release.
    return {
        "candidateWindowsFirstbootDocumentsConsistent": True,
        "pinnedMicrosoftIsoDigestMatched": True,
        "secondStageDvdStartAbsent": True,
        "serialManifestVerified": True,
        "windowsGuestOriginAuthenticated": False,
        "windowsBootVerified": False,
        "windowsBcdWinreRestorationVerified": False,
        "sameDiskDualBootVerified": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--serial", required=True, type=Path)
    parser.add_argument("--serial-sha256", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = json.loads(read_regular(args.result, MAX_REPORT),
                            object_pairs_hook=unique_keys)
        proof = evaluate(
            args.profile, result,
            read_regular(args.serial, MAX_SERIAL),
            read_regular(args.serial_sha256, MAX_MANIFEST),
        )
    except (BaselineGateError, OSError, ValueError, TypeError, KeyError,
            json.JSONDecodeError) as error:
        print(json.dumps({
            "candidateWindowsFirstbootDocumentsConsistent": False,
            "storageWritesAuthorized": False,
            "releaseEligible": False,
            "sameDiskDualBootVerified": False,
            "error": str(error),
        }, sort_keys=True))
        return 2
    print(json.dumps(proof, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
