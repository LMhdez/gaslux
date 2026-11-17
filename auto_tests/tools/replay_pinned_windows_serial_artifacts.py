#!/usr/bin/env python3
"""Offline replay of two SHA-pinned genuine Microsoft-client QEMU COM1 artifacts.

The original 17 Nov 2026 GitHub Actions run #44048550209 did NOT pass its
historical firstboot host gate. These artifacts were collected from disposable
KVM guests and are used ONLY as independent parser regression inputs.
No guest is started, no storage is written, and no boot is certified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from windows_x64_qemu_host_gate import EXPECTED
from windows_x64_tcg_firstboot import (
    FAILURE,
    GUEST_PROOF_TOKEN_ALLOWLIST,
    MARKER,
    scan_windows_guest_tokens,
)

# SHA-256 values measured from the immutable GH Actions artifact ZIPs.
# Do not change these in response to CI failures or use synthetic substitutes.
PINNED = {
    "win10_22h2_en_us_x64": {
        "build": "19045",
        "first_sha256": "af961a954499b5354d36cfbfd8d7633d8403d5e362386e994791c5b65738fcf1",
        "serial_sha256": "5c59b062ab19e874328b424857c192375830e31896a102790e6386af1c48f637",
        "report_sha256": "635d3228bf3dd0be896c3a83d6ad090c0fb51a1ab24f2e703dabddc632749c15",
    },
    "win11_26h2_en_us_x64": {
        "build": "26300",
        "first_sha256": "00942807d69285c8331e772519ca90497d466f8ec32e88a91ea28c39611c99a3",
        "serial_sha256": "8f84030570fb924f798516139cd2850f7a3c8e9795211595510d4db6da46b41e",
        "report_sha256": "6ad9a756d0a03bab7052432878dc0380fa792f0d9f462930dd7185d8b872cdec",
    },
}
DVD_START = re.compile(rb'BdsDxe: starting Boot[0-9A-Fa-f]{4} "UEFI QEMU DVD-ROM')
WINDOWS_BOOT_MANAGER = re.compile(
    rb'BdsDxe: starting Boot[0-9A-Fa-f]{4} "Windows Boot Manager"'
)


def require(condition: bool, why: str) -> None:
    if not condition:
        raise ValueError(why)


def pinned_bytes(path: Path, max_bytes: int, expected_digest: str) -> bytes:
    require(path.is_file() and not path.is_symlink(), "missing/nonregular artifact")
    require(0 < path.stat().st_size <= max_bytes, "artifact size outside safe limit")
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == expected_digest,
            "authentic archived evidence hash mismatch")
    return data


def replay(root: Path, profile: str) -> dict[str, object]:
    pin = PINNED[profile]
    directory = root / profile
    require(directory.is_dir() and not directory.is_symlink(), "missing profile archive")
    report_path = directory / (profile + "-result.json")
    initial = directory / (profile + "-initial-dvd-serial.log")
    serial = directory / (profile + "-serial.log")
    first_hash = directory / (profile + "-initial-dvd-serial.sha256")
    last_hash = directory / (profile + "-serial.sha256")
    require(
        {p.name for p in directory.iterdir()} ==
        {p.name for p in (report_path, initial, serial, first_hash, last_hash)},
        "unexpected original artifact files",
    )
    report_bytes = pinned_bytes(report_path, 64_000, pin["report_sha256"])
    first_bytes = pinned_bytes(initial, 2_000_000, pin["first_sha256"])
    last_bytes = pinned_bytes(serial, 2_000_000, pin["serial_sha256"])
    for file, digest, filename in (
        (first_hash, pin["first_sha256"], initial.name),
        (last_hash, pin["serial_sha256"], serial.name),
    ):
        content = pinned_bytes(
            file, 512, hashlib.sha256((digest + "  " + filename + "\n").encode()).hexdigest()
        )
        require(content == (digest + "  " + filename + "\n").encode(),
                "archived serial digest manifest changed")
    report = json.loads(report_bytes)
    require(report["profile"] == profile and report["accelerator"] == "kvm",
            "replayed report belongs to another Windows guest")
    require(report.get("isoHashVerified") is True and
            report.get("isoSha256") == EXPECTED[profile],
            "original Microsoft ISO hash was not verified")
    require(report["initialDvdGuestSerialSha256"] == pin["first_sha256"],
            "first-stage report SHA does not match genuine DVD log")
    # The historical verdict MUST remain negative; parser compatibility is
    # not retroactive proof of a clean Windows shutdown or recovery.
    require(report["windowsClientBootVerified"] is False and
            report["dualBootVerified"] is False and
            report["winReAndBcdRecovered"] is False and
            report["stable"] is False,
            "historical Windows boot/recovery flags were unexpectedly upgraded")
    require(
        "QEMU exited before installed Windows first-logon witness"
        in report["diagnostic"],
        "historical failure classification unexpectedly changed",
    )
    require(len(DVD_START.findall(first_bytes)) == 1,
            "first-stage firmware did not start Microsoft DVD exactly once")
    require(not DVD_START.search(last_bytes),
            "disk-only Windows guest replay booted its DVD")
    require(WINDOWS_BOOT_MANAGER.search(last_bytes) is not None,
            "installed disk never started Windows Boot Manager")
    require(FAILURE.encode() not in last_bytes,
            "guest emitted an explicit failed-audit marker")

    tokens, consumed, carry, discarding = scan_windows_guest_tokens(
        serial, 0, b"", False,
    )
    require(consumed == len(last_bytes) and not discarding,
            "COM1 scanner did not consume complete genuine artifact")
    # The old guest already exited before the artifact was archived. A final
    # carry is only a complete token at EOF; this does not certify VM exit.
    if carry in GUEST_PROOF_TOKEN_ALLOWLIST:
        tokens.add(carry)
    elif carry:
        require(not carry.startswith(FAILURE.encode()),
                "trailing guest failure marker")
    required = {
        ("GASLUX_WINDOWS_X64_BOOT_BUILD=" + pin["build"]).encode(),
        b"GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1",
        b"GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1",
        b"GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1",
        b"GASLUX_WINDOWS_X64_BCD_ENUMERATED=1",
        b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1",
        f"{MARKER}={profile}".encode(),
    }
    require(tokens == required, "current scanner could not recognize authentic COM1 proof tokens")
    require(all(last_bytes.count(t) == 1 for t in required),
            "historical guest COM1 duplicated or omitted audit proof")
    return {
        "profile": profile,
        "authenticArchivedCom1ParserCompatible": True,
        "recognizedCompleteAuditTokens": len(required),
        "historicalWindowsBootCertified": False,
        "windowsRecoveryVerified": False,
        "dualBootVerified": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-directory", type=Path, required=True)
    args = parser.parse_args()
    results = []
    try:
        for profile in PINNED:
            results.append(replay(args.artifact_directory, profile))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(json.dumps({"replayPassed": False, "windowsBootVerified": False,
                          "storageWritesAuthorized": False, "error": str(error)},
                         sort_keys=True))
        return 1
    print(json.dumps({"replayPassed": True, "profiles": results,
                      "windowsBootVerified": False, "releaseEligible": False},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
