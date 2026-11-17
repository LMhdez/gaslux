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
from windows_x64_tcg_firstboot import witness_powershell

MAX_REPORT = 65536
MAX_SERIAL = 16 * 1024 * 1024
# Host archiver retains first-stage DVD serial only when <= 2,000,000 bytes.
MAX_INITIAL_SERIAL = 2_000_000
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
             manifest: bytes, initial_serial: bytes,
             initial_manifest: bytes) -> dict[str, object]:
    """Cross-check supplied two-stage evidence; never authorize any writing."""
    catalog = load_catalog()
    require(profile in EXPECTED and profile in catalog["profiles"],
            "unknown Windows client profile")
    require(type(report) is dict and report.get("profile") == profile,
            "Windows result belongs to another profile")
    for key in ("isoHashVerified", "officialIsoUnmodified",
                "windowsClientBootVerified"):
        require(report.get(key) is True, "missing Windows lab proof: " + key)
    # Two mutually exclusive SHA-pinned Windows boot-media paths now exist:
    # the derived no-prompt ISO used by PR #98, and the ORIGINAL Microsoft
    # ISO attached read-only by PR #108. Do not silently require or invent a
    # derivative for the original-media experiment. This is only a report
    # consistency gate: report flags/manifest cannot authenticate their origin.
    derived_mode = report.get("labDerivedIsoOnly")
    require(type(derived_mode) is bool,
            "Windows boot-media mode must be an explicit boolean")
    for key in ("stable", "dualBootVerified", "winReAndBcdRecovered"):
        require(report.get(key) is False,
                "unsupported Windows recovery/stability claim: " + key)
    require(not report.get("error"), "Windows lab reported failure")
    # A reported success flag alone is not proof of completion. Require the
    # exact diagnostic emitted only by the verified installed-guest serial
    # audit followed by clean QEMU exit, not a generic exit code zero.
    require(
        report.get("diagnostic") ==
        "installed Windows client audit and clean VM poweroff verified",
        "Windows firstboot audit and clean guest shutdown not both proven",
    )
    require(report.get("accelerator") == "kvm", "Windows did not run in KVM")
    require(report.get("isoSha256") == EXPECTED[profile],
            "Windows ISO does not match pinned Microsoft digest")
    require(type(report.get("isoSizeBytes")) is int and
            report["isoSizeBytes"] >= 3 * 1024**3 and
            report["isoSizeBytes"] <= 9 * 1024**3,
            "invalid Windows ISO size")
    for key in ("firstLogonScriptSha256",
                "initialDvdGuestSerialSha256"):
        require(type(report.get(key)) is str and
                SHA256.fullmatch(report[key]) is not None,
                "missing SHA256: " + key)
    if derived_mode:
        derivative = report.get("labDerivedIsoSha256")
        require(type(derivative) is str and
                SHA256.fullmatch(derivative) is not None and
                derivative != EXPECTED[profile],
                "derived Windows ISO must have a distinct SHA256")
    else:
        require("labDerivedIsoSha256" not in report,
                "unaltered original Windows ISO cannot claim a derived hash")
    # Bind the Windows guest audit script to the checked-out source itself,
    # rather than accepting an arbitrary syntactically valid SHA256. This
    # independently catches an altered FirstLogon audit payload.
    third_boot = (os.environ.get("GASLUX_WINDOWS_THIRDBOOT_TEST")
                  == "I_ACCEPT_THIRD_WINDOWS_KVM_BOOT")
    if third_boot:
        require(report.get("windowsRebootAfterOverlayDiscardVerified") is True,
                "third Windows boot after overlay discard not confirmed")
    generated = witness_powershell(
        profile, catalog["profiles"][profile]["expectedWindowsBuildPrefix"],
        third_boot_lab=third_boot,
    ) + "\n"
    require(
        report["firstLogonScriptSha256"] ==
        hashlib.sha256(generated.encode("utf-8")).hexdigest(),
        "Windows FirstLogon script SHA256 differs from checked-out witness",
    )
    require(0 < len(initial_serial) <= MAX_INITIAL_SERIAL,
            "missing or oversized initial Windows DVD serial")
    # The original Windows two-stage host owns this first-stage log and
    # records its SHA-256 in the same JSON that names the second-stage guest.
    # Cross-check the actual archived bytes, rather than merely accepting an
    # arbitrary syntactically valid report digest.
    first_digest = hashlib.sha256(initial_serial).hexdigest()
    require(first_digest == report["initialDvdGuestSerialSha256"],
            "initial DVD serial SHA256 differs from Windows report")
    try:
        first_manifest_text = initial_manifest.decode("ascii")
    except UnicodeDecodeError as error:
        raise BaselineGateError("invalid initial DVD serial manifest") from error
    first_filename = profile + "-initial-dvd-serial.log"
    first_match = re.fullmatch(
        r"([0-9a-f]{64})  " + re.escape(first_filename) + r"\n?",
        first_manifest_text,
    )
    require(first_match is not None and first_match.group(1) == first_digest,
            "initial DVD serial SHA256 differs from evidence manifest")
    require(len(DVD_START.findall(initial_serial)) == 1,
            "initial DVD stage must show exactly one UEFI DVD startup")
    # The original Microsoft Windows 10 DVD may print its real key prompt,
    # followed by a firmware timeout if the HMP Enter arrived too late.
    # This exact failure was witnessed in PR #108 real COM1 logs. An
    # apparently successful report must never override a recorded failed
    # UEFI boot attempt, even with a syntactically valid serial manifest.
    require(
        not re.search(
            rb'(?im)^BdsDxe: failed to start Boot[0-9a-f]{4} '
            rb'"UEFI QEMU DVD-ROM[^\r\n]*Time out',
            initial_serial,
        ),
        "initial Windows DVD firmware reported a boot timeout",
    )
    require(
        not any(
            b"DVD-ROM" in line and b"Time out" in line
            for line in initial_serial.splitlines()
        ),
        "initial Windows DVD firmware reported a boot timeout",
    )
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
    # Both client builds share five audit fields plus exact build/profile.
    # Never collect an unbounded set of arbitrary GASLUX_WINDOWS_X64_* tokens:
    # the native Windows COM1 scanner's PR94 allowlist is an upper bound,
    # not permission to accept unrecognized names in downstream evidence.
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
    allowed = frozenset(markers)
    allowed_names = frozenset(marker.split("=", 1)[0] for marker in markers)
    seen: dict[str, int] = {}
    # Real COM1 WriteLine calls may coalesce into one line. A bounded, exact
    # whitespace-delimited witness is acceptable; arbitrary prefixes are not.
    for line in serial.decode("ascii", errors="replace").splitlines():
        fields = line.split()
        if any("GASLUX_WINDOWS_X64_" in field for field in fields):
            require(all(field.startswith("GASLUX_WINDOWS_X64_") and
                        len(field) <= 256 for field in fields),
                    "unexpected prefix or oversized Windows serial witness")
            for field in fields:
                if field not in allowed:
                    name = field.split("=", 1)[0]
                    if name in allowed_names:
                        raise BaselineGateError(
                            "ambiguous Windows witness field: " + name)
                    raise BaselineGateError(
                        "unrecognized Windows serial proof token")
                seen[field] = seen.get(field, 0) + 1
                require(seen[field] <= 1,
                        "missing/ambiguous installed client witness: " + field)
    for marker in markers:
        require(seen.get(marker, 0) == 1,
                "missing/ambiguous installed client witness: " + marker)
    # Never promote a self-reported, SHA-hashed text document to an
    # authenticated Windows guest, safe disk mutation or product release.
    return {
        "candidateWindowsFirstbootDocumentsConsistent": True,
        "pinnedMicrosoftIsoDigestMatched": True,
        "secondStageDvdStartAbsent": True,
        "initialDvdSerialManifestVerified": True,
        "firstStageSingleDvdStartObserved": True,
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
    parser.add_argument("--initial-dvd-serial", required=True, type=Path)
    parser.add_argument("--initial-dvd-serial-sha256", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = json.loads(read_regular(args.result, MAX_REPORT),
                            object_pairs_hook=unique_keys)
        proof = evaluate(
            args.profile, result,
            read_regular(args.serial, MAX_SERIAL),
            read_regular(args.serial_sha256, MAX_MANIFEST),
            read_regular(args.initial_dvd_serial, MAX_INITIAL_SERIAL),
            read_regular(args.initial_dvd_serial_sha256, MAX_MANIFEST),
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
