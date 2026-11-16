#!/usr/bin/env python3
"""Fail-closed, read-only prerequisites for two real Windows client x64 QEMU VMs.

This does NOT install Windows. A passing host readiness gate cannot be
interpreted as an OS boot, dual boot, BCD/WinRE verification or rollback proof.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import stat
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "auto_tests/fixtures/windows_x64_official_evaluation_isos.json"

# The authoritative Microsoft SHA-256 publications were verified independently.
# Do not allow a change to the JSON fixture to silently permit a different ISO.
EXPECTED = {
    "win10_22h2_en_us_x64":
        "ef7312733a9f5d7d51cfa04ac497671995674ca5e1058d5164d6028f0938d668",
    "win11_26h2_en_us_x64":
        "bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38",
}
WINDOWS10_SOURCE = (
    "https://download.microsoft.com/download/c/1/1/"
    "c11d2ca5-967c-45c0-bc7d-2d9ca3f1fe07/Windows10Enterprise22H2HashValues.pdf"
)
WINDOWS11_SOURCE = (
    "https://support.microsoft.com/en-us/servicing/os/windows/docs/2026/09/"
    "verify-the-authenticity-of-a-windows-11-enterprise-evaluation-iso-file"
)
MIN_DISK_FREE = 28 * 1024**3
MIN_AVAILABLE_MEMORY = 8 * 1024**3
OVMF_CODE = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
OVMF_VARS = "/usr/share/OVMF/OVMF_VARS_4M.fd"


def load_catalog(path: Path = CATALOG) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if (type(data) is not dict or data.get("schemaVersion") != 1 or
            data.get("labOnly") is not True or
            data.get("windowsClientBootVerified") is not False):
        raise ValueError("unexpected evaluation contract")
    if set(data.get("profiles", {})) != set(EXPECTED):
        raise ValueError("Windows 10+11 x64 client matrix incomplete")
    for key, sha in EXPECTED.items():
        p = data["profiles"][key]
        if type(p) is not dict or p.get("sha256") != sha:
            raise ValueError(f"{key}: hash deviates from Microsoft publication")
        expected_source = WINDOWS10_SOURCE if key.startswith("win10") else WINDOWS11_SOURCE
        if (p.get("hashAuthorityUrl") != expected_source or
                p.get("expectedProductType") != 1 or
                p.get("architecture") != "x64" or
                p.get("firmware") != "uefi" or
                p.get("partitionStyle") != "gpt" or
                p.get("issuer") != "Microsoft" or
                p.get("releaseReady") is not False):
            raise ValueError(f"{key}: incorrect client architecture/authority/firmware")
        url = urlparse(p.get("downloadUrl", ""))
        if (url.scheme != "https" or url.hostname != "go.microsoft.com" or
                url.username or url.password or url.fragment or
                url.path not in ("/fwlink/", "/fwlink/p/")):
            raise ValueError(f"{key}: not an official HTTPS Microsoft fwlink")
        if key.startswith("win10") and p.get("expectedWindowsBuildPrefix") != "19045":
            raise ValueError("Windows 10 build expectation changed")
        if key.startswith("win11") and p.get("expectedWindowsBuildPrefix") != "26300":
            raise ValueError("Windows 11 build expectation changed")
    return data


def available_memory_bytes() -> int:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    return 0


def kvm_accessible() -> bool:
    kvm = Path("/dev/kvm")
    if not kvm.exists() or kvm.is_symlink():
        return False
    if not stat.S_ISCHR(kvm.stat().st_mode):
        return False
    try:
        with kvm.open("rb+"):
            return True
    except OSError:
        return False


def host_report(path: Path = Path("/mnt")) -> dict:
    failed: list[str] = []
    if (os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_OS") != "Linux" or
            os.environ.get("GASLUX_VM_TEST_CONSENT") != "DISPOSABLE_GITHUB_ACTIONS_ONLY"):
        failed.append("dedicated authorized GitHub-hosted Linux runner absent")
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
        failed.append("host must be Linux x64")
    if not kvm_accessible():
        failed.append("hardware KVM acceleration unavailable or denied on hosted runner")
    free = shutil.disk_usage(path).free
    if free < MIN_DISK_FREE:
        failed.append("less than 28 GiB free on VM test volume")
    if available_memory_bytes() < MIN_AVAILABLE_MEMORY:
        failed.append("less than 8 GiB available RAM")
    for name in ("qemu-img", "qemu-system-x86_64", "swtpm", "sha256sum"):
        if shutil.which(name) is None:
            failed.append(f"required VM tool missing: {name}")
    for f in (OVMF_CODE, OVMF_VARS):
        p = Path(f)
        if not (p.is_file() and not p.is_symlink() and p.stat().st_size > 500_000):
            failed.append(f"OVMF firmware file missing/unsafe: {f}")
    return {
        "schemaVersion": 1,
        "profileCount": len(EXPECTED),
        "evaluationIsoHashesPinnedFromMicrosoft": True,
        "readyForWindows10X64Guest": not failed,
        "readyForWindows11X64Guest": not failed,
        "windows10GuestInstalled": False,
        "windows11GuestInstalled": False,
        "windowsAndLinuxDualBootVerified": False,
        "windowsRecoveryVerified": False,
        "productionStable": False,
        "physicalDiskWrites": False,
        "blockers": failed,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=("metadata", "host"), required=True)
    ap.add_argument("--report", type=Path)
    args = ap.parse_args(argv)
    try:
        load_catalog()
        result = ({"schemaVersion": 1, "profiles": sorted(EXPECTED),
                   "officialMicrosoftSHA256Pinned": True,
                   "windowsClientBootVerified": False,
                   "stableForWindows10Or11": False}
                  if args.mode == "metadata" else host_report())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result = {"schemaVersion": 1, "ok": False, "error": str(exc),
                  "windowsClientBootVerified": False, "productionStable": False}
    ok = ("error" not in result and
          (args.mode == "metadata" or result["readyForWindows10X64Guest"]))
    result["ok"] = bool(ok)
    encoded = json.dumps(result, sort_keys=True, indent=2)
    print(encoded)
    if args.report is not None:
        if args.report.is_symlink() or args.report.exists():
            print("refusing existing or linked report path", file=sys.stderr)
            return 2
        if not args.report.parent.is_dir():
            print("report directory missing", file=sys.stderr)
            return 2
        args.report.write_text(encoded + "\n", encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
