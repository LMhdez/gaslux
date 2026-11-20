#!/usr/bin/env python3
"""Issue #3: verify real protected Windows files inside a genuine CachyOS Archiso.

Strictly read-only laboratory stage. This code never authorizes installation,
partition or EFI writes. QEMU additionally attaches the Windows COW readonly.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Any, Callable

from cachyos_windows_shared_archiso_handoff import (
    SERIAL, SharedDiskHandoffRejected, require, verify,
)
from cachyos_windows_shared_archiso_guest_probe import (
    efi_mode_readonly, require_live_archiso, validate_lsblk_readonly,
)
from cachyos_windows_shared_gpt_raw_audit import (
    inspect_bound_gpt_windows, read_guest_disk_windows_readonly,
)

WINDOWS_FILES = (
    (0, "vfat", "EFI/Microsoft/Boot/bootmgfw.efi", "espBootManagerSha256"),
    (0, "vfat", "EFI/Microsoft/Boot/BCD", "espBcdSha256"),
    (2, "ntfs3", "Windows/System32/winload.efi", "windowsLoaderSha256"),
    (3, "ntfs3", "Recovery/WindowsRE/Winre.wim", "winreImageSha256"),
)
RO_OPTIONS = {"ro", "nosuid", "nodev", "noexec"}


def command(argv: list[str], timeout: int = 20) -> str:
    completed = subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        check=False, timeout=timeout,
    )
    require(completed.returncode == 0,
            "read-only Windows verification command failed: " + argv[0])
    require(len(completed.stdout) < 8192, "unexpected command output size")
    return completed.stdout.strip()


def select_sources(plan: dict[str, Any], observed: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    """Bind each protected file to signed GUID and the exact selected virtio disk."""
    verdict = validate_lsblk_readonly(plan, observed)
    require(verdict["storageWritesAuthorized"] is False,
            "shared disk topology unexpectedly authorizes writes")
    matches = [d for d in observed["blockdevices"]
               if type(d) is dict and d.get("type") == "disk"
               and d.get("serial") == SERIAL]
    require(len(matches) == 1, "selected QEMU disk is not unique")
    disk = matches[0]
    sources = []
    for index, fs_type, relative, hash_key in WINDOWS_FILES:
        partition = disk["children"][index]
        source = partition["path"]
        require(source == disk["path"] + str(index + 1)
                and partition["partuuid"] == plan["partitions"][index]["uniqueGuid"]
                and partition["fstype"].lower() in
                    (("vfat", "fat") if fs_type == "vfat" else ("ntfs", "ntfs3"))
                and hash_key in plan["windowsHashes"],
                "protected Windows file is not on signed partition")
        sources.append((source, fs_type, relative, hash_key))
    return sources


def hash_regular_no_symlinks(root: Path, relative: str) -> str:
    """Never traverse a symlink or reparse link outside the read-only mount."""
    require(relative and not relative.startswith("/") and
            ".." not in relative.split("/"), "unsafe protected Windows path")
    target = root
    segments = relative.split("/")
    for n, segment in enumerate(segments):
        require(segment not in ("", ".", ".."),
                "unsafe protected Windows path component")
        target = target / segment
        st = target.lstat()
        require(not stat.S_ISLNK(st.st_mode),
                "protected Windows path contains a link")
        require(stat.S_ISDIR(st.st_mode) if n < len(segments) - 1
                else stat.S_ISREG(st.st_mode),
                "protected Windows file is not regular")
    fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode),
                "protected Windows target changed after path validation")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        return digest.hexdigest()
    finally:
        os.close(fd)


def audit_protected_windows(
    plan: dict[str, Any],
    observed: dict[str, Any],
    *, execute: Callable[[list[str], int], str] = command,
    hash_file: Callable[[Path, str], str] = hash_regular_no_symlinks,
    runtime_dir: Path = Path("/run"),
) -> dict[str, bool]:
    """Mount each source RO, independently hash, unmount; no root write grants."""
    sources = select_sources(plan, observed)
    require(runtime_dir.is_dir() and not runtime_dir.is_symlink(),
            "untrusted read-only verification scratch directory")
    with tempfile.TemporaryDirectory(prefix="gaslux-win-verify-ro-", dir=runtime_dir) as scratch:
        destination = Path(scratch)
        for source, filesystem, relative, hash_key in sources:
            mount_args = ["mount", "-t", filesystem, "-o",
                          "ro,nosuid,nodev,noexec", source, str(destination)]
            execute(mount_args, 30)
            try:
                origin = execute(["findmnt", "-n", "-M", str(destination),
                                  "-o", "SOURCE"], 15)
                options = execute(["findmnt", "-n", "-M", str(destination),
                                   "-o", "OPTIONS"], 15)
                require(origin == source
                        and RO_OPTIONS.issubset(set(options.split(","))),
                        "Windows mount is not bound read-only to signed partition")
                digest = hash_file(destination, relative)
                require(digest == plan["windowsHashes"][hash_key],
                        "real Windows EFI/BCD/loader/WinRE hash differs")
            finally:
                # Any failure, including unmount failure, rejects this audit.
                execute(["umount", str(destination)], 30)
    return {
        "realWindowsEspBcdLoaderWinreGuestHashesVerified": True,
        "guestWindowsMountsReadOnlyVerified": True,
        "pacstrapAuthorized": False,
        "storageWritesAuthorized": False,
        "windowsInPlaceRecoveryVerified": False,
        "sameDiskDualBootVerified": False,
        "releaseEligible": False,
    }


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--plan", required=True, type=Path)
    cli.add_argument("--signature", required=True, type=Path)
    cli.add_argument("--public-key", required=True, type=Path)
    cli.add_argument("--expected-run-id", required=True)
    cli.add_argument("--expected-root-uuid", required=True)
    args = cli.parse_args()
    try:
        require_live_archiso()
        efi_mode_readonly()
        authenticated = verify(
            args.plan, args.signature, args.public_key,
            Path("/proc/cmdline").read_text(encoding="utf-8"),
            independent_run_id=args.expected_run_id,
            independent_root_uuid=args.expected_root_uuid,
        )
        require(authenticated["storageWritesAuthorized"] is False,
                "signed Windows plan cannot grant write authority")
        # Canonical bytes and Ed25519 were validated by verify() above.
        plan = json.loads(args.plan.read_bytes())
        output = command(["lsblk", "--json", "--tree", "--bytes",
                          "--output", "NAME,TYPE,PATH,SERIAL,SIZE,LOG-SEC,START,PARTTYPE,PARTUUID,FSTYPE,UUID,MOUNTPOINTS"], 15)
        require(len(output) < 32768, "guest block topology too large")
        observed = json.loads(output)
        select_sources(plan, observed)
        disk = next(d for d in observed["blockdevices"]
                    if type(d) is dict and d.get("serial") == SERIAL
                    and d.get("type") == "disk")
        first, last = read_guest_disk_windows_readonly(Path(disk["path"]))
        inspect_bound_gpt_windows(first, last, plan)
        status = audit_protected_windows(plan, observed)
        print(json.dumps(status, sort_keys=True), flush=True)
        return 0
    except (SharedDiskHandoffRejected, OSError, ValueError, TypeError,
            KeyError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"realWindowsEspBcdLoaderWinreGuestHashesVerified": False,
                          "pacstrapAuthorized": False, "storageWritesAuthorized": False,
                          "releaseEligible": False, "error": str(exc)}, sort_keys=True),
              flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
