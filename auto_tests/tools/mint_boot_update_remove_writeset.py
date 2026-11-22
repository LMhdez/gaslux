#!/usr/bin/env python3
"""Read-only, SHA-pinned inventory of the Mint/Zorin boot maintenance boundary.

A forensic *inventory*, NOT a boot writer, policy waiver or live ESP proof.
Do not pass this result to grub-install, apt, efibootmgr or rollback to
authorize mutations. Source pins mean unreviewed code changes DENY analysis.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path, PurePosixPath

# Audited 2026-11-22 dev 8e68a475d6397ba8fef2e0f9f83758545e202a5f.
# Git blob SHA-1 values, not signatures. These pins guard STATIC AUDIT FRESHNESS;
# they authenticate neither the GitHub origin nor an installed OS.
PINNED_SOURCE_BLOBS: dict[str, str] = {
    "assets/live/libertix-update-grub.sh": "1cf3ac619fcbaed4958a94cc189b2fc86c94e700",
    "assets/live/libertix-sync-efi.sh": "3c93d6ba0c4538dcf209644a10503ea9f5e1c650",
    "assets/live/libertix-preferred-boot-path.py": "2202e84f094c1f3e7b2d67ddd8fbb90f51a478c5",
    "assets/live/configure-target-main.sh": "c5ea624dbbd61aabd36c0ab886c171559b79433f",
    "assets/live/libertix-install-main.sh": "f176249b0744905c2cc431869555837813b2ce2c",
    "assets/live/libertix-uefi-adapter.sh": "fed5228b27c8f4fa8da9f83f08e6c727da83d6a1",
    "assets/live/libertix-bios-adapter.sh": "93b4085aa1cd55c2d09f7ea00c8aa50d0b4e261d",
    "Scripts/libertix-uefi-recovery-agent.ps1": "ade5d6e961f4b73fadcb4aa84c5b47d8bbcbd254",
    "Scripts/uefi/Libertix.Uefi.Transaction.ps1": "c92227ee8d2a113fa1810c1ba91b82180d486579",
    "Scripts/uefi/Libertix.Uefi.Firmware.ps1": "bd02b3cbe5b16198983c482aff4fa5f3147198db",
    "Scripts/modules/Libertix.PreferredBootPath.psm1": "e95f72d7948e7c89ac1fc3694b2067e3bddcd9d7",
    "Pages/UninstallLinux.xaml.cs": "47236cbb56043043c193d35b471058762d4b7f2f",
}

SOURCE_BYTE_LIMIT = 1_000_000
ESP_FILE_BYTE_LIMIT = 32 * 1024 * 1024
TRANSACTION = re.compile(r"[a-f0-9]{32}\Z")
READONLY_FALSE = {
    "productionWriteAuthorized": False,
    "bootUpdateVerified": False,
    "windowsBootAfterUpdateVerified": False,
    "windowsInPlaceRollbackProven": False,
    "sameDiskDualBootVerified": False,
    "releaseEligible": False,
    "stable": False,
}


class BootWriteSetError(ValueError):
    pass


def _require(ok: bool, reason: str) -> None:
    if not ok:
        raise BootWriteSetError(reason)


def _read_pinned_regular(path: Path, root: Path, limit: int) -> bytes:
    """Read a regular, unlinked-once file without following known symlink paths.

    This is a diagnostic against obvious aliasing, not a same-UID race-free
    runtime authority (no physical device is touched and no writes occur).
    """
    _require(root.is_absolute() and path.is_relative_to(root), "source path escapes root")
    current = root
    _require(not current.is_symlink() and current.is_dir(), "source root is not a directory")
    for component in path.relative_to(root).parts[:-1]:
        _require(component not in ("", ".", ".."), "ambiguous source component")
        current = current / component
        mode = current.lstat().st_mode
        _require(stat.S_ISDIR(mode) and not stat.S_ISLNK(mode), "source ancestor is a link")
    before = path.lstat()
    _require(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == os.getuid()
        and before.st_nlink == 1
        and 0 < before.st_size <= limit,
        "source must be a single owned bounded regular file",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        _require(
            (opened.st_dev, opened.st_ino, opened.st_size)
            == (before.st_dev, before.st_ino, before.st_size),
            "source changed between lstat and open",
        )
        blocks = bytearray()
        while len(blocks) < before.st_size:
            piece = os.read(fd, min(65536, before.st_size - len(blocks)))
            _require(bool(piece), "short source read")
            blocks.extend(piece)
        _require(not os.read(fd, 1), "source grew during scan")
        after = os.fstat(fd)
        _require(
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
                opened.st_ctime_ns),
            "source identity or content changed during scan",
        )
        current = path.lstat()
        _require(
            (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino)
            and stat.S_ISREG(current.st_mode),
            "source pathname changed after scan",
        )
        return bytes(blocks)
    finally:
        os.close(fd)


def git_blob_sha1(content: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\x00" + content).hexdigest()


def audit_source_pins(repository: Path) -> dict:
    """Authenticate only the local CHECKED-OUT source bytes against reviewed pins."""
    _require(type(repository) is type(Path()) and repository.is_absolute(), "absolute repository path required")
    issues: list[dict] = []
    observed: dict[str, str | None] = {}
    for relative, expected in PINNED_SOURCE_BLOBS.items():
        try:
            blob = _read_pinned_regular(repository / relative, repository, SOURCE_BYTE_LIMIT)
            actual = git_blob_sha1(blob)
            observed[relative] = actual
            if actual != expected:
                issues.append({"file": relative, "reason": "source_git_blob_changed"})
        except (OSError, BootWriteSetError):
            observed[relative] = None
            issues.append({"file": relative, "reason": "source_missing_foreign_or_unreadable"})
    return {
        "reviewedDevCommit": "8e68a475d6397ba8fef2e0f9f83758545e202a5f",
        "sourcePinned": not issues,
        "sourcePinsAreCryptographicPublisherSignatures": False,
        "observedBlobIds": observed,
        "issues": issues,
        **READONLY_FALSE,
    }


def classify_write_set(*, firmware: str, operation: str, preferred_active: bool) -> dict:
    """Bounded code-path map, not a dynamic or exhaustive OS write trace."""
    _require(firmware in {"bios", "uefi"}, "unsupported firmware")
    _require(operation in {"install", "update", "uninstall"}, "unsupported operation")
    _require(type(preferred_active) is bool, "ambiguous fallback status")
    _require(firmware == "uefi" or not preferred_active, "preferred path is UEFI-only")

    entries: list[dict] = []

    def add(target: str, nature: str, source: str, impact: str) -> None:
        entries.append({
            "target": target, "operation": nature, "source": source,
            "impact": impact, "writeAuthorized": False,
        })

    if operation == "install":
        add("Linux root /boot and /etc", "initramfs/grub configuration", 
            "assets/live/configure-target-main.sh", "LINUX")
        if firmware == "bios":
            add("selected disk MBR boot code", "grub-install i386-pc --recheck", 
                "assets/live/libertix-install-main.sh", "PROTECTED_DISK")
        else:
            add("ESP/EFI/Libertix/*", "signed GRUB EFI installation", 
                "assets/live/libertix-uefi-adapter.sh", "SHARED_ESP")
            add("NVRAM/Boot####, BootOrder, BootNext", "boot entry staging/reordering", 
                "assets/live/libertix-uefi-adapter.sh", "FIRMWARE")
    elif operation == "update":
        add("Linux root /boot/grub/grub.cfg", "atomic candidate validation and replace",
            "assets/live/libertix-update-grub.sh", "LINUX")
        add("Linux root /boot/initrd.img-* and /boot/vmlinuz-*",
            "package/kernel/initramfs hooks (exact package write set not established)",
            "assets/live/configure-target-main.sh", "UNKNOWN_PACKAGE")
        if firmware == "bios":
            add("selected disk MBR/PBR", "possible external grub package maintainer hooks",
                "external dpkg package scripts not audited", "UNKNOWN_EXTERNAL_WRITER")
        else:
            add("ESP/EFI/Libertix/{shimx64.efi,grubx64.efi,mmx64.efi}",
                "package-signed EFI chain synchronization",
                "assets/live/libertix-sync-efi.sh", "SHARED_ESP")
            add("ESP/EFI/Libertix/secure-boot-chain.json",
                "installed EFI trust evidence replacement",
                "assets/live/libertix-sync-efi.sh", "SHARED_ESP")
            if preferred_active:
                for name in (
                    "bootmgfw.efi", "bootmgfw.libertix-windows.efi",
                    "grubx64.efi", "mmx64.efi", "grub.cfg",
                ):
                    add(f"ESP/EFI/Microsoft/Boot/{name}",
                        "conditional preferred-boot-path synchronization",
                        "assets/live/libertix-preferred-boot-path.py",
                        "WINDOWS_BOOT_CRITICAL")
                add("ESP/EFI/Libertix/BootGuardianReference/*",
                    "conditional verified-reference chain synchronization",
                    "assets/live/libertix-preferred-boot-path.py",
                    "SHARED_ESP")
            add("EFI/BOOT and firmware BootOrder/BootNext",
                "unobserved external maintainer hooks; no no-write guarantee",
                "external dpkg/firmware scripts not audited", "UNKNOWN_EXTERNAL_WRITER")
    else:
        add("owned Linux partition and associated Windows NTFS geometry",
            "verified uninstall recovery and shrink reversal",
            "Scripts/libertix-uefi-recovery-agent.ps1" if firmware == "uefi"
            else "Windows BIOS recovery (writer not statically attested here)",
            "PROTECTED_DISK")
        if firmware == "uefi":
            add("ESP/EFI/Libertix and EFI/LibertixInstaller",
                "transaction-scoped removal (historical shell paths also use rm -rf)",
                "assets/live/libertix-uefi-adapter.sh", "SHARED_ESP")
            add("NVRAM/Boot####, BootOrder, BootNext; BCD firmware entries",
                "cleanup and restoration using Windows recovery state",
                "Scripts/uefi/Libertix.Uefi.Firmware.ps1", "FIRMWARE_AND_BCD")
            if preferred_active:
                add("ESP/EFI/Microsoft/Boot/*",
                    "exceptional preferred path restore; hash/identity proof required",
                    "Scripts/modules/Libertix.PreferredBootPath.psm1",
                    "WINDOWS_BOOT_CRITICAL")
        else:
            add("selected disk MBR/PBR, Windows active flag and BCD",
                "BIOS rollback restoring saved boot state",
                "assets/live/libertix-bios-adapter.sh", "PROTECTED_DISK")
    return {
        "schema": "gaslux-mint-boot-update-remove-writeset-readonly-v1",
        "firmware": firmware, "operation": operation,
        "preferredPathActiveInput": preferred_active,
        "writeSet": entries,
        "sourceInspectionOnly": True,
        "installedPackagesHooksExhaustivelyAudited": False,
        "windowsBootAndRecoveryValidatedAfterAction": False,
        "hardwareDiskIdentityAuthenticated": False,
        "ownershipMarkerAloneGrantsAuthority": False,
        "executeWrites": False,
        **READONLY_FALSE,
    }


ESP_AUDIT_FILES = frozenset({
    "EFI/Libertix/.libertix-owner",
    "EFI/Libertix/shimx64.efi",
    "EFI/Libertix/grubx64.efi",
    "EFI/Libertix/mmx64.efi",
    "EFI/Libertix/preferred-boot-path.json",
    "EFI/Microsoft/Boot/bootmgfw.efi",
    "EFI/Microsoft/Boot/bootmgfw.libertix-windows.efi",
    "EFI/BOOT/BOOTX64.EFI",
})


def inspect_esp_file(esp: Path, relative: str) -> dict:
    """Read-only synthetic/authorized mount inventory: never follow a path link."""
    _require(type(relative) is str and relative in ESP_AUDIT_FILES,
             "unrecognized EFI target: refuse")
    _require(type(esp) is type(Path()) and esp.is_absolute(), "absolute ESP path required")
    _require(esp.name not in {"", ".", ".."} and not esp.is_symlink(),
             "unsafe ESP root")
    base = esp.lstat()
    _require(stat.S_ISDIR(base.st_mode) and base.st_uid == os.getuid(),
             "ESP root is not an owned directory")
    parts = PurePosixPath(relative).parts
    current = esp
    for component in parts[:-1]:
        current = current / component
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            return {"path": relative, "status": "ABSENT", "writeAuthorized": False}
        _require(stat.S_ISDIR(mode) and not stat.S_ISLNK(mode),
                 "EFI path contains a symlink or non-directory ancestor")
    try:
        data = _read_pinned_regular(current / parts[-1], esp, ESP_FILE_BYTE_LIMIT)
    except FileNotFoundError:
        return {"path": relative, "status": "ABSENT", "writeAuthorized": False}
    return {
        "path": relative, "status": "OBSERVED_READONLY",
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "sourceIdentityAndMountAuthenticated": False,
        "writeAuthorized": False,
    }


def audit_esp_snapshot(esp: Path, run_id: str) -> dict:
    """A marker is NOT proof of ownership or permission to replace/delete."""
    _require(type(run_id) is str and TRANSACTION.fullmatch(run_id) is not None,
             "invalid transaction identifier")
    files: dict[str, dict] = {}
    issues: list[str] = []
    for relative in sorted(ESP_AUDIT_FILES):
        try:
            files[relative] = inspect_esp_file(esp, relative)
        except (OSError, BootWriteSetError):
            files[relative] = {
                "path": relative, "status": "BLOCKED_PATH_IDENTITY",
                "writeAuthorized": False,
            }
            issues.append(relative)
    owner = esp / "EFI/Libertix/.libertix-owner"
    try:
        # No trust is inferred from this marker. It only supplies a mismatch.
        content = _read_pinned_regular(owner, esp, 4096)
        marker_match = content.splitlines()[0].decode("ascii") == run_id
    except (OSError, IndexError, UnicodeError, BootWriteSetError):
        marker_match = False
    if not marker_match:
        issues.append("missing_or_foreign_owner_marker")
    if files["EFI/Microsoft/Boot/bootmgfw.efi"]["status"] != "OBSERVED_READONLY":
        issues.append("windows_loader_absent_or_unsafe")
    return {
        "schema": "gaslux-mint-esp-readonly-inspection-v1",
        "status": "BLOCKED_EVIDENCE" if issues else "READONLY_INVENTORY_ONLY",
        "observations": files,
        "issues": issues,
        "markerMatchesRunId": marker_match,
        "markerAuthenticatesOwnership": False,
        "deviceAndPartitionGeometryAuthenticated": False,
        "actualEspMountVerified": False,
        "recoveryAndWindowsBootVerified": False,
        **READONLY_FALSE,
    }
