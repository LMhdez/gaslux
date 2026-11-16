#!/usr/bin/env python3
"""Read-only candidate installed-target audit; never a real boot or rollback proof."""

from __future__ import annotations

import hashlib
import re
import stat
from pathlib import Path

from gaslux_lab_media_probe import ProbeRefusal, read_os_release_evidence

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_FAT_UUID = re.compile(r"[0-9A-F]{4}-[0-9A-F]{4}\Z")
_RUN = re.compile(r"[A-Za-z0-9_-]{12,100}\Z")
_TARGETS = {
    "popos": ("ext4", "system76"),
    "q4os": ("ext4", "q4os-native"),
    "bazzite": ("btrfs", "fedora-atomic"),
}


def _safe(root: Path, relative: str, *, directory: bool = False) -> Path:
    if type(relative) is not str or not relative or relative.startswith("/"):
        raise ProbeRefusal("Invalid relative target path")
    parts = Path(relative).parts
    if ".." in parts or "." in parts:
        raise ProbeRefusal("Unsafe target path traversal")
    target = root
    for part in parts:
        target = target / part
        try:
            mode = target.lstat().st_mode
        except OSError as exc:
            raise ProbeRefusal("Required target path missing: " + relative) from exc
        if stat.S_ISLNK(mode):
            raise ProbeRefusal("Symlink in target evidence: " + relative)
    if directory:
        if not target.is_dir():
            raise ProbeRefusal("Target directory missing: " + relative)
    elif not target.is_file() or target.stat().st_size == 0:
        raise ProbeRefusal("Target regular file missing/empty: " + relative)
    return target


def _fstab_entries(raw: str) -> dict[str, tuple[str, str]]:
    if len(raw) > 32768:
        raise ProbeRefusal("Oversized fstab")
    entries = {}
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        cols = line.split()
        if len(cols) < 4 or cols[1] in entries:
            raise ProbeRefusal("Malformed/duplicate target mountpoint")
        entries[cols[1]] = cols[0], cols[2]
    return entries


def _check_specific(root: Path, distro: str, boot: str, root_uuid: str) -> dict:
    identity = read_os_release_evidence(str(_safe(root, "etc/os-release")))
    if distro == "popos":
        if identity["ID"] != "pop":
            raise ProbeRefusal("Not a native Pop!_OS target")
        # Package status is observational, not proof that an installer ran.
        pkg = _safe(root, "var/lib/dpkg/status").read_text(encoding="utf-8")
        required = ("pop-desktop", "linux-system76", "systemd-boot")
        for name in required:
            if not re.search(
                rf"(?m)^Package: {re.escape(name)}\n(?:[^\n]*\n)*?Status: install ok installed$",
                pkg,
            ):
                raise ProbeRefusal("Missing installed System76 package evidence: " + name)
        if boot == "systemd-boot":
            entry_dir = _safe(root, "boot/efi/loader/entries", directory=True)
            entries = [x for x in entry_dir.glob("*.conf") if x.is_file() and not x.is_symlink()]
            if not entries:
                raise ProbeRefusal("No Pop!_OS systemd-boot entry")
            if not any("Pop_OS" in x.read_text(encoding="utf-8") for x in entries):
                raise ProbeRefusal("System76 boot entry does not refer to Pop_OS")
        else:
            grub = _safe(root, "boot/grub/grub.cfg").read_text(encoding="utf-8")
            if "linux" not in grub or "Pop" not in grub:
                raise ProbeRefusal("Missing Pop!_OS BIOS GRUB entry")
        return {"osReleaseId": "pop", "packageEvidence": list(required)}
    if distro == "q4os":
        if identity["ID"] != "debian" or identity.get("VERSION_ID") != "13":
            raise ProbeRefusal("Not a verified Q4OS Debian 13 base")
        q4os = _safe(root, "etc/q4os_version").read_text(encoding="utf-8").strip()
        if re.fullmatch(r"6\.[0-9]+(?:-deb13u[0-9]+)?", q4os) is None:
            raise ProbeRefusal("Q4OS release marker invalid")
        grub = _safe(root, "boot/grub/grub.cfg").read_text(encoding="utf-8")
        if not all(word in grub for word in ("Q4OS", "linux")):
            raise ProbeRefusal("Missing Q4OS GRUB entry")
        return {"osReleaseId": "debian", "q4osVersion": q4os}
    if distro == "bazzite":
        if identity["ID"] not in {"fedora", "bazzite"} or "Bazzite" not in identity.get(
            "PRETTY_NAME", ""
        ):
            raise ProbeRefusal("Installed Fedora root is not uniquely Bazzite")
        # Real deployments require signed image provenance and bootc/OSTree proof.
        _safe(root, "ostree/deploy", directory=True)
        entries_dir = _safe(root, "boot/loader/entries", directory=True)
        entries = [x for x in entries_dir.glob("*.conf") if x.is_file() and not x.is_symlink()]
        if not entries or not any("ostree" in x.read_text(encoding="utf-8") for x in entries):
            raise ProbeRefusal("Missing Bazzite Atomic boot entry")
        return {"osReleaseId": identity["ID"], "atomicDeploymentEvidencePresent": True}
    raise ProbeRefusal("Unknown distribution target")


def audit_candidate_target(
    *,
    root: Path,
    distribution_id: str,
    backend: str,
    run_id: str,
    expected_root_uuid: str,
    firmware_layout: str,
    esp_uuid: str,
    windows_loader_sha256: str | None = None,
) -> dict:
    """Inspect a fixture or already-mounted target without writing to it.

    Neither root-mount identity nor EFI NVRAM can be attested from a directory.
    Return values are explicitly non-authoritative.
    """
    if (not isinstance(root, Path) or not root.is_absolute()
            or root.is_symlink() or not root.is_dir()):
        raise ProbeRefusal("Unsafe target directory")
    if (type(run_id) is not str or _RUN.fullmatch(run_id) is None
            or type(expected_root_uuid) is not str
            or _UUID.fullmatch(expected_root_uuid) is None):
        raise ProbeRefusal("Invalid transaction or root filesystem identity")
    expected = _TARGETS.get(distribution_id)
    if expected is None or backend != expected[1]:
        raise ProbeRefusal("Candidate backend mismatch")
    if firmware_layout not in {"uefi/gpt", "bios/mbr"}:
        raise ProbeRefusal("Unsupported firmware layout")
    if distribution_id == "bazzite" and firmware_layout != "uefi/gpt":
        raise ProbeRefusal("Bazzite target requires UEFI/GPT")
    marker = _safe(root, ".gaslux-stage-owner").read_text(encoding="utf-8").strip()
    if marker != run_id:
        raise ProbeRefusal("Foreign/incorrect target ownership marker")
    mounts = _fstab_entries(_safe(root, "etc/fstab").read_text(encoding="utf-8"))
    if mounts.get("/") != ("UUID=" + expected_root_uuid, expected[0]):
        raise ProbeRefusal("Root UUID or filesystem mismatch")
    if firmware_layout == "uefi/gpt":
        if type(esp_uuid) is not str or _FAT_UUID.fullmatch(esp_uuid) is None:
            raise ProbeRefusal("Missing ESP UUID")
        matches = [mount for mount in ("/boot", "/boot/efi")
                   if mounts.get(mount) == ("UUID=" + esp_uuid, "vfat")]
        if len(matches) != 1:
            raise ProbeRefusal("Missing/ambiguous ESP mount")
        if (type(windows_loader_sha256) is not str
                or _SHA256.fullmatch(windows_loader_sha256) is None):
            raise ProbeRefusal("Missing independently measured Windows Boot Manager hash")
        loader = _safe(root, matches[0].lstrip("/") + "/EFI/Microsoft/Boot/bootmgfw.efi")
        if hashlib.sha256(loader.read_bytes()).hexdigest() != windows_loader_sha256:
            raise ProbeRefusal("Windows Boot Manager binary was changed")
        boot = "systemd-boot" if distribution_id == "popos" else "grub"
        if distribution_id == "bazzite" and matches[0] != "/boot/efi":
            raise ProbeRefusal("Atomic ESP mount not at expected path")
    else:
        if esp_uuid != "none" or windows_loader_sha256 is not None:
            raise ProbeRefusal("BIOS path cannot claim EFI loader evidence")
        boot = "grub"
    details = _check_specific(root, distribution_id, boot, expected_root_uuid)
    return {
        "distribution": distribution_id,
        "backend": backend,
        "runId": run_id,
        "rootFilesystemEvidenceVerified": True,
        "ownershipMarkerVerified": True,
        "bootFilesObserved": True,
        "windowsLoaderFileHashMatches": firmware_layout == "uefi/gpt",
        "rootBlockDeviceVerified": False,
        "espBlockDeviceVerified": False,
        "firmwareNVRAMVerified": False,
        "linuxBootVerified": False,
        "windowsBootVerified": False,
        "recoveryVerified": False,
        "installationAuthorized": False,
        "diskWrites": 0,
        **details,
    }
