"""CachyOS GRUB UEFI effects lab PREPARATION ONLY — no writer.

Consumes bounded, *untrusted* before/after synthetic inventories and offers
an exact-file ownership cleanup preview. Never runs GRUB/QEMU, opens a block
device, changes EFI/NVRAM or grants any operation. This is NOT an attestor of
a historical Windows, GRUB execution, QCOW2 source or complete sector trace.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any

import cachyos_uefi_writeset_readonly as writeset

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TX = re.compile(r"[a-z0-9-]{12,80}\Z")
FILE = re.compile(r"/(?:[A-Za-z0-9_.+-]+/)*[A-Za-z0-9_.+-]+\Z")
NAMES = re.compile(r"[A-Za-z0-9_.-]{1,80}\Z")
SNAP_KEYS = frozenset((
    "sampleId", "transactionId", "diskGuid", "espPartuuid",
    "diskBytes", "sectorBytes", "espOffsetBytes", "espLengthBytes",
    "gptPrimarySha256", "gptBackupSha256", "pmbrSha256",
    "ovmfVarsSha256", "bootOrder", "bootNext", "files", "sectorSamples",
))
FILE_KEYS = frozenset(("sizeBytes", "sha256"))
CLEAN_KEYS = frozenset(("sizeBytes", "sha256"))
ESP_PREFIX = "/boot/efi/"
EFI_OWNED = "/boot/efi/EFI/Gaslux-CachyOS/"
LINUX_ROOT_EXACT = frozenset((
    "/etc/fstab", "/etc/grub.d/45_gaslux_windows",
    "/etc/default/grub.d/99-gaslux.cfg",
    "/boot/vmlinuz-linux-cachyos",
    "/boot/initramfs-linux-cachyos.img",
    "/boot/grub/grub.cfg",
    "/boot/grub/grub.cfg.gaslux-candidate",
))
PROTECTED_EFI = (
    "/efi/microsoft/", "/efi/boot/", "/efi/oem/",
    "/efi/recovery/", "/efi/libertix/",
)


class EffectsRefused(ValueError):
    """Malformed or foreign evidence is denied before comparisons."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise EffectsRefused(reason)


def sha(value: object) -> bool:
    return type(value) is str and HEX64.fullmatch(value) is not None


def _file_map(value: object) -> dict:
    require(type(value) is dict and len(value) <= 256, "INVALID_FILE_INVENTORY")
    for path, info in value.items():
        require(type(path) is str and FILE.fullmatch(path) is not None
                and "//" not in path
                and not any(component in {".", ".."} for component in path.split("/"))
                and type(info) is dict and set(info) == FILE_KEYS
                and type(info["sizeBytes"]) is int
                and 0 <= info["sizeBytes"] <= 16 * 1024 * 1024
                and sha(info["sha256"]), "INVALID_FILE_INVENTORY")
    return value


def _sample_map(value: object, disk: int) -> dict[str, str]:
    require(type(value) is dict and len(value) <= 1024, "INVALID_SECTOR_SAMPLES")
    for sector, digest in value.items():
        require(type(sector) is str and sector.isascii()
                and sector.isdecimal() and str(int(sector)) == sector
                and int(sector) < disk // 512 and sha(digest),
                "INVALID_SECTOR_SAMPLES")
    return value


def _snapshot(value: object) -> dict:
    require(type(value) is dict and set(value) == SNAP_KEYS,
            "SNAPSHOT_SCHEMA_INVALID")
    for key in ("sampleId", "transactionId"):
        require(type(value[key]) is str and TX.fullmatch(value[key]) is not None,
                "SAMPLE_OR_TRANSACTION_INVALID")
    for key in ("diskGuid", "espPartuuid"):
        writeset._uuid(value[key])  # reuse strict canonical validation
    for key in ("diskBytes", "sectorBytes", "espOffsetBytes",
                "espLengthBytes"):
        require(type(value[key]) is int and value[key] > 0,
                "SNAPSHOT_GEOMETRY_INVALID")
    require(value["sectorBytes"] == 512
            and value["diskBytes"] % 512 == 0
            and value["espOffsetBytes"] % 512 == 0
            and value["espLengthBytes"] % 512 == 0
            and value["espOffsetBytes"] >= 34 * 512
            and value["espOffsetBytes"] + value["espLengthBytes"]
                <= value["diskBytes"] - 33 * 512,
            "SNAPSHOT_GEOMETRY_INVALID")
    for key in ("gptPrimarySha256", "gptBackupSha256", "pmbrSha256",
                "ovmfVarsSha256"):
        require(sha(value[key]), "SNAPSHOT_DIGEST_INVALID")
    require(type(value["bootOrder"]) is list
            and len(value["bootOrder"]) <= 128
            and all(type(s) is str and
                    re.fullmatch(r"[0-9A-F]{4}", s) is not None
                    for s in value["bootOrder"])
            and len(set(value["bootOrder"])) == len(value["bootOrder"])
            and (value["bootNext"] is None or
                 (type(value["bootNext"]) is str
                  and re.fullmatch(r"[0-9A-F]{4}",
                                   value["bootNext"]) is not None)),
            "FIRMWARE_INVENTORY_INVALID")
    _file_map(value["files"])
    _sample_map(value["sectorSamples"], value["diskBytes"])
    return value


def grub_source_readiness(repo: Path) -> dict[str, Any]:
    """Read exact audited source, report missing signed GRUB artifact identity."""
    pins = writeset._pinned_sources(repo)  # no GRUB invocation
    stage = (repo / "assets/live/cachyos-stage-target.sh").read_text(
        encoding="utf-8")
    require("pacman sudo networkmanager grub efibootmgr os-prober" in stage
            and "pacstrap -K" in stage
            and "--no-nvram" in (repo / "assets/live/cachyos-uefi-lab.py").
            read_text(encoding="utf-8"), "REVISED_GRUB_INSTALL_SOURCE")
    return {
        "status": "GRUB_VERSION_AND_SIGNED_BINARIES_UNPINNED",
        "sourceGitBlobs": pins,
        "packageDependency": "grub (unversioned pacstrap package)",
        "grubPackageVersion": None,
        "grubPackageSha256": None,
        "grubExecutableSha256": None,
        "grubModulesSha256": None,
        "archPackageSignatureVerified": False,
        "ovmfCodeIdentityVerified": False,
        "ovmfVarsCheckpointVerified": False,
        "qcow2SnapshotRestorableVerified": False,
        "physicalEspFdAuthenticated": False,
        "safetyApprovedToExecute": False,
        "canRunGrubInstall": False,
        "authorization": False,
    }


def compare_synthetic_snapshots(before: dict, after: dict) -> dict[str, Any]:
    """Compare *self-asserted, sampled* facts; never infer real GRUB effects."""
    a, b = _snapshot(before), _snapshot(after)
    keys = ("sampleId", "transactionId", "diskGuid", "espPartuuid",
            "diskBytes", "sectorBytes", "espOffsetBytes", "espLengthBytes")
    require(all(a[k] == b[k] for k in keys),
            "FOREIGN_CHECKPOINT_OR_DISK_ESP_IDENTITY")
    require(set(a["sectorSamples"]) == set(b["sectorSamples"]),
            "SECTOR_SAMPLE_COVERAGE_CHANGED")
    paths = set(a["files"]) | set(b["files"])
    changes = []
    violations = []
    for path in sorted(paths):
        old = a["files"].get(path)
        new = b["files"].get(path)
        if old == new:
            continue
        if path.startswith(EFI_OWNED):
            boundary = "GASLUX_ESP_DECLARED_NOT_AUTHENTICATED"
        elif path.lower().startswith(EFI_OWNED.lower()):
            boundary = "EFI_CASEFOLD_COLLISION"
            violations.append("EFI_CASEFOLD_COLLISION:" + path)
        elif path.startswith(ESP_PREFIX):
            boundary = "FOREIGN_OR_PROTECTED_ESP_WRITE"
            violations.append("FOREIGN_OR_PROTECTED_ESP_WRITE:" + path)
        elif path in LINUX_ROOT_EXACT or path.startswith("/boot/grub/"):
            boundary = "LINUX_ROOT_DECLARED_NOT_AUTHENTICATED"
        else:
            boundary = "UNEXPECTED_ROOT_WRITE"
            violations.append("UNEXPECTED_ROOT_WRITE:" + path)
        # Reject any protected Microsoft/BOOT/OEM/Recovery change,
        # including case variants. 'EFI/Gaslux-CachyOS' never receives
        # write permission through this classification.
        lower = path.lower()
        if lower.startswith(ESP_PREFIX.lower()) and any(
            lower[len(ESP_PREFIX):].startswith(prefix.lstrip("/"))
            for prefix in PROTECTED_EFI
        ):
            if "PROTECTED_EFI_WRITE:" + path not in violations:
                violations.append("PROTECTED_EFI_WRITE:" + path)
        changes.append({
            "path": path,
            "kind": "CREATE" if old is None else
                    ("DELETE" if new is None else "MODIFY"),
            "boundary": boundary, "authorization": False,
        })
    changed_lbas = []
    first = a["espOffsetBytes"] // 512
    end = (a["espOffsetBytes"] + a["espLengthBytes"]) // 512
    for sec in sorted(a["sectorSamples"], key=int):
        if a["sectorSamples"][sec] != b["sectorSamples"][sec]:
            lba = int(sec)
            changed_lbas.append(lba)
            if not first <= lba < end:
                violations.append("WRITE_OUTSIDE_DECLARED_ESP:" + sec)
    for key in ("gptPrimarySha256", "gptBackupSha256", "pmbrSha256"):
        if a[key] != b[key]:
            violations.append("GPT_OR_PMBR_CHANGED:" + key)
    if a["bootOrder"] != b["bootOrder"]:
        violations.append("BOOTORDER_CHANGED")
    if a["bootNext"] != b["bootNext"]:
        violations.append("BOOTNEXT_CHANGED")
    if a["ovmfVarsSha256"] != b["ovmfVarsSha256"]:
        violations.append("OVMF_VARS_CHANGED")
    return {
        "status": "SYNTHETIC_SAMPLED_EFFECTS_DENY_ONLY",
        "sampleId": a["sampleId"],
        "transactionId": a["transactionId"],
        "changedFiles": changes,
        "sampledChangedLbas": changed_lbas,
        "violations": sorted(set(violations)),
        "syntheticSampledNoViolation": len(violations) == 0,
        "sectorCoverageComplete": False,
        "qemuBlkNodeToDiskAuthenticated": False,
        "actualGrubInstallExecuted": False,
        "grubVersionVerified": False,
        "grubEffectiveWriteSetProven": False,
        "nvramPreservationIndependentlyProven": False,
        "windowsProtectedFilesPreservedIndependently": False,
        "physicalOwnershipVerified": False,
        "authorization": False,
        "approvedMutation": False,
        "productionStorageWritesAuthorized": False,
        "releaseEligible": False,
        "stable": False,
    }


def preview_efi_cleanup_owned_files(
    directory: Path, transaction_id: str, expected: dict[str, dict],
) -> dict[str, Any]:
    """Read-only, no-follow exact-child inventory. Never removes anything."""
    require(type(directory) is type(Path()) and directory.is_absolute()
            and directory.name == "Gaslux-CachyOS"
            and directory.parent.name == "EFI"
            and directory.resolve() == directory,
            "NOT_THE_DECLARED_GASLUX_ESP_DIRECTORY")
    require(type(transaction_id) is str
            and TX.fullmatch(transaction_id) is not None,
            "TRANSACTION_INVALID")
    require(type(expected) is dict
            and 1 <= len(expected) <= 32
            and ".gaslux-owner" in expected
            and all(type(k) is str and NAMES.fullmatch(k) is not None
                    and k not in {".", ".."}
                    and type(v) is dict and set(v) == CLEAN_KEYS
                    and type(v["sizeBytes"]) is int
                    and 0 <= v["sizeBytes"] <= 16 * 1024 * 1024
                    and sha(v["sha256"])
                    for k, v in expected.items()),
            "OWNERSHIP_MANIFEST_INVALID")
    try:
        dir_st = directory.lstat()
        require(stat.S_ISDIR(dir_st.st_mode)
                and dir_st.st_uid == os.getuid(),
                "EFI_DIRECTORY_NOT_OWNED")
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise EffectsRefused("EFI_DIRECTORY_NOT_ACCESSIBLE") from exc
    try:
        opened_st = os.fstat(dir_fd)
        require((dir_st.st_dev, dir_st.st_ino) ==
                (opened_st.st_dev, opened_st.st_ino),
                "EFI_DIRECTORY_RACED")
        names = os.listdir(dir_fd)
        require(len(names) == len(set(names)) and set(names) == set(expected),
                "FOREIGN_CHILD_OR_MISSING_OWNED_FILE")
        entries: dict[str, dict] = {}
        for name in sorted(names):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=dir_fd)
            try:
                old = os.fstat(fd)
                require(stat.S_ISREG(old.st_mode) and old.st_nlink == 1
                        and old.st_uid == os.getuid()
                        and old.st_size == expected[name]["sizeBytes"],
                        "FOREIGN_CHILD_TYPE_OWNER_OR_LENGTH")
                digest = hashlib.sha256()
                remaining = old.st_size
                owner_text = bytearray() if name == ".gaslux-owner" else None
                while remaining:
                    data = os.read(fd, min(remaining, 65536))
                    require(bool(data), "OWNED_FILE_SHORT_READ")
                    digest.update(data)
                    if owner_text is not None:
                        require(len(owner_text) + len(data) <= 128,
                                "INVALID_OWNER_MARKER")
                        owner_text.extend(data)
                    remaining -= len(data)
                current = os.fstat(fd)
                require((old.st_dev, old.st_ino, old.st_size,
                         old.st_mtime_ns, old.st_ctime_ns) ==
                        (current.st_dev, current.st_ino, current.st_size,
                         current.st_mtime_ns, current.st_ctime_ns),
                        "OWNED_FILE_RACED")
                require(digest.hexdigest() == expected[name]["sha256"],
                        "OWNED_FILE_CONTENT_DIVERGED")
                if owner_text is not None:
                    require(bytes(owner_text) == (transaction_id + "\n").encode(),
                            "FOREIGN_TRANSACTION_MARKER")
                entries[name] = {
                    "sizeBytes": old.st_size, "sha256": digest.hexdigest(),
                    "ownershipProof": "LOCAL_STAGED_METADATA_ONLY",
                    "authorization": False,
                }
            finally:
                os.close(fd)
        end = os.fstat(dir_fd)
        require((dir_st.st_dev, dir_st.st_ino, dir_st.st_mtime_ns) ==
                (end.st_dev, end.st_ino, end.st_mtime_ns)
                and set(os.listdir(dir_fd)) == set(expected),
                "EFI_DIRECTORY_CHANGED_DURING_INVENTORY")
    except OSError as exc:
        raise EffectsRefused("EFI_CHILD_READ_REFUSED") from exc
    finally:
        os.close(dir_fd)
    return {
        "status": "OWNED_FILE_INVENTORY_MATCHES_DENY_ONLY",
        "entries": entries,
        "allExpectedChildrenEnumerated": True,
        "historicalTransactionOwnershipAuthenticated": False,
        "physicalEspAuthenticated": False,
        "canDelete": False,
        "deleteActionPresent": False,
        "authorization": False,
    }
