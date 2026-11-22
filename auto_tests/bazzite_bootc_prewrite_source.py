#!/usr/bin/env python3
"""Pinned bootc v1.17.1 *source* prewrite inspection; never a runtime writer gate.

The upstream Git objects are not an authenticated build-to-Bazzite-ELF mapping.
No caller assertion, successful source match or plan can authorize installation.
Reads bounded regular source files only; emits a refusal JSON on stdout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path

SOURCE_REPOSITORY = "bootc-dev/bootc"
SOURCE_COMMIT = "d01e723ae9480fa53aa9db09a7eff0439548e9f6"
SOURCE_TAG_OBJECT = "434e0e7e1b2631c65babd0eee4c456fd77fa9070"
RPM_VERSION = "bootc-0:1.17.1-1.fc45.x86_64"
# Git blob identities from the immutable upstream commit tree, not Cosign.
SOURCE_BLOBS = {
    "crates/lib/src/install.rs": "03eeb22172457165e778b51aee03210e4d1d64a1",
    "crates/lib/src/bootloader.rs": "08a208d2819ecbd6e8fa4a4c3b686bfc82e5b6c6",
    "crates/lib/src/install/baseline.rs": "d45688a5968ffa63bf2c3d5075921089abb6f971",
    "crates/lib/src/deploy.rs": "4ef2b471ab5459a1932751cde50b7eaffea80906",
    "crates/lib/src/bootc_composefs/update.rs": "c0dcafe3461c7076058b9acd05afa8b6b66d03cb",
    "docs/src/man/bootc-install-to-filesystem.8.md": "9549e156b2b8e3dc629ab9f948c230857996040a",
}
MAX_SOURCE_BYTES = 512 * 1024
NO_AUTHORITY = (
    "installationAuthorized",
    "partitionWriteAuthorized",
    "windowsEspWriteAuthorized",
    "gptMetadataWriteAuthorized",
    "nvramWriteAuthorized",
    "guestCommandChannelAuthorized",
    "nativeInstallationVerified",
    "sameDiskDualBootVerified",
    "rollbackProven",
    "stable",
)
GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")


class Refusal(ValueError):
    """Unknown, missing or unsafe source/plan."""


def git_blob_id(raw: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(raw)}\0".encode("ascii") + raw, usedforsecurity=False
    ).hexdigest()


def _read_source(path: Path, expected_git_blob: str) -> tuple[str, dict]:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= MAX_SOURCE_BYTES
        ):
            raise Refusal("FOREIGN_OR_UNBOUNDED_SOURCE_FILE")
        raw = bytearray()
        while len(raw) < before.st_size:
            chunk = os.read(fd, min(65536, before.st_size - len(raw)))
            if not chunk:
                raise Refusal("TRUNCATED_UPSTREAM_SOURCE")
            raw.extend(chunk)
        after = os.fstat(fd)

        def identity(st):
            return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

        if identity(before) != identity(after):
            raise Refusal("UPSTREAM_SOURCE_CHANGED_DURING_READ")
        raw = bytes(raw)
        if git_blob_id(raw) != expected_git_blob:
            raise Refusal("UPSTREAM_SOURCE_BLOB_MISMATCH")
        return raw.decode("utf-8"), {
            "gitBlob": expected_git_blob,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
    except UnicodeError as exc:
        raise Refusal("INVALID_UPSTREAM_SOURCE_ENCODING") from exc
    finally:
        os.close(fd)


def _require_fragments(text: str, fragments: tuple[str, ...], area: str) -> None:
    for item in fragments:
        if item not in text:
            raise Refusal(f"UNRESOLVED_UPSTREAM_CONTROL_FLOW_{area}")


def analyze_source(root: Path) -> dict:
    """Check exact upstream files and locate real dangerous edges; not ELF proof."""
    if root.is_symlink() or not root.is_dir():
        raise Refusal("INVALID_UPSTREAM_CHECKOUT")
    source = {}
    measurements = {}
    for path, pin in SOURCE_BLOBS.items():
        text, record = _read_source(root / path, pin)
        source[path] = text
        measurements[path] = record

    code = source["crates/lib/src/install.rs"]
    boot = source["crates/lib/src/bootloader.rs"]
    baseline = source["crates/lib/src/install/baseline.rs"]
    ostree_deploy = source["crates/lib/src/deploy.rs"]
    composefs_update = source["crates/lib/src/bootc_composefs/update.rs"]
    manual = source["docs/src/man/bootc-install-to-filesystem.8.md"]

    entry = code.split("pub(crate) async fn install_to_filesystem(", 1)
    if len(entry) != 2:
        raise Refusal("MISSING_TO_FILESYSTEM_ENTRY")
    entry = entry[1].split("pub(crate) async fn install_to_existing_root(", 1)[0]
    _require_fragments(
        entry,
        (
            "let state = prepare_install(",
            "Some(ReplaceMode::Wipe) =>",
            "remove_all_in_dir_no_xdev(&rootfs_fd, true)",
            "Some(ReplaceMode::Alongside) =>",
            "clean_boot_directories(&target_rootfs_fd, &target_root_path, is_already_ostree)",
            "None => require_empty_rootdir(&rootfs_fd)?",
            "install_to_filesystem_impl(&state, &mut rootfs, cleanup).await?",
        ),
        "ENTRY",
    )
    _require_fragments(
        code,
        (
            "std::fs::create_dir(ALONGSIDE_ROOT_MOUNT)?",
            "fn clean_boot_directories(",
            "crate::bootloader::mount_esp_part(&rootfs, &rootfs_path, is_ostree)?",
            "clean_esp_bootloader_dirs(&efidir)?",
            "fn clean_esp_bootloader_dirs(",
            'for name in ["EFI", "loader"]',
            "remove_dir_no_xdev(efidir, name, false)",
            'Task::new("Initializing ostree layout", "ostree")',
            '.args(["admin", "init-fs", "--modern", "."])',
            "install_container(state, rootfs, ostree, storage, has_ostree).await?",
            "crate::bootloader::install_via_bootupd(",
        ),
        "INSTALL",
    )
    _require_fragments(
        boot,
        (
            'let mut bootupd_args: Vec<&str> = vec!["backend", "install"]',
            '["--update-firmware", "--auto"]',
            "Some(device.require_single_root()?.path())",
            'Command::new("bootupctl")',
            "let mut bootctl_args = vec![",
            '"install",',
            '"--esp-path",',
            'bootctl_args.push("--no-variables")',
            'Command::new("bootctl")',
        ),
        "BOOTLOADER",
    )
    _require_fragments(
        baseline,
        ("fn mkfs<", "fn systemd_repart(", "fn wipefs("),
        "DISK_ONLY",
    )
    _require_fragments(
        manual,
        ("prepared and mounted by an external tool or script", "--replace"),
        "UPSTREAM_MANUAL",
    )
    _require_fragments(
        ostree_deploy,
        ("async fn deploy(", "ostree.stage_tree_with_options("),
        "OSTREE_UPDATE_DEPLOYMENT",
    )
    _require_fragments(
        composefs_update,
        (
            "pub(crate) async fn do_upgrade(",
            "write_composefs_state(",
            "composefs_gc(",
            "apply_upgrade(",
        ),
        "COMPOSEFS_UPDATE",
    )

    return {
        "decision": "PREWRITE_UNPROVEN",
        "sourceRepository": SOURCE_REPOSITORY,
        "sourceCommit": SOURCE_COMMIT,
        "sourceTagObject": SOURCE_TAG_OBJECT,
        "rpmVersionStringMatches": RPM_VERSION,
        "sourceFiles": measurements,
        "upstreamGitBlobIdentitiesMatched": True,
        "upstreamTagSignatureVerifiedByGaslux": False,
        "sourceToBazziteElfCryptographicBindingVerified": False,
        "bootcRuntimePathObserved": False,
        "updateSourceBranchesIdentified": [
            "ostree.staged_deployment",
            "composefs.staged_state_and_gc",
        ],
        "updateRuntimeAndBootSafetyVerified": False,
        "firstPotentialPersistentOperations": [
            {
                "path": "crates/lib/src/install.rs",
                "function": "install_to_filesystem",
                "condition": "targeting_host_root AND missing /target",
                "operation": "std::fs::create_dir(ALONGSIDE_ROOT_MOUNT)",
                "scope": "host filesystem, before prepare_install",
            },
            {
                "path": "crates/lib/src/install.rs",
                "function": "install_to_filesystem",
                "condition": "replace=wipe",
                "operation": "remove_all_in_dir_no_xdev(rootfs_fd, true)",
                "scope": "mounted target root",
            },
            {
                "path": "crates/lib/src/install.rs",
                "function": "clean_esp_bootloader_dirs",
                "condition": "replace=alongside AND EFI architecture AND ESP mounted",
                "operation": 'remove_dir_no_xdev(efidir, "EFI" / "loader", false)',
                "scope": "selected ESP; includes foreign Windows EFI if wrongly selected",
            },
            {
                "path": "crates/lib/src/install.rs",
                "function": "initialize_ostree_root",
                "condition": "new ostree root after empty-root validation",
                "operation": "ostree admin init-fs --modern .",
                "scope": "mounted target root; before OCI deployment/bootloader",
            },
        ],
        "unboundedEffectsNotReconciled": [
            "prepare_install mounts and temporary host namespace effects",
            "bootupd/bootctl EFI files and NVRAM effects",
            "target OCI deployment versus upstream Rust build identity",
            "Btrfs subvolume and OSTree updates/rollback",
            "OSTree stage_tree_with_options and composefs state writes/GC on update",
            "target ESP physical identity and owner",
        ],
        **{k: False for k in NO_AUTHORITY},
    }


def _guid(value: object) -> str:
    if type(value) is not str or not GUID.fullmatch(value):
        raise Refusal("INVALID_DISK_OR_PARTITION_GUID")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise Refusal("INVALID_DISK_OR_PARTITION_GUID") from exc
    if str(parsed) != value or parsed.int == 0:
        raise Refusal("INVALID_DISK_OR_PARTITION_GUID")
    return value


def assess_candidate(plan: dict) -> dict:
    """Deny every candidate; identify contradictions before any native writer."""
    expected = {
        "firmware",
        "partitionTable",
        "planComplete",
        "transactionId",
        "planTransactionId",
        "approvedDiskGuid",
        "selectedDiskGuid",
        "windowsEspPartuuid",
        "linuxEspPartuuid",
        "selectedEspPartuuid",
        "plannedBootloader",
        "requestedBootloader",
        "replaceMode",
    }
    if type(plan) is not dict or set(plan) != expected:
        raise Refusal("PARTIAL_OR_UNKNOWN_PLAN")
    if plan["firmware"] != "uefi" or plan["partitionTable"] != "gpt":
        raise Refusal("BIOS_MBR_UNSUPPORTED")
    if plan["planComplete"] is not True:
        raise Refusal("PARTIAL_PLAN")
    transaction = plan["transactionId"]
    if (
        type(transaction) is not str
        or not 1 <= len(transaction) <= 128
        or not re.fullmatch(r"[A-Za-z0-9_.:-]+", transaction)
        or transaction != plan["planTransactionId"]
    ):
        raise Refusal("FOREIGN_TRANSACTION")
    if _guid(plan["approvedDiskGuid"]) != _guid(plan["selectedDiskGuid"]):
        raise Refusal("FOREIGN_DESTINATION")
    win = _guid(plan["windowsEspPartuuid"])
    linux = _guid(plan["linuxEspPartuuid"])
    selected = _guid(plan["selectedEspPartuuid"])
    if win == linux or selected != linux or selected == win:
        raise Refusal("WINDOWS_ESP_OR_FOREIGN_ESP_SELECTED")
    if (
        plan["requestedBootloader"] not in {"grub", "systemd-boot"}
        or plan["requestedBootloader"] != plan["plannedBootloader"]
    ):
        raise Refusal("UNPLANNED_BOOTLOADER")
    if plan["replaceMode"] != "none":
        raise Refusal("DESTRUCTIVE_REPLACE_MODE_REFUSED")
    return {
        "decision": "PREWRITE_UNPROVEN",
        "reason": "SOURCE_AND_SELF_ASSERTED_PLAN_CANNOT_AUTHORIZE_BOOTC",
        "destinationIdentityAuthenticated": False,
        "espContentsAndBootloaderWriteSetVerified": False,
        **{k: False for k in NO_AUTHORITY},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = analyze_source(args.upstream_root)
    except (Refusal, OSError) as exc:
        report = {"decision": "REFUSED_UPSTREAM_SOURCE", "reason": str(exc)[:240]}
        report.update({k: False for k in NO_AUTHORITY})
        print(json.dumps(report, indent=2, sort_keys=True))
        return 3
    print(json.dumps(report, indent=2, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
