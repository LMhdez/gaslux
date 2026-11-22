#!/usr/bin/env python3
"""Forensic Windows-only A versus direct-kernel Mint then Windows B.

Only after the independent checkpoint passes genuine-QCOW2 restore tests.
Do not interpret differences as repair permission or an installer success.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import time
import uuid
from pathlib import Path

from windows_cachyos_overlay_reboot import (
    audit_complete_third_serial,
    gpt_windows,
    third_guest_args,
)
from windows_cachyos_qcow2_gpt_readonly import VIRTUAL_BYTES
from windows_mint_ab_checkpoint import (
    AB_DIR,
    ARMS,
    CONSENT,
    REFERENCE,
    VARS,
    equivalent,
    file_guard,
    image_info,
    prepare_checkpoint,
    sha256_file,
)
from windows_mint_overlay_root import _guest_disk_audit, has_orderly_shutdown_witness

ROOT_MARKER = b"GASLUXMINT login:"
WIN_EXPECT = (
    "windowsEspDigestChanged",
    "windowsMsrDigestChanged",
    "windowsOsNtfsDigestChanged",
    "windowsRecoveryDigestChanged",
)


class ForensicError(RuntimeError):
    pass


def require(ok: bool, reason: str):
    if not ok:
        raise ForensicError(reason)


def checked_file(path: Path, parent: Path):
    require(
        path.parent == parent
        and path.is_file()
        and not path.is_symlink()
        and path.stat().st_nlink == 1,
        "untrusted A/B evidence path",
    )


def guest_ro_inventory(disk: Path, root_uuid: str) -> dict:
    """Collect full Windows partition checksums plus fifth-root files read-only."""
    import guestfs

    guest = guestfs.GuestFS(python_return_dict=True)
    try:
        guest.add_drive_opts(str(disk), format="qcow2", readonly=1)
        guest.launch()
        devices = guest.list_devices()
        require(
            len(devices) == 1 and guest.blockdev_getsize64(devices[0]) == VIRTUAL_BYTES,
            "A/B guest disk identity changed",
        )
        d = devices[0]
        suffix = "p" if d[-1].isdigit() else ""
        parts = [d + suffix + str(n) for n in range(1, 6)]
        require(
            guest.list_partitions() == parts
            and guest.vfs_type(parts[4]) == "ext4"
            and guest.vfs_uuid(parts[4]) == root_uuid,
            "A/B root UUID or GPT partition count changed",
        )
        hashes = [guest.checksum_device("sha256", p) for p in parts[:4]]
        root_files = {}
        guest.mount_ro(parts[4], "/")
        for path in ("/etc/os-release", "/etc/fstab"):
            require(guest.is_file(path), "Mint root metadata missing: " + path)
            root_files[path] = guest.checksum("sha256", path)
        # The kernel and initramfs are identified by their exact tree contents.
        boots = sorted(
            [
                name
                for name in guest.ls("/boot")
                if re.fullmatch(r"vmlinuz-[A-Za-z0-9.+_-]{1,128}", name)
            ]
        )
        require(len(boots) == 1, "Mint boot kernel identity ambiguous")
        version = boots[0].removeprefix("vmlinuz-")
        for path in ("/boot/" + boots[0], "/boot/initrd.img-" + version):
            require(guest.is_file(path), "missing installed Mint boot artifact")
            root_files[path] = guest.checksum("sha256", path)
        guest.umount_all()

        inventories = {}
        for index, name in ((0, "esp"), (3, "recovery")):
            volume = parts[index]
            try:
                guest.mount_ro(volume, "/")
                names = sorted(guest.find("/"))
                require(len(names) <= 120000, "A/B forensic file inventory exceeded safety bound")
                contents = {}
                seen = set()
                for path in names:
                    absolute = "/" + path.lstrip("/")
                    require(
                        canonical_inventory_path(absolute),
                        "unsafe guestfs inventory path",
                    )
                    require(
                        absolute not in seen,
                        "duplicate guestfs inventory entry",
                    )
                    seen.add(absolute)
                    if guest.is_file(absolute):
                        contents[absolute] = guest.checksum("sha256", absolute)
                require(bool(contents), "read-only ESP/Recovery file enumeration was empty")
                inventories[name] = {"available": True, "fileSha256": contents}
                guest.umount_all()
            except Exception as exc:
                guest.umount_all()
                inventories[name] = {"available": False, "reason": type(exc).__name__}
        return {
            "partitionSha256": hashes,
            "rootUuid": root_uuid,
            "mintRootFiles": root_files,
            "fileInventories": inventories,
        }
    finally:
        try:
            guest.shutdown()
        finally:
            guest.close()


def gpt_manifest(image: Path, scratch: Path) -> dict:
    from tempfile import TemporaryDirectory

    with TemporaryDirectory(prefix="mint-ab-gpt-", dir=scratch) as temp:
        front, back = gpt_windows(image, Path(temp))
    primary = front[512:1024]
    entries = front[1024 : 1024 + 128 * 128]
    require(primary[:8] == b"EFI PART", "missing A/B GPT primary header")
    raw_guids = []
    for i in range(5):
        rec = entries[i * 128 : (i + 1) * 128]
        require(any(rec[:16]) and any(rec[16:32]), "missing GUID for A/B partition " + str(i + 1))
        raw_guids.append(str(uuid.UUID(bytes_le=rec[16:32])))
    return {
        "diskGuid": str(uuid.UUID(bytes_le=primary[56:72])),
        "partitionGuids": raw_guids,
        "rawPrimaryGptWindowSha256": hashlib.sha256(front).hexdigest(),
        "rawBackupGptWindowSha256": hashlib.sha256(back).hexdigest(),
        "partitionRanges": [
            dict(
                index=i + 1,
                firstLba=struct.unpack_from("<Q", entries, i * 128 + 32)[0],
                lastLba=struct.unpack_from("<Q", entries, i * 128 + 40)[0],
            )
            for i in range(5)
        ],
        "sectorBytes": 512,
    }


def verify_ab_source(workspace: Path, proof: dict, base: Path) -> None:
    require(
        proof.get("checkpointReadyForReview") is True
        and proof.get("controlRecoveredAfterFaultInjection") is True
        and proof.get("sharedBackingChains") is False
        and proof.get("armsBooted") is False
        and proof.get("releaseEligible") is False,
        "A/B checkpoint recovery and independent arms not proven",
    )
    directory = workspace / AB_DIR
    ref = directory / REFERENCE
    file_guard(ref, directory, 0o400)
    require(
        sha256_file(ref) == proof.get("referenceSha256"),
        "immutable reference checkpoint differs before QEMU",
    )
    for arm, digest in zip(ARMS, (proof["controlSha256"], proof["treatmentSha256"]), strict=True):
        p = directory / arm
        file_guard(p, directory, 0o600)
        image_info(p)
        require(sha256_file(p) == digest, "A/B arm changed BEFORE guest start")
        equivalent(ref, p)
    for vars_name in VARS:
        p = directory / vars_name
        file_guard(p, directory, 0o600)
        require(sha256_file(p) == proof["initialOvmfVarsSha256"], "initial A/B OVMF state mismatch")
    require(
        sha256_file(base) == proof["windowsBackingSha256"],
        "Windows backing changed before forensic boots",
    )


def run_windows_arm(
    original: list[str], base: Path, nvram: Path, arm: Path, vars_path: Path, serial: Path
) -> dict:
    require(
        serial.parent == base.parent and not serial.exists() and not serial.is_symlink(),
        "reused Windows A/B serial",
    )
    qemu = third_guest_args(original, base, nvram, arm, vars_path, serial)
    started = time.monotonic()
    with (serial.parent / (serial.stem + "-qemu-stderr.log")).open("xb") as err:
        proc = subprocess.Popen(qemu, stdout=subprocess.DEVNULL, stderr=err)
        try:
            proc.wait(timeout=1200)
            require(proc.returncode == 0, "A/B Windows QEMU did not shut down cleanly")
        except subprocess.TimeoutExpired as exc:
            raise ForensicError("A/B Windows boot timeout") from exc
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)
    serial_sha = audit_complete_third_serial(serial)
    return {
        "bootWitnessSha256": serial_sha,
        "bootAttemptId": str(uuid.uuid4()),
        "elapsedMonotonicSeconds": round(time.monotonic() - started, 2),
        "realWindows10GuestMarkersVerified": True,
    }


def run_mint_arm(arm: Path, kernel: Path, initramfs: Path, root_uuid: str, serial: Path) -> dict:
    require(not serial.exists() and not serial.is_symlink(), "reused Mint A/B serial")
    args = [
        "qemu-system-x86_64",
        "-machine",
        "q35,accel=kvm",
        "-cpu",
        "host",
        "-smp",
        "2",
        "-m",
        "4096",
        "-display",
        "none",
        "-net",
        "none",
        "-no-reboot",
        "-drive",
        f"if=none,id=windows-cow,format=qcow2,file={arm}",
        "-device",
        "virtio-blk-pci,drive=windows-cow,bootindex=1",
        "-kernel",
        str(kernel),
        "-initrd",
        str(initramfs),
        "-append",
        f"root=UUID={root_uuid} rw rootwait console=ttyS0,115200n8 "
        "systemd.unit=multi-user.target "
        "systemd.wants=serial-getty@ttyS0.service",
        "-serial",
        f"file:{serial}",
        "-boot",
        "order=c,menu=off",
    ]
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        proc.wait(timeout=550)
        require(proc.returncode == 0, "Mint B failed to power off")
        raw = serial.read_bytes()
        require(
            ROOT_MARKER in raw and b"Linux version" in raw and has_orderly_shutdown_witness(raw),
            "Mint B missing real login/kernel/shutdown serial witness",
        )
        return {
            "bootAttemptId": str(uuid.uuid4()),
            "mintSerialSha256": hashlib.sha256(raw).hexdigest(),
            "mintDirectKernelBootVerified": True,
            "mintOrderlyShutdownVerified": True,
        }
    except subprocess.TimeoutExpired as exc:
        raise ForensicError("Mint treatment guest shutdown timeout") from exc
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=30)


def archive_serial(source: Path, evidence: Path, max_bytes: int = 512_000) -> str:
    checked_file(source, source.parent)
    require(source.stat().st_size <= max_bytes, "oversized A/B COM1 evidence")
    target = evidence / source.name
    require(not target.exists() and not target.is_symlink(), "reused A/B COM1 archive")
    with source.open("rb") as inp, target.open("xb") as out:
        shutil.copyfileobj(inp, out, 64 * 1024)
        out.flush()
        os.fsync(out.fileno())
    require(
        sha256_file(source) == sha256_file(target), "A/B COM1 evidence changed during archiving"
    )
    return sha256_file(target)


def changed_files(before: dict, after: dict) -> dict:
    answer = {}
    for name in ("esp", "recovery"):
        b, a = before["fileInventories"][name], after["fileInventories"][name]
        if not b["available"] or not a["available"]:
            answer[name] = {"available": False, "reason": "missing read-only filesystem inventory"}
            continue
        x, y = b["fileSha256"], a["fileSha256"]
        names = sorted(set(x) | set(y))
        answer[name] = {
            "available": True,
            "changed": [n for n in names if x.get(n) != y.get(n)],
            "beforeSha256": {n: x.get(n) for n in names if x.get(n) != y.get(n)},
            "afterSha256": {n: y.get(n) for n in names if x.get(n) != y.get(n)},
        }
    return answer


def write_manifest(directory: Path, name: str, data: dict) -> str:
    require(
        directory.is_dir() and not directory.is_symlink() and not (directory / name).exists(),
        "unsafe A/B evidence location",
    )
    p = directory / name
    with p.open("xb") as f:
        f.write((json.dumps(data, indent=2, sort_keys=True) + "\n").encode())
        f.flush()
        os.fsync(f.fileno())
    return sha256_file(p)


def canonical_inventory_path(path: object) -> bool:
    """Reject aliases and traversal without excluding legitimate Unicode names."""
    return (
        isinstance(path, str)
        and 1 < len(path) <= 4096
        and path.startswith("/")
        and not path.startswith("//")
        and not path.endswith("/")
        and "\0" not in path
        and "\\" not in path
        and all(component not in ("", ".", "..") for component in path[1:].split("/"))
    )


# Each forensic stage must have usable per-file ESP and Recovery inventories
# in addition to the four complete raw-partition SHA-256 values. An unavailable
# filesystem inventory is NEVER evidence that contents are unchanged.
F03_EVIDENCE_PHASES = {
    "before_windows_a": (
        "mint-ab-evidence-before-windows-a.json",
        ("arm_a_preboot", "arm_b_preboot"),
    ),
    "after_windows_a": (
        "mint-ab-evidence-after-windows-a.json",
        ("arm_a_after_windows",),
    ),
    "after_mint_b": (
        "mint-ab-evidence-after-mint-b.json",
        ("arm_b_after_mint",),
    ),
    "after_windows_b": (
        "mint-ab-evidence-after-windows-b.json",
        ("arm_b_after_windows",),
    ),
}


F03_PREDECESSOR_FILES = {
    "before_windows_a": {
        "checkpoint": "mint-ab-checkpoint.json",
        "earlyCapacity": "mint-ab-capacity-early.json",
    },
    "after_windows_a": {
        "baselineEvidence": "mint-ab-evidence-before-windows-a.json",
        "afterControlIntegrity": "mint-ab-after-control-gate.json",
    },
    "after_mint_b": {
        "baselineEvidence": "mint-ab-evidence-before-windows-a.json",
        "afterControlEvidence": "mint-ab-evidence-after-windows-a.json",
        "control": "mint-ab-control.json",
        "postMintIntegrity": "mint-ab-after-mint-gate.json",
    },
    "after_windows_b": {
        "afterMintEvidence": "mint-ab-evidence-after-mint-b.json",
        "postMintIntegrity": "mint-ab-after-mint-gate.json",
    },
}


# Bound the bytes per manifest and all reads from one pinned file descriptor.
# This eliminates the SHA-vs-JSON pathname reopen race (M-278-01).
F03_PREDECESSOR_MAX_BYTES = 2_000_000
F03_PREDECESSOR_READ_CHUNK = 64 * 1024
F03_FILE_IDENTITY_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_uid",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _same_predecessor_identity(before, after) -> bool:
    return all(getattr(before, key) == getattr(after, key) for key in F03_FILE_IDENTITY_FIELDS)


def _pinned_predecessor_bytes(directory_fd: int, filename: str) -> tuple[bytes | None, str | None]:
    """Read one owned predecessor from ONE O_NOFOLLOW fd, never a second path.

    Validate fstat before and after the bounded read and check that the
    directory entry still identifies that fd. This detects observed concurrent
    changes, not all possible same-UID concurrent attacks.
    """
    require(
        isinstance(filename, str)
        and filename
        in {name for items in F03_PREDECESSOR_FILES.values() for name in items.values()},
        "F-03: unrecognized predecessor filename",
    )
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(filename, flags, dir_fd=directory_fd)
    except OSError:
        return None, "missing_or_foreign_predecessor"
    try:
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or before.st_nlink != 1
            ):
                return None, "missing_or_foreign_predecessor"
            if before.st_size < 1 or before.st_size > F03_PREDECESSOR_MAX_BYTES:
                return None, "oversized_or_empty_predecessor"
            payload = bytearray()
            while len(payload) < before.st_size:
                count = min(F03_PREDECESSOR_READ_CHUNK, before.st_size - len(payload))
                piece = os.read(fd, count)
                if not piece:
                    return None, "predecessor_short_read"
                if len(piece) > count:
                    return None, "predecessor_invalid_read"
                payload.extend(piece)
            # Detect any bytes appended beyond the pinned fstat size.
            if os.read(fd, 1):
                return None, "predecessor_changed_during_read"
            after = os.fstat(fd)
            if not _same_predecessor_identity(before, after):
                return None, "predecessor_changed_during_read"
            current = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
            if not _same_predecessor_identity(before, current) or not stat.S_ISREG(current.st_mode):
                return None, "predecessor_path_identity_changed"
            return bytes(payload), None
        except OSError:
            return None, "predecessor_read_or_identity_error"
    finally:
        os.close(fd)


def authenticated_predecessor_status(
    *,
    phase: str,
    evidence: Path,
    transaction_id: str,
    supplied_sha256: dict,
) -> tuple[dict, list]:
    """Hash and interpret EXACT SAME pinned bytes for each previous F-03 gate.

    The early capacity record precedes checkpoint creation and is authenticated
    by the GitHub run and source commit instead of a transactionId.
    """
    expected = F03_PREDECESSOR_FILES[phase]
    require(
        isinstance(supplied_sha256, dict) and set(supplied_sha256) == set(expected),
        "F-03: ambiguous predecessor references",
    )
    require(
        isinstance(evidence, Path)
        and evidence.is_absolute()
        and evidence.resolve() == evidence
        and evidence.name not in ("", ".", ".."),
        "F-03: untrusted evidence directory path",
    )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        directory_fd = os.open(evidence, flags)
    except OSError as exc:
        raise ForensicError("F-03: cannot pin expected evidence directory") from exc
    try:
        directory_before = os.fstat(directory_fd)
        try:
            directory_path = os.stat(evidence, follow_symlinks=False)
        except OSError as exc:
            raise ForensicError("F-03: evidence directory identity unavailable") from exc
        require(
            stat.S_ISDIR(directory_before.st_mode)
            and directory_before.st_uid == os.getuid()
            and (stat.S_IMODE(directory_before.st_mode) & 0o077) == 0
            and directory_before.st_dev == directory_path.st_dev
            and directory_before.st_ino == directory_path.st_ino
            and stat.S_ISDIR(directory_path.st_mode),
            "F-03: unowned or replaced private evidence directory",
        )
        status, problems = {}, []
        for key, filename in expected.items():
            issue = None
            digest = supplied_sha256[key]
            if not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
                issue = "invalid_expected_sha256"
            else:
                payload, issue = _pinned_predecessor_bytes(directory_fd, filename)
                if issue is None:
                    if hashlib.sha256(payload).hexdigest() != digest:
                        issue = "predecessor_sha256_mismatch"
                    else:
                        try:
                            record = json.loads(payload.decode("utf-8"))
                        except (UnicodeError, ValueError):
                            record = None
                        if not isinstance(record, dict):
                            issue = "invalid_predecessor_json"
                        elif key == "earlyCapacity":
                            if not (
                                record.get("schema") == "gaslux-mint-ab-capacity-v1"
                                and record.get("result") == "PASS"
                                and record.get("githubRunId") == os.environ.get("GITHUB_RUN_ID")
                                and record.get("sourceCommit") == os.environ.get("GITHUB_SHA")
                            ):
                                issue = "foreign_preflight_run"
                        elif record.get("transactionId") != transaction_id:
                            issue = "foreign_predecessor_transaction"
                        elif record.get("result") not in (None, "PASS"):
                            issue = "previous_gate_not_passed"
            status[key] = {"file": filename, "sha256Matched": issue is None}
            if issue is not None:
                problems.append({"predecessor": key, "issue": issue})
        # A renamed/replaced evidence directory must not authorize continuation.
        try:
            directory_after = os.fstat(directory_fd)
            final_path = os.stat(evidence, follow_symlinks=False)
        except OSError as exc:
            raise ForensicError("F-03: evidence directory changed during audit") from exc
        require(
            directory_before.st_dev == directory_after.st_dev == final_path.st_dev
            and directory_before.st_ino == directory_after.st_ino == final_path.st_ino
            and directory_before.st_uid == directory_after.st_uid == final_path.st_uid
            and stat.S_ISDIR(final_path.st_mode)
            and (stat.S_IMODE(final_path.st_mode) & 0o077) == 0,
            "F-03: private evidence directory changed during audit",
        )
        return status, problems
    finally:
        os.close(directory_fd)


def require_complete_forensic_inventories(
    *,
    phase: str,
    sources: dict,
    transaction_id: str,
    evidence: Path,
    preceding_sha256: dict,
) -> dict:
    """F-03: durable, fail-closed evidence gate; never repairs guest media.

    The underlying read-only guestfs acquisition may report available=False.
    Preserve that observation without claiming an unverified mount cause.
    """
    require(phase in F03_EVIDENCE_PHASES, "F-03: unsupported evidence phase")
    filename, expected_sources = F03_EVIDENCE_PHASES[phase]
    require(
        isinstance(sources, dict) and set(sources) == set(expected_sources),
        "F-03: ambiguous A/B evidence sources",
    )
    require(
        isinstance(transaction_id, str) and bool(transaction_id),
        "F-03: missing checkpoint transaction ID",
    )
    predecessor_status, predecessor_issues = authenticated_predecessor_status(
        phase=phase,
        evidence=evidence,
        transaction_id=transaction_id,
        supplied_sha256=preceding_sha256,
    )

    resource_status = {}
    unavailable = []
    for label in expected_sources:
        manifest = sources[label]
        inventories = manifest.get("fileInventories") if isinstance(manifest, dict) else None
        for resource in ("esp", "recovery"):
            item = inventories.get(resource) if isinstance(inventories, dict) else None
            files = item.get("fileSha256") if isinstance(item, dict) else None
            if not isinstance(item, dict) or item.get("available") is not True:
                state = "unavailable"
            elif (
                not isinstance(files, dict)
                or not files
                or len(files) > 120000
                or not all(
                    canonical_inventory_path(name)
                    and isinstance(digest, str)
                    and re.fullmatch(r"[a-f0-9]{64}", digest)
                    for name, digest in files.items()
                )
            ):
                state = "incomplete"
            else:
                state = "complete"
            resource_status[label + ":" + resource] = {
                "state": state,
                "fileCount": len(files) if state == "complete" else None,
            }
            if state != "complete":
                reason = item.get("reason") if isinstance(item, dict) else None
                unavailable.append(
                    {
                        "source": label,
                        "resource": resource,
                        "evidenceState": state,
                        "reportedReason": (
                            reason if isinstance(reason, str) and len(reason) <= 128 else None
                        ),
                    }
                )
    passed = not unavailable and not predecessor_issues
    report = {
        "schema": "gaslux-mint-ab-required-inventory-evidence-v1",
        "transactionId": transaction_id,
        "phase": phase,
        "result": "PASS" if passed else "BLOCKED_EVIDENCE",
        "unavailableResources": unavailable,
        "inventoryStatus": resource_status,
        "precedingManifestSha256": preceding_sha256,
        "authenticatedPredecessors": predecessor_status,
        "predecessorIssues": predecessor_issues,
        "continuationAllowedByEvidenceGate": passed,
        # No evidence-only PASS grants permission independently of F-01/F-02,
        # preflight, firmware and checkpoint protections.
        "nextGuestBootAuthorizedByThisGate": False,
        "subsequentBootsBlocked": list(
            {
                "before_windows_a": ("windows_a", "mint_b", "windows_b"),
                "after_windows_a": ("mint_b", "windows_b"),
                "after_mint_b": ("windows_b",),
                "after_windows_b": (),
            }[phase]
        )
        if not passed
        else [],
        "productionInstallAuthorized": False,
        "sameDiskDualBootVerified": False,
        "windowsInPlaceRollbackProven": False,
        "releaseEligible": False,
        "stable": False,
    }
    write_manifest(evidence, filename, report)
    require(
        passed,
        "F-03: required ESP/Recovery inventory evidence incomplete at "
        + phase
        + ": "
        + ", ".join(
            item["source"] + ":" + item["resource"] + " (" + item["evidenceState"] + ")"
            for item in unavailable
        )
        + (
            " prior:" + ", ".join(i["predecessor"] + "/" + i["issue"] for i in predecessor_issues)
            if predecessor_issues
            else ""
        ),
    )
    return report


def require_untouched_after_control(
    *,
    directory: Path,
    base: Path,
    checkpoint: dict,
    evidence: Path,
    transaction_id: str,
) -> dict:
    """A must never alter reference, unused B, backing or unused B VARS.

    Persist the per-resource verdict BEFORE rejecting. No repair, baseline
    change or guest B invocation is permitted on any mismatch.
    """
    reference = directory / REFERENCE
    treatment = directory / ARMS[1]
    vars_b = directory / VARS[1]
    for path, mode in ((reference, 0o400), (treatment, 0o600), (vars_b, 0o600)):
        file_guard(path, directory, mode)
    file_guard(base, base.parent)
    observations = {
        "referenceSha256": sha256_file(reference),
        "unusedTreatmentSha256": sha256_file(treatment),
        "windowsBackingSha256": sha256_file(base),
        "unusedTreatmentOvmfVarsSha256": sha256_file(vars_b),
    }
    checks = {
        "referenceStillUntouched": (
            observations["referenceSha256"] == checkpoint["referenceSha256"]
        ),
        "armBStillUntouched": (
            observations["unusedTreatmentSha256"] == checkpoint["treatmentSha256"]
        ),
        "backingUnchanged": (
            observations["windowsBackingSha256"] == checkpoint["windowsBackingSha256"]
        ),
        "ovmfBStillUntouched": (
            observations["unusedTreatmentOvmfVarsSha256"] == checkpoint["initialOvmfVarsSha256"]
        ),
    }
    passed = all(checks.values())
    if passed:
        image_info(treatment)
        equivalent(reference, treatment)
    report = {
        "schema": "gaslux-mint-ab-cross-arm-gate-v1",
        "gate": "after_control_before_mint",
        "transactionId": transaction_id,
        "result": "PASS" if passed else "BLOCKED_INTEGRITY",
        "checks": checks,
        "observedSha256": observations,
        "referenceAndBStillUntouched": passed,
        "mintBStarted": False,
        "windowsBStarted": False,
        "productionInstallAuthorized": False,
        "releaseEligible": False,
    }
    write_manifest(evidence, "mint-ab-after-control-gate.json", report)
    require(
        passed,
        "F-01: after-control cross-arm integrity failure: "
        + ", ".join(name for name, ok in checks.items() if not ok),
    )
    return report


def require_integrity_after_mint(
    *,
    directory: Path,
    base: Path,
    checkpoint: dict,
    evidence: Path,
    transaction_id: str,
    before: dict,
    after: dict,
    expected_gpt: dict,
    observed_gpt: dict,
) -> dict:
    """Immediately after Mint B shutdown, BEFORE Windows B can be started."""
    reference = directory / REFERENCE
    vars_b = directory / VARS[1]
    file_guard(reference, directory, 0o400)
    file_guard(vars_b, directory, 0o600)
    file_guard(base, base.parent)
    observed = {
        "referenceSha256": sha256_file(reference),
        "windowsBackingSha256": sha256_file(base),
        "treatmentOvmfVarsSha256": sha256_file(vars_b),
    }
    before_partitions = before["partitionSha256"]
    after_partitions = after["partitionSha256"]
    require(
        isinstance(before_partitions, list)
        and len(before_partitions) == 4
        and isinstance(after_partitions, list)
        and len(after_partitions) == 4
        and all(
            isinstance(h, str) and re.fullmatch(r"[a-f0-9]{64}", h)
            for h in before_partitions + after_partitions
        ),
        "F-02: incomplete post-Mint Windows partition hash acquisition",
    )
    # Compare the *entire* GPT manifest: disk GUID, each PARTUUID,
    # partition LBAs, sector size and primary/backup GPT byte digests.
    gpt_fields = (
        "diskGuid",
        "partitionGuids",
        "partitionRanges",
        "sectorBytes",
        "rawPrimaryGptWindowSha256",
        "rawBackupGptWindowSha256",
    )
    gpt_differences = {key: expected_gpt.get(key) != observed_gpt.get(key) for key in gpt_fields}
    checks = {
        "gptUnchanged": (expected_gpt == observed_gpt and not any(gpt_differences.values())),
        "windowsEspUnchanged": before_partitions[0] == after_partitions[0],
        "windowsMsrUnchanged": before_partitions[1] == after_partitions[1],
        "windowsOsNtfsUnchanged": before_partitions[2] == after_partitions[2],
        "windowsRecoveryUnchanged": before_partitions[3] == after_partitions[3],
        "rootUuidUnchanged": before["rootUuid"] == after["rootUuid"],
        "mintRootFilesUnchanged": before["mintRootFiles"] == after["mintRootFiles"],
        "referenceUnchanged": observed["referenceSha256"] == checkpoint["referenceSha256"],
        "backingUnchanged": observed["windowsBackingSha256"] == checkpoint["windowsBackingSha256"],
        "treatmentOvmfVarsUnchanged": observed["treatmentOvmfVarsSha256"]
        == checkpoint["initialOvmfVarsSha256"],
    }
    passed = all(checks.values())
    report = {
        "schema": "gaslux-mint-ab-post-mint-gate-v1",
        "gate": "after_mint_before_windows_b",
        "transactionId": transaction_id,
        "result": "PASS" if passed else "BLOCKED_INTEGRITY",
        "checks": checks,
        "gptDifferences": gpt_differences,
        "gptBefore": expected_gpt,
        "gptAfterMint": observed_gpt,
        "windowsPartitionSha256BeforeMint": before_partitions,
        "windowsPartitionSha256AfterMint": after_partitions,
        "rootUuidBeforeMint": before["rootUuid"],
        "rootUuidAfterMint": after["rootUuid"],
        "mintRootFileSha256BeforeMint": before["mintRootFiles"],
        "mintRootFileSha256AfterMint": after["mintRootFiles"],
        "observedSha256": observed,
        "windowsBStarted": False,
        "productionInstallAuthorized": False,
        "releaseEligible": False,
    }
    write_manifest(evidence, "mint-ab-after-mint-gate.json", report)
    require(
        passed,
        "F-02: post-Mint pre-Windows B integrity failure: "
        + ", ".join(name for name, ok in checks.items() if not ok)
        + (
            " (GPT: " + ", ".join(k for k, changed in gpt_differences.items() if changed) + ")"
            if any(gpt_differences.values())
            else ""
        ),
    )
    return report


def run_ab(
    *,
    original: list[str],
    base: Path,
    nvram: Path,
    overlay: Path,
    workspace: Path,
    root_uuid: str,
    kernel: Path,
    initramfs: Path,
    evidence: Path,
) -> dict:
    require(
        os.environ.get("GASLUX_MINT_AB_CHECKPOINT_CONSENT") == CONSENT
        and os.environ.get("GASLUX_MINT_AB_BOOT_CONSENT")
        == "I_ACCEPT_ONE_DISPOSABLE_WINDOWS10_MINT_AB_AFTER_RESTORE",
        "missing separate single A/B KVM experiment consent",
    )
    early_file = evidence / "mint-ab-capacity-early.json"
    checked_file(early_file, evidence)
    early = json.loads(early_file.read_bytes())
    require(
        early.get("schema") == "gaslux-mint-ab-capacity-v1"
        and early.get("phase") == "early"
        and early.get("result") == "PASS"
        and early.get("checkpointReadyForReview") is False
        and early.get("compressionAssumedForCapacity") is False
        and early.get("githubRunId") == os.environ.get("GITHUB_RUN_ID")
        and early.get("sourceCommit") == os.environ.get("GITHUB_SHA"),
        "missing same-run approved conservative A/B capacity preflight",
    )
    early_hash = sha256_file(early_file)
    code_args = [
        arg.removeprefix("if=pflash,format=raw,readonly=on,file=")
        for arg in original
        if arg.startswith("if=pflash,format=raw,readonly=on,file=")
    ]
    require(len(code_args) == 1, "A/B original QEMU OVMF_CODE is ambiguous")
    _guest_disk_audit(overlay, root_uuid)  # all five roots and four Windows SHA
    checkpoint = prepare_checkpoint(
        base=base,
        nvram=nvram,
        overlay=overlay,
        mint_root_uuid=root_uuid,
        ovmf_code=Path(code_args[0]),
        diagnostic_dir=evidence,
    )
    verify_ab_source(workspace, checkpoint, base)
    write_manifest(evidence, "mint-ab-checkpoint.json", checkpoint)
    directory = workspace / AB_DIR
    arms = (directory / ARMS[0], directory / ARMS[1])
    before = [guest_ro_inventory(arm, root_uuid) for arm in arms]
    # F-03: both independent reference inventories must be complete BEFORE
    # any Windows A guest is started, even if both failures are identical.
    require_complete_forensic_inventories(
        phase="before_windows_a",
        sources={"arm_a_preboot": before[0], "arm_b_preboot": before[1]},
        transaction_id=checkpoint["transactionId"],
        evidence=evidence,
        preceding_sha256={
            "checkpoint": sha256_file(evidence / "mint-ab-checkpoint.json"),
            "earlyCapacity": early_hash,
        },
    )
    gpts = [gpt_manifest(arm, workspace) for arm in arms]
    require(
        before[0] == before[1] and gpts[0] == gpts[1],
        "A/B preboot partition, root or GUID state differs",
    )
    ab = {
        "schema": "gaslux-mint-ab-windows-replay-v1",
        "transactionId": checkpoint["transactionId"],
        "runIdentity": os.environ.get("GITHUB_RUN_ID"),
        "sourceCommit": os.environ.get("GITHUB_SHA"),
        "checkpointManifestSha256": sha256_file(directory / "checkpoint.json"),
        "earlyCapacityManifestSha256": early_hash,
        "baselineInventoryEvidenceSha256": sha256_file(
            evidence / F03_EVIDENCE_PHASES["before_windows_a"][0]
        ),
        "sameWindowsOrdinalBeforeArms": True,
        "rootBefore": before[0]["mintRootFiles"],
        "partitionSha256Before": before[0]["partitionSha256"],
        "rawGptBefore": gpts[0],
        "nativeGrubDualBootVerified": False,
        "sameDiskDualBootVerified": False,
        "rollbackInPlaceVerified": False,
        "windowsInPlaceRollbackProven": False,
        "releaseEligible": False,
        "stable": False,
        "windowsProtectedIntegrityAccepted": False,
    }
    # Both arms start from the same post-third-Windows-boot checkpoint.
    # Control: the next Windows boot with no Mint boot.
    ab["control"] = run_windows_arm(
        original,
        base,
        nvram,
        arms[0],
        directory / VARS[0],
        workspace / "mint-ab-arm-a-windows-serial.log",
    )
    require(
        archive_serial(workspace / "mint-ab-arm-a-windows-serial.log", evidence)
        == ab["control"]["bootWitnessSha256"],
        "control Windows boot transcript digest differs",
    )
    after_a = guest_ro_inventory(arms[0], root_uuid)
    gpt_a = gpt_manifest(arms[0], workspace)
    ab["control"]["partitionSha256After"] = after_a["partitionSha256"]
    ab["control"]["fileDiff"] = changed_files(before[0], after_a)
    ab["control"]["mintRootContentsPreserved"] = (
        after_a["mintRootFiles"] == before[0]["mintRootFiles"]
    )
    ab["control"]["gptUnchanged"] = gpt_a == gpts[0]
    # F-01: block the NEXT guest if Windows A touched any unused B resource.
    control_gate = require_untouched_after_control(
        directory=directory,
        base=base,
        checkpoint=checkpoint,
        evidence=evidence,
        transaction_id=ab["transactionId"],
    )
    # F-03: an unavailable A filesystem inventory is NOT a content delta.
    # Preserve the explicit refusal before starting Mint on B.
    require_complete_forensic_inventories(
        phase="after_windows_a",
        sources={"arm_a_after_windows": after_a},
        transaction_id=ab["transactionId"],
        evidence=evidence,
        preceding_sha256={
            "baselineEvidence": ab["baselineInventoryEvidenceSha256"],
            "afterControlIntegrity": sha256_file(evidence / "mint-ab-after-control-gate.json"),
        },
    )
    write_manifest(
        evidence,
        "mint-ab-control.json",
        {
            "transactionId": ab["transactionId"],
            "sourceCommit": ab["sourceCommit"],
            "checkpointManifestSha256": ab["checkpointManifestSha256"],
            "control": ab["control"],
            "referenceAndBStillUntouched": control_gate["referenceAndBStillUntouched"],
            "afterControlGateSha256": sha256_file(evidence / "mint-ab-after-control-gate.json"),
            "afterControlEvidenceSha256": sha256_file(
                evidence / F03_EVIDENCE_PHASES["after_windows_a"][0]
            ),
            "releaseEligible": False,
        },
    )
    # Treatment: Mint direct-kernel first, then the SAME Windows ordinal.
    ab["treatment"] = run_mint_arm(
        arms[1], kernel, initramfs, root_uuid, evidence / "mint-ab-arm-b-mint-serial.log"
    )
    # F-02: capture GPT immediately after Mint shutdown; a changed
    # partition table must not even reach a subsequent Windows boot.
    after_mint_gpt = gpt_manifest(arms[1], workspace)
    after_mint = guest_ro_inventory(arms[1], root_uuid)
    # Full GPT, all Windows partition digests, Mint root and immutable
    # backing/reference MUST pass before starting Windows B.
    post_mint_gate = require_integrity_after_mint(
        directory=directory,
        base=base,
        checkpoint=checkpoint,
        evidence=evidence,
        transaction_id=ab["transactionId"],
        before=before[1],
        after=after_mint,
        expected_gpt=gpts[1],
        observed_gpt=after_mint_gpt,
    )
    # F-03: file-level acquisition of the treatment remains required
    # separately from the F-02 raw GPT and partition-integrity gates.
    require_complete_forensic_inventories(
        phase="after_mint_b",
        sources={"arm_b_after_mint": after_mint},
        transaction_id=ab["transactionId"],
        evidence=evidence,
        preceding_sha256={
            "baselineEvidence": ab["baselineInventoryEvidenceSha256"],
            "afterControlEvidence": sha256_file(
                evidence / F03_EVIDENCE_PHASES["after_windows_a"][0]
            ),
            "control": sha256_file(evidence / "mint-ab-control.json"),
            "postMintIntegrity": sha256_file(evidence / "mint-ab-after-mint-gate.json"),
        },
    )
    require(
        archive_serial(evidence / "mint-ab-arm-b-mint-serial.log", directory, max_bytes=2_000_000)
        == ab["treatment"]["mintSerialSha256"],
        "Mint B transcript digest differs",
    )
    ab["treatment"]["partitionSha256AfterMint"] = after_mint["partitionSha256"]
    ab["treatment"]["gptAfterMintUnchanged"] = post_mint_gate["checks"]["gptUnchanged"]
    ab["treatment"]["postMintGateSha256"] = sha256_file(evidence / "mint-ab-after-mint-gate.json")
    ab["treatment"]["postMintEvidenceSha256"] = sha256_file(
        evidence / F03_EVIDENCE_PHASES["after_mint_b"][0]
    )
    ab["treatment"]["windows"] = run_windows_arm(
        original,
        base,
        nvram,
        arms[1],
        directory / VARS[1],
        workspace / "mint-ab-arm-b-windows-serial.log",
    )
    require(
        archive_serial(workspace / "mint-ab-arm-b-windows-serial.log", evidence)
        == ab["treatment"]["windows"]["bootWitnessSha256"],
        "treatment Windows boot transcript digest differs",
    )
    after_b = guest_ro_inventory(arms[1], root_uuid)
    gpt_b = gpt_manifest(arms[1], workspace)
    # The final B-versus-A per-file comparison is also inadmissible if the
    # post-Windows B inventory is unavailable. No false completed manifest.
    require_complete_forensic_inventories(
        phase="after_windows_b",
        sources={"arm_b_after_windows": after_b},
        transaction_id=ab["transactionId"],
        evidence=evidence,
        preceding_sha256={
            "afterMintEvidence": ab["treatment"]["postMintEvidenceSha256"],
            "postMintIntegrity": ab["treatment"]["postMintGateSha256"],
        },
    )
    ab["treatment"]["afterWindowsEvidenceSha256"] = sha256_file(
        evidence / F03_EVIDENCE_PHASES["after_windows_b"][0]
    )
    ab["treatment"]["partitionSha256AfterWindows"] = after_b["partitionSha256"]
    ab["treatment"]["fileDiff"] = changed_files(before[1], after_b)
    ab["treatment"]["mintRootContentsPreserved"] = (
        after_b["mintRootFiles"] == before[1]["mintRootFiles"]
    )
    ab["treatment"]["gptUnchanged"] = gpt_b == gpts[1]
    ab["control"]["changedPartitionFlags"] = [
        x != y
        for x, y in zip(before[0]["partitionSha256"], after_a["partitionSha256"], strict=True)
    ]
    ab["treatment"]["changedPartitionFlags"] = [
        x != y
        for x, y in zip(before[1]["partitionSha256"], after_b["partitionSha256"], strict=True)
    ]
    ab["samePartitionChangesObservedInBothArms"] = (
        ab["control"]["changedPartitionFlags"] == ab["treatment"]["changedPartitionFlags"]
    )
    ab["backingUnchanged"] = sha256_file(base) == checkpoint["windowsBackingSha256"]
    ab["referenceUnchanged"] = sha256_file(directory / REFERENCE) == checkpoint["referenceSha256"]
    ab["initialOvmfVarsSha256"] = checkpoint["initialOvmfVarsSha256"]
    ab["controlOvmfVarsSha256After"] = sha256_file(directory / VARS[0])
    ab["treatmentOvmfVarsSha256After"] = sha256_file(directory / VARS[1])
    ab["protectedWindowsDigestsUnchanged"] = (
        not any(ab["treatment"]["changedPartitionFlags"][i] for i in (0, 1, 3))
        and ab["backingUnchanged"]
        and ab["referenceUnchanged"]
        and ab["treatment"]["gptUnchanged"]
        and ab["treatment"]["mintRootContentsPreserved"]
        and all(
            d["fileInventories"][part]["available"]
            for d in (before[0], before[1], after_a, after_b)
            for part in ("esp", "recovery")
        )
    )
    # The A/B experiment NEVER declares OS safety/installation acceptance,
    # even if a diagnostic happens to show equal protected digests.
    ab["windowsProtectedIntegrityAccepted"] = False
    write_manifest(evidence, "mint-ab-forensic.json", ab)
    # After forensic read-only acquisition, prove BOTH writable arms can
    # be reconstituted from the unchanged standalone checkpoint. No release
    # authorization follows from recovery of a disposable QEMU experiment.
    from windows_mint_ab_checkpoint import clone_vars, reproduce_restore

    ref = directory / REFERENCE
    for arm in arms:
        require(reproduce_restore(ref, arm, directory), "A/B postboot reference recovery failed")
        equivalent(ref, arm)
    vars_source = workspace / "windows-uefi-cow-checkpoint" / "trial-ovmf-variables.fd"
    for name in VARS:
        current = directory / name
        file_guard(current, directory, 0o600)
        current.unlink()  # EXACT owned copied vars, never the source
        clone_vars(vars_source, current, directory)
    require(
        sha256_file(base) == checkpoint["windowsBackingSha256"]
        and sha256_file(ref) == checkpoint["referenceSha256"]
        and all(
            sha256_file(directory / name) == checkpoint["initialOvmfVarsSha256"] for name in VARS
        ),
        "A/B recovery mutated the backing, checkpoint or OVMF state",
    )
    recovery = {
        "transactionId": ab["transactionId"],
        "restoreArmAProven": True,
        "restoreArmBProven": True,
        "ovmfArmAAndBRestored": True,
        "backingAndReferencePreserved": True,
        "releaseEligible": False,
        "productionRollbackProven": False,
    }
    write_manifest(evidence, "mint-ab-recovery.json", recovery)
    ab["disposableArmsRestoredAfterBoot"] = True
    # Forensic classification never authorizes writes, even if A == B.
    return ab


if __name__ == "__main__":
    raise SystemExit("No direct invocation: requires prior genuine Windows COW checkpoint")
