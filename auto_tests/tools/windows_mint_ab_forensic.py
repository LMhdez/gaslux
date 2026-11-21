#!/usr/bin/env python3
"""Forensic Windows-only A versus direct-kernel Mint then Windows B.

Only after the independent checkpoint passes genuine-QCOW2 restore tests.
Do not interpret differences as repair permission or an installer success.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import re
import stat
import struct
import subprocess
import time
import uuid

from windows_mint_ab_checkpoint import (
    AB_DIR, ARMS, CONSENT, VARS, REFERENCE, prepare_checkpoint,
    file_guard, image_info, equivalent, sha256_file,
)
from windows_mint_overlay_root import (
    _guest_disk_audit, has_orderly_shutdown_witness, MintOverlayError,
)
from windows_cachyos_overlay_reboot import (
    third_guest_args, audit_complete_third_serial, gpt_windows,
)
from windows_cachyos_qcow2_gpt_readonly import VIRTUAL_BYTES

ROOT_MARKER = b"GASLUXMINT login:"
WIN_EXPECT = ("windowsEspDigestChanged", "windowsMsrDigestChanged",
              "windowsOsNtfsDigestChanged", "windowsRecoveryDigestChanged")


class ForensicError(RuntimeError):
    pass


def require(ok: bool, reason: str):
    if not ok:
        raise ForensicError(reason)


def checked_file(path: Path, parent: Path):
    require(path.parent == parent and path.is_file() and not path.is_symlink()
            and path.stat().st_nlink == 1, "untrusted A/B evidence path")


def guest_ro_inventory(disk: Path, root_uuid: str) -> dict:
    """Collect full Windows partition checksums plus fifth-root files read-only."""
    import guestfs
    guest = guestfs.GuestFS(python_return_dict=True)
    try:
        guest.add_drive_opts(str(disk), format="qcow2", readonly=1)
        guest.launch()
        devices = guest.list_devices()
        require(len(devices) == 1
                and guest.blockdev_getsize64(devices[0]) == VIRTUAL_BYTES,
                "A/B guest disk identity changed")
        d = devices[0]
        suffix = "p" if d[-1].isdigit() else ""
        parts = [d + suffix + str(n) for n in range(1, 6)]
        require(guest.list_partitions() == parts
                and guest.vfs_type(parts[4]) == "ext4"
                and guest.vfs_uuid(parts[4]) == root_uuid,
                "A/B root UUID or GPT partition count changed")
        hashes = [guest.checksum_device("sha256", p) for p in parts[:4]]
        root_files = {}
        guest.mount_ro(parts[4], "/")
        for path in ("/etc/os-release", "/etc/fstab"):
            require(guest.is_file(path), "Mint root metadata missing: " + path)
            root_files[path] = guest.checksum("sha256", path)
        # The kernel and initramfs are identified by their exact tree contents.
        boots = sorted([name for name in guest.ls("/boot")
                        if re.fullmatch(r"vmlinuz-[A-Za-z0-9.+_-]{1,128}", name)])
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
                require(len(names) <= 120000,
                        "A/B forensic file inventory exceeded safety bound")
                contents = {}
                for path in names:
                    absolute = "/" + path.lstrip("/")
                    require("\x00" not in absolute and len(absolute) <= 4096,
                            "unsafe guestfs inventory path")
                    if guest.is_file(absolute):
                        contents[absolute] = guest.checksum("sha256", absolute)
                require(bool(contents),
                        "read-only ESP/Recovery file enumeration was empty")
                inventories[name] = {"available": True,
                                     "fileSha256": contents}
                guest.umount_all()
            except Exception as exc:
                guest.umount_all()
                inventories[name] = {"available": False,
                                     "reason": type(exc).__name__}
        return {"partitionSha256": hashes, "rootUuid": root_uuid,
                "mintRootFiles": root_files, "fileInventories": inventories}
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
    entries = front[1024:1024 + 128*128]
    require(primary[:8] == b"EFI PART",
            "missing A/B GPT primary header")
    raw_guids = []
    for i in range(5):
        rec = entries[i*128:(i+1)*128]
        require(any(rec[:16]) and any(rec[16:32]),
                "missing GUID for A/B partition " + str(i+1))
        raw_guids.append(str(uuid.UUID(bytes_le=rec[16:32])))
    return {
        "diskGuid": str(uuid.UUID(bytes_le=primary[56:72])),
        "partitionGuids": raw_guids,
        "rawPrimaryGptWindowSha256": hashlib.sha256(front).hexdigest(),
        "rawBackupGptWindowSha256": hashlib.sha256(back).hexdigest(),
        "partitionRanges": [
            dict(index=i+1, firstLba=struct.unpack_from("<Q", entries, i*128+32)[0],
                 lastLba=struct.unpack_from("<Q", entries, i*128+40)[0])
            for i in range(5)
        ],
        "sectorBytes": 512,
    }


def verify_ab_source(workspace: Path, proof: dict, base: Path) -> None:
    require(proof.get("checkpointReadyForReview") is True
            and proof.get("controlRecoveredAfterFaultInjection") is True
            and proof.get("sharedBackingChains") is False
            and proof.get("armsBooted") is False
            and proof.get("releaseEligible") is False,
            "A/B checkpoint recovery and independent arms not proven")
    directory = workspace / AB_DIR
    ref = directory / REFERENCE
    file_guard(ref, directory, 0o400)
    require(sha256_file(ref) == proof.get("referenceSha256"),
            "immutable reference checkpoint differs before QEMU")
    for arm, digest in zip(ARMS, (proof["controlSha256"], proof["treatmentSha256"])):
        p = directory / arm
        file_guard(p, directory, 0o600)
        image_info(p)
        require(sha256_file(p) == digest, "A/B arm changed BEFORE guest start")
        equivalent(ref, p)
    for vars_name in VARS:
        p = directory / vars_name
        file_guard(p, directory, 0o600)
        require(sha256_file(p) == proof["initialOvmfVarsSha256"],
                "initial A/B OVMF state mismatch")
    require(sha256_file(base) == proof["windowsBackingSha256"],
            "Windows backing changed before forensic boots")


def run_windows_arm(original: list[str], base: Path, nvram: Path,
                    arm: Path, vars_path: Path, serial: Path) -> dict:
    require(serial.parent == base.parent and not serial.exists()
            and not serial.is_symlink(), "reused Windows A/B serial")
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
    return {"bootWitnessSha256": serial_sha,
            "bootAttemptId": str(uuid.uuid4()),
            "elapsedMonotonicSeconds": round(time.monotonic()-started, 2),
            "realWindows10GuestMarkersVerified": True}


def run_mint_arm(arm: Path, kernel: Path, initramfs: Path,
                 root_uuid: str, serial: Path) -> dict:
    require(not serial.exists() and not serial.is_symlink(),
            "reused Mint A/B serial")
    args = ["qemu-system-x86_64", "-machine", "q35,accel=kvm",
            "-cpu", "host", "-smp", "2", "-m", "4096", "-display", "none",
            "-net", "none", "-no-reboot", "-drive",
            f"if=none,id=windows-cow,format=qcow2,file={arm}",
            "-device", "virtio-blk-pci,drive=windows-cow,bootindex=1",
            "-kernel", str(kernel), "-initrd", str(initramfs),
            "-append", f"root=UUID={root_uuid} rw rootwait console=ttyS0,115200n8 "
                       "systemd.unit=multi-user.target "
                       "systemd.wants=serial-getty@ttyS0.service",
            "-serial", f"file:{serial}", "-boot", "order=c,menu=off"]
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        proc.wait(timeout=550)
        require(proc.returncode == 0, "Mint B failed to power off")
        raw = serial.read_bytes()
        require(ROOT_MARKER in raw and b"Linux version" in raw
                and has_orderly_shutdown_witness(raw),
                "Mint B missing real login/kernel/shutdown serial witness")
        return {"bootAttemptId": str(uuid.uuid4()),
                "mintSerialSha256": hashlib.sha256(raw).hexdigest(),
                "mintDirectKernelBootVerified": True,
                "mintOrderlyShutdownVerified": True}
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
    require(not target.exists() and not target.is_symlink(),
            "reused A/B COM1 archive")
    with source.open("rb") as inp, target.open("xb") as out:
        shutil.copyfileobj(inp, out, 64*1024)
        out.flush()
        os.fsync(out.fileno())
    require(sha256_file(source) == sha256_file(target),
            "A/B COM1 evidence changed during archiving")
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
    require(directory.is_dir() and not directory.is_symlink()
            and not (directory/name).exists(), "unsafe A/B evidence location")
    p = directory / name
    with p.open("xb") as f:
        f.write((json.dumps(data, indent=2, sort_keys=True) + "\n").encode())
        f.flush()
        os.fsync(f.fileno())
    return sha256_file(p)


def require_untouched_after_control(
    *, directory: Path, base: Path, checkpoint: dict,
    evidence: Path, transaction_id: str,
) -> dict:
    """A must never alter reference, unused B, backing or unused B VARS.

    Persist the per-resource verdict BEFORE rejecting. No repair, baseline
    change or guest B invocation is permitted on any mismatch.
    """
    reference = directory / REFERENCE
    treatment = directory / ARMS[1]
    vars_b = directory / VARS[1]
    for path, mode in ((reference, 0o400), (treatment, 0o600),
                       (vars_b, 0o600)):
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
            observations["referenceSha256"] == checkpoint["referenceSha256"]),
        "armBStillUntouched": (
            observations["unusedTreatmentSha256"] == checkpoint["treatmentSha256"]),
        "backingUnchanged": (
            observations["windowsBackingSha256"] == checkpoint["windowsBackingSha256"]),
        "ovmfBStillUntouched": (
            observations["unusedTreatmentOvmfVarsSha256"]
            == checkpoint["initialOvmfVarsSha256"]),
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
    require(passed, "F-01: after-control cross-arm integrity failure: "
            + ", ".join(name for name, ok in checks.items() if not ok))
    return report


def require_integrity_after_mint(
    *, directory: Path, base: Path, checkpoint: dict, evidence: Path,
    transaction_id: str, before: dict, after: dict,
    expected_gpt: dict, observed_gpt: dict,
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
    require(isinstance(before_partitions, list) and len(before_partitions) == 4
            and isinstance(after_partitions, list) and len(after_partitions) == 4
            and all(isinstance(h, str) and re.fullmatch(r"[a-f0-9]{64}", h)
                    for h in before_partitions + after_partitions),
            "F-02: incomplete post-Mint Windows partition hash acquisition")
    # Compare the *entire* GPT manifest: disk GUID, each PARTUUID,
    # partition LBAs, sector size and primary/backup GPT byte digests.
    gpt_fields = ("diskGuid", "partitionGuids", "partitionRanges",
                  "sectorBytes", "rawPrimaryGptWindowSha256",
                  "rawBackupGptWindowSha256")
    gpt_differences = {
        key: expected_gpt.get(key) != observed_gpt.get(key)
        for key in gpt_fields
    }
    checks = {
        "gptUnchanged": (expected_gpt == observed_gpt
                         and not any(gpt_differences.values())),
        "windowsEspUnchanged": before_partitions[0] == after_partitions[0],
        "windowsMsrUnchanged": before_partitions[1] == after_partitions[1],
        "windowsOsNtfsUnchanged": before_partitions[2] == after_partitions[2],
        "windowsRecoveryUnchanged": before_partitions[3] == after_partitions[3],
        "rootUuidUnchanged": before["rootUuid"] == after["rootUuid"],
        "mintRootFilesUnchanged": before["mintRootFiles"] == after["mintRootFiles"],
        "referenceUnchanged": observed["referenceSha256"]
                              == checkpoint["referenceSha256"],
        "backingUnchanged": observed["windowsBackingSha256"]
                            == checkpoint["windowsBackingSha256"],
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
    require(passed, "F-02: post-Mint pre-Windows B integrity failure: "
            + ", ".join(name for name, ok in checks.items() if not ok)
            + (" (GPT: " + ", ".join(k for k, changed in gpt_differences.items()
                                     if changed) + ")" if any(gpt_differences.values()) else ""))
    return report


def run_ab(*, original: list[str], base: Path, nvram: Path,
           overlay: Path, workspace: Path, root_uuid: str,
           kernel: Path, initramfs: Path, evidence: Path) -> dict:
    require(os.environ.get("GASLUX_MINT_AB_CHECKPOINT_CONSENT") == CONSENT
            and os.environ.get("GASLUX_MINT_AB_BOOT_CONSENT")
                == "I_ACCEPT_ONE_DISPOSABLE_WINDOWS10_MINT_AB_AFTER_RESTORE",
            "missing separate single A/B KVM experiment consent")
    early_file = evidence/"mint-ab-capacity-early.json"
    checked_file(early_file, evidence)
    early = json.loads(early_file.read_bytes())
    require(early.get("schema") == "gaslux-mint-ab-capacity-v1"
            and early.get("phase") == "early"
            and early.get("result") == "PASS"
            and early.get("checkpointReadyForReview") is False
            and early.get("compressionAssumedForCapacity") is False
            and early.get("githubRunId") == os.environ.get("GITHUB_RUN_ID")
            and early.get("sourceCommit") == os.environ.get("GITHUB_SHA"),
            "missing same-run approved conservative A/B capacity preflight")
    early_hash = sha256_file(early_file)
    code_args = [arg.removeprefix("if=pflash,format=raw,readonly=on,file=")
                 for arg in original
                 if arg.startswith("if=pflash,format=raw,readonly=on,file=")]
    require(len(code_args) == 1, "A/B original QEMU OVMF_CODE is ambiguous")
    _guest_disk_audit(overlay, root_uuid)  # all five roots and four Windows SHA
    checkpoint = prepare_checkpoint(base=base, nvram=nvram, overlay=overlay,
                                    mint_root_uuid=root_uuid,
                                    ovmf_code=Path(code_args[0]),
                                    diagnostic_dir=evidence)
    verify_ab_source(workspace, checkpoint, base)
    write_manifest(evidence, "mint-ab-checkpoint.json", checkpoint)
    directory = workspace / AB_DIR
    arms = (directory / ARMS[0], directory / ARMS[1])
    before = [guest_ro_inventory(arm, root_uuid) for arm in arms]
    gpts = [gpt_manifest(arm, workspace) for arm in arms]
    require(before[0] == before[1] and gpts[0] == gpts[1],
            "A/B preboot partition, root or GUID state differs")
    ab = {"schema": "gaslux-mint-ab-windows-replay-v1",
          "transactionId": checkpoint["transactionId"],
          "runIdentity": os.environ.get("GITHUB_RUN_ID"),
          "sourceCommit": os.environ.get("GITHUB_SHA"),
          "checkpointManifestSha256": sha256_file(directory/"checkpoint.json"),
          "earlyCapacityManifestSha256": early_hash,
          "sameWindowsOrdinalBeforeArms": True,
          "rootBefore": before[0]["mintRootFiles"],
          "partitionSha256Before": before[0]["partitionSha256"],
          "rawGptBefore": gpts[0],
          "nativeGrubDualBootVerified": False, "rollbackInPlaceVerified": False,
          "releaseEligible": False, "windowsProtectedIntegrityAccepted": False}
    # Both arms start from the same post-third-Windows-boot checkpoint.
    # Control: the next Windows boot with no Mint boot.
    ab["control"] = run_windows_arm(
        original, base, nvram, arms[0], directory/VARS[0],
        workspace/"mint-ab-arm-a-windows-serial.log")
    require(archive_serial(workspace/"mint-ab-arm-a-windows-serial.log",
                           evidence) == ab["control"]["bootWitnessSha256"],
            "control Windows boot transcript digest differs")
    after_a = guest_ro_inventory(arms[0], root_uuid)
    gpt_a = gpt_manifest(arms[0], workspace)
    ab["control"]["partitionSha256After"] = after_a["partitionSha256"]
    ab["control"]["fileDiff"] = changed_files(before[0], after_a)
    ab["control"]["mintRootContentsPreserved"] = (after_a["mintRootFiles"]
                                                   == before[0]["mintRootFiles"])
    ab["control"]["gptUnchanged"] = (gpt_a == gpts[0])
    # F-01: block the NEXT guest if Windows A touched any unused B resource.
    control_gate = require_untouched_after_control(
        directory=directory, base=base, checkpoint=checkpoint,
        evidence=evidence, transaction_id=ab["transactionId"],
    )
    write_manifest(evidence, "mint-ab-control.json", {
        "transactionId": ab["transactionId"],
        "sourceCommit": ab["sourceCommit"],
        "checkpointManifestSha256": ab["checkpointManifestSha256"],
        "control": ab["control"],
        "referenceAndBStillUntouched": control_gate["referenceAndBStillUntouched"],
        "afterControlGateSha256": sha256_file(
            evidence / "mint-ab-after-control-gate.json"),
        "releaseEligible": False,
    })
    # Treatment: Mint direct-kernel first, then the SAME Windows ordinal.
    ab["treatment"] = run_mint_arm(
        arms[1], kernel, initramfs, root_uuid,
        evidence/"mint-ab-arm-b-mint-serial.log")
    after_mint = guest_ro_inventory(arms[1], root_uuid)
    # F-02: full GPT, all Windows partition digests, Mint root and
    # immutable backing/reference MUST pass before starting Windows B.
    after_mint_gpt = gpt_manifest(arms[1], workspace)
    post_mint_gate = require_integrity_after_mint(
        directory=directory, base=base, checkpoint=checkpoint,
        evidence=evidence, transaction_id=ab["transactionId"],
        before=before[1], after=after_mint,
        expected_gpt=gpts[1], observed_gpt=after_mint_gpt,
    )
    require(archive_serial(evidence/"mint-ab-arm-b-mint-serial.log",
                           directory, max_bytes=2_000_000)
            == ab["treatment"]["mintSerialSha256"],
            "Mint B transcript digest differs")
    ab["treatment"]["partitionSha256AfterMint"] = after_mint["partitionSha256"]
    ab["treatment"]["gptAfterMintUnchanged"] = post_mint_gate["checks"]["gptUnchanged"]
    ab["treatment"]["postMintGateSha256"] = sha256_file(
        evidence / "mint-ab-after-mint-gate.json")
    ab["treatment"]["windows"] = run_windows_arm(
        original, base, nvram, arms[1], directory/VARS[1],
        workspace/"mint-ab-arm-b-windows-serial.log")
    require(archive_serial(workspace/"mint-ab-arm-b-windows-serial.log",
                           evidence) == ab["treatment"]["windows"]["bootWitnessSha256"],
            "treatment Windows boot transcript digest differs")
    after_b = guest_ro_inventory(arms[1], root_uuid)
    gpt_b = gpt_manifest(arms[1], workspace)
    ab["treatment"]["partitionSha256AfterWindows"] = after_b["partitionSha256"]
    ab["treatment"]["fileDiff"] = changed_files(before[1], after_b)
    ab["treatment"]["mintRootContentsPreserved"] = (
        after_b["mintRootFiles"] == before[1]["mintRootFiles"])
    ab["treatment"]["gptUnchanged"] = gpt_b == gpts[1]
    ab["control"]["changedPartitionFlags"] = [
        x != y for x, y in zip(before[0]["partitionSha256"],
                             after_a["partitionSha256"])]
    ab["treatment"]["changedPartitionFlags"] = [
        x != y for x, y in zip(before[1]["partitionSha256"],
                             after_b["partitionSha256"])]
    ab["samePartitionChangesObservedInBothArms"] = (
        ab["control"]["changedPartitionFlags"]
        == ab["treatment"]["changedPartitionFlags"])
    ab["backingUnchanged"] = sha256_file(base) == checkpoint["windowsBackingSha256"]
    ab["referenceUnchanged"] = sha256_file(directory/REFERENCE) == checkpoint["referenceSha256"]
    ab["initialOvmfVarsSha256"] = checkpoint["initialOvmfVarsSha256"]
    ab["controlOvmfVarsSha256After"] = sha256_file(directory/VARS[0])
    ab["treatmentOvmfVarsSha256After"] = sha256_file(directory/VARS[1])
    ab["protectedWindowsDigestsUnchanged"] = (
        not any(ab["treatment"]["changedPartitionFlags"][i] for i in (0, 1, 3))
        and ab["backingUnchanged"] and ab["referenceUnchanged"]
        and ab["treatment"]["gptUnchanged"]
        and ab["treatment"]["mintRootContentsPreserved"]
        and all(d["fileInventories"][part]["available"]
                for d in (before[0], before[1], after_a, after_b)
                for part in ("esp", "recovery")))
    # The A/B experiment NEVER declares OS safety/installation acceptance,
    # even if a diagnostic happens to show equal protected digests.
    ab["windowsProtectedIntegrityAccepted"] = False
    write_manifest(evidence, "mint-ab-forensic.json", ab)
    # After forensic read-only acquisition, prove BOTH writable arms can
    # be reconstituted from the unchanged standalone checkpoint. No release
    # authorization follows from recovery of a disposable QEMU experiment.
    from windows_mint_ab_checkpoint import reproduce_restore, clone_vars
    ref = directory / REFERENCE
    for arm in arms:
        require(reproduce_restore(ref, arm, directory),
                "A/B postboot reference recovery failed")
        equivalent(ref, arm)
    vars_source = workspace/"windows-uefi-cow-checkpoint"/"trial-ovmf-variables.fd"
    for name in VARS:
        current = directory/name
        file_guard(current, directory, 0o600)
        current.unlink()  # EXACT owned copied vars, never the source
        clone_vars(vars_source, current, directory)
    require(sha256_file(base) == checkpoint["windowsBackingSha256"]
            and sha256_file(ref) == checkpoint["referenceSha256"]
            and all(sha256_file(directory/name) == checkpoint["initialOvmfVarsSha256"]
                    for name in VARS),
            "A/B recovery mutated the backing, checkpoint or OVMF state")
    recovery = {
        "transactionId": ab["transactionId"],
        "restoreArmAProven": True, "restoreArmBProven": True,
        "ovmfArmAAndBRestored": True, "backingAndReferencePreserved": True,
        "releaseEligible": False, "productionRollbackProven": False,
    }
    write_manifest(evidence, "mint-ab-recovery.json", recovery)
    ab["disposableArmsRestoredAfterBoot"] = True
    # Forensic classification never authorizes writes, even if A == B.
    return ab


if __name__ == "__main__":
    raise SystemExit("No direct invocation: requires prior genuine Windows COW checkpoint")
