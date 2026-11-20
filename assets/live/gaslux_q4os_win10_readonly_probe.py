"""Genuine Windows 10 QCOW2: independent read-only QEMU/guestfs GPT evidence.

LAB ONLY. Windows setup is a separate established Q4OS workflow stage.
This module never invokes installation, partitioning, GRUB, mkfs, EFI or writers.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

from gaslux_q4os_safety_adapter import refuse_calamares
from gaslux_q4os_windows_boundary import (
    Q4osWindowsBoundaryRefusal,
    inspect_private_raw_vm_disk,
)
from libertix_disk_identity_gate import (
    DiskIdentityError,
    assert_snapshot_matches,
    inspect_gpt_image,
)
from libertix_prewrite_no_writer import (
    PrewriteDenied,
    canonical,
    decide_no_writer,
)

SIZE = 48 * 1024**3
EDGE = 2 * 1024**2
NAME = "windows10-enterprise-eval-22h2-uefi-gpt.qcow2"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(*args: str) -> str:
    process = subprocess.run(
        args, check=False, capture_output=True, text=True, timeout=900
    )
    require(process.returncode == 0, "read-only QEMU command failed: " + args[0])
    return process.stdout


def _private_regular(path: Path) -> None:
    require(path.is_absolute() and not path.is_symlink(), "unsafe image path")
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1,
        "nonexclusive or foreign image",
    )


def _read_only_appliance(qcow: Path, scratch: Path, sector: int) -> dict:
    """Independent QEMU libguestfs transport. Shared Safety parser, no GPT fork."""
    import guestfs

    guest_image = scratch / "guest-gpt-only.raw"
    require(not guest_image.exists(), "guest metadata destination reused")
    g = guestfs.GuestFS(python_return_dict=True)
    try:
        g.add_drive_opts(str(qcow), format="qcow2", readonly=1)
        g.launch()
        devices = g.list_devices()
        require(len(devices) == 1, "guestfs did not attach exactly one read-only disk")
        device = devices[0]  # diagnostic only; sole attached drive is source identity
        size = g.blockdev_getsize64(device)
        logical = g.blockdev_getss(device)
        require(size == SIZE and logical == sector, "guest geometry mismatch")
        with guest_image.open("xb") as dest:
            dest.truncate(size)
            dest.seek(0)
            first = g.pread_device(device, EDGE, 0)
            dest.write(first)
            dest.seek(size - EDGE)
            last = g.pread_device(device, EDGE, size - EDGE)
            dest.write(last)
            require(len(first) == EDGE and len(last) == EDGE, "incomplete guest GPT")
        observed = inspect_gpt_image(guest_image, logical_sector_size=sector)
        observed["source"] = "single-readonly-libguestfs-qemu-appliance"
        observed["devicePathDiagnosticOnly"] = True
        observed["transportAuthenticatedToWindowsHost"] = False
        return observed
    finally:
        with suppress(RuntimeError):
            g.shutdown()
        g.close()


def _real_safety_denial(host: dict) -> dict:
    """Actual #267 gate on observed GPT, WITHOUT source-authenticated MACs/keys."""
    txid = secrets.token_hex(16)
    plan = {
        "planId": txid,
        "firmware": "uefi",
        "disk": {name: host[name] for name in (
            "partitionStyle", "partitionTableId", "sizeBytes", "logicalSectorSizeBytes"
        )},
    }
    plan_bytes = canonical(plan)
    try:
        decide_no_writer(
            plan=plan, plan_bytes=plan_bytes, transaction_id=txid,
            vm_id=secrets.token_hex(16),
            host_evidence=None, guest_evidence=None, immediate_evidence=None,
            host_key=None, guest_key=None, fresh_nonce=secrets.token_hex(32),
            owned_regions=[], write_set=[],
        )
    except PrewriteDenied as exc:
        return {
            "decision": "DENY_UNAUTHENTICATED",
            "reason": str(exc),
            "hostGuestTransactionAuthenticated": False,
        }
    raise ValueError("Safety unexpectedly accepted unauthenticated real Windows records")


def inspect_windows_readonly(workspace: Path, evidence: Path) -> dict:
    require(
        workspace.is_absolute() and workspace.parent == Path(os.environ["RUNNER_TEMP"])
        and workspace.name == "gaslux-win10-" + os.environ["GITHUB_RUN_ID"],
        "only disposable GitHub Windows 10 workspace",
    )
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux",
        "not an authorized hosted QEMU lab",
    )
    require(
        workspace.is_dir() and not workspace.is_symlink()
        and workspace.stat().st_uid == os.getuid()
        and workspace.stat().st_mode & 0o077 == 0,
        "Windows image workspace not private",
    )
    require(evidence.is_absolute() and evidence.is_dir() and not evidence.is_symlink(),
            "unsafe evidence directory")
    image = workspace / NAME
    _private_regular(image)
    before = sha256_file(image)
    info = json.loads(run("qemu-img", "info", "--output=json", "-f", "qcow2", str(image)))
    require(
        info.get("format") == "qcow2" and info.get("virtual-size") == SIZE
        and not info.get("backing-filename") and not info.get("full-backing-filename")
        and not info.get("data-file"),
        "unexpected QCOW2 backing, data-file or virtual geometry",
    )
    run("qemu-img", "check", "-f", "qcow2", str(image))
    scratch = workspace / "q4os-readonly-boundary"
    scratch.mkdir(mode=0o700)
    raw = scratch / "windows-target.raw"
    require(not raw.exists(), "refusing existing converted image")
    # Materialize ONLY GPT edge observations from qemu-img's independent
    # read-only QCOW2 decoder, not the Windows NTFS/ESP content.
    # No full 48-GiB raw clone and no exposure of real guest data as artifact.
    first_edge = scratch / "host-gpt-first.bin"
    last_edge = scratch / "host-gpt-last.bin"
    run("qemu-img", "dd", "-f", "qcow2", "-O", "raw",
        "bs=1M", "count=2", "if=" + str(image), "of=" + str(first_edge))
    run("qemu-img", "dd", "-f", "qcow2", "-O", "raw",
        "bs=1M", "count=2", "skip=" + str(SIZE // (1024**2) - 2),
        "if=" + str(image), "of=" + str(last_edge))
    require(first_edge.stat().st_size == EDGE and last_edge.stat().st_size == EDGE,
            "incomplete host GPT edges")
    with raw.open("xb") as destination:
        destination.truncate(SIZE)
        destination.seek(0)
        destination.write(first_edge.read_bytes())
        destination.seek(SIZE - EDGE)
        destination.write(last_edge.read_bytes())
    _private_regular(raw)
    host = inspect_gpt_image(raw, logical_sector_size=512)
    guest = _read_only_appliance(image, scratch, 512)
    guest_safety = {
        key: guest[key] for key in (
            "partitionStyle", "partitionTableId", "sizeBytes",
            "logicalSectorSizeBytes", "partitions"
        )
    }
    assert_snapshot_matches(host, guest_safety)
    protected = {
        "esp": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
        "msr": "e3c9e316-0b5c-4db8-817d-f92df00215ae",
        "ntfsWindows": "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
        "winre": "de94bba4-06d1-4d40-a16a-bfd50179d6ac",
    }
    count = {
        label: sum(p["typeGuid"] == type_guid for p in host["partitions"])
        for label, type_guid in protected.items()
    }
    # Q4OS's full-content inspector is safe to run only as an expected
    # early denial for a missing WinRE partition. The sparse GPT witness
    # deliberately contains NO Windows volume data to authenticate.
    if count["winre"] == 0:
        try:
            inspect_private_raw_vm_disk(scratch, raw, sector_bytes=512)
        except Q4osWindowsBoundaryRefusal as exc:
            q4os_reason = str(exc)
        else:
            raise ValueError("Q4OS unexpectedly accepted Windows lacking WinRE")
    else:
        q4os_reason = (
            "Full ESP/NTFS/WinRE content not acquired by metadata-only GPT "
            "observation; safe target plan blocked"
        )
    q4os = None
    adapter = refuse_calamares(
        q4os=q4os, expected=host, safety_observed=guest_safety,
        safety_compare=assert_snapshot_matches, plan=None, transaction=None,
        write_set=None, calamares=None, safety_attestation=None,
    )
    safety = _real_safety_denial(host)
    after = sha256_file(image)
    require(before == after, "genuine Windows backing changed during read-only audit")
    report = {
        "schemaVersion": 1,
        "source": "genuine-Windows-10-QEMU-firstboot-separate-verified-step",
        "qcow2OriginalSha256Before": before,
        "qcow2OriginalSha256After": after,
        "backingChainPresent": False,
        "qemuLibguestfsReadOnly": True,
        "guestDeviceCount": 1,
        "hostGuestGptMatches": True,
        "gptWitnessOnlyNoWindowsPartitionPayload": True,
        "host": host,
        "guest": guest,
        "protectedPartitionCounts": count,
        "winrePresent": count["winre"] == 1,
        "q4osBoundaryRefusal": q4os_reason,
        "q4osAdapter": adapter,
        "safety267": safety,
        "provenanceAuthenticatedAcrossWindowsAndGuest": False,
        "windowsBootWitnessProvidedByPriorWorkflowStep": True,
        "windowsDataWrittenDuringInspection": False,
        "calamaresExecuted": False,
        "installationAuthorized": False,
        "diskWritesAuthorized": False,
        "rollbackVerified": False,
    }
    require(adapter["decision"] == "refuse" and safety["decision"] == "DENY_UNAUTHENTICATED",
            "expected safety refusals missing")
    require(report["installationAuthorized"] is False, "unexpected installation authority")
    result = evidence / "q4os-windows10-real-readonly-refusal.json"
    require(not result.exists(), "report destination exists")
    result.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence / "q4os-windows10-real-readonly-refusal.sha256").write_text(
        sha256_file(result) + "  " + result.name + "\n", encoding="ascii"
    )
    return report


def main() -> int:
    workspace = Path(os.environ["RUNNER_TEMP"]) / (
        "gaslux-win10-" + os.environ["GITHUB_RUN_ID"]
    )
    evidence = Path(os.environ["RUNNER_TEMP"]) / "q4os-win10-readonly-evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    try:
        result = inspect_windows_readonly(workspace, evidence)
    except (OSError, ValueError, RuntimeError, DiskIdentityError) as exc:
        failure = {
            "decision": "refuse", "reason": str(exc),
            "installationAuthorized": False, "diskWritesAuthorized": False,
            "provenanceAuthenticatedAcrossWindowsAndGuest": False,
        }
        (evidence / "q4os-readonly-failure.json").write_text(
            json.dumps(failure, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(json.dumps(failure))
        return 1
    print(json.dumps({
        "decision": "refuse", "winrePresent": result["winrePresent"],
        "hostGuestGptMatches": result["hostGuestGptMatches"],
        "sourceSha256": result["qcow2OriginalSha256Before"],
        "backingPreserved": True, "installAuthorized": False,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
