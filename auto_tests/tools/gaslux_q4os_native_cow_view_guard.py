#!/usr/bin/env python3
"""Owner-bound signed backup and COW for native Calamares GUI VIEW ONLY.

The native installer is allowed to SHOW an empty synthetic disk and propose
a layout in memory. It MUST NOT execute Calamares jobs or write any disk.
Actual Q4OS installation or Windows partitioning is NOT authorized here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets" / "live"))
sys.path.insert(0, str(ROOT / "auto_tests" / "tools"))

from gaslux_q4os_guest_disk_probe import expected_virtio_serial  # noqa: E402
from gaslux_q4os_qemu_identity_lab import (  # noqa: E402
    _fsync_directory,
    _fsync_file,
    _qemu_img_info,
    _verify_plan,
    _write_json_durable,
    sparse_content_sha256,
)
from gaslux_q4os_snapshot_recovery_lab import run_lab as snapshot_lab  # noqa: E402
from gaslux_q4os_vm_target_plan import DISK_BYTES  # noqa: E402
from gaslux_q4os_vm_target_plan_lab import run_lab as signed_plan_lab  # noqa: E402

OVERLAY = "q4os-native-calamares-view-only.qcow2"
SERIAL_FILE = "q4os-native-calamares-virtio-serial.txt"
AUDIT = "q4os-native-calamares-cow-view-audit.json"


class CalamaresCowViewRefusal(RuntimeError):
    """A signed Q4OS synthetic Calamares preview boundary failed."""


def require(ok: bool, message: str) -> None:
    if not ok:
        raise CalamaresCowViewRefusal(message)


def process(argv: list[str]) -> str:
    r = subprocess.run(argv, capture_output=True, text=True, timeout=180, check=False)
    require(r.returncode == 0, argv[0] + " failed: " + (r.stderr + r.stdout)[-900:])
    return r.stdout


def _owner_dir(path: Path) -> None:
    require(path.is_absolute() and path.is_dir() and not path.is_symlink(), "Unsafe VM path")
    data = path.stat()
    require(stat.S_ISDIR(data.st_mode) and data.st_uid == os.getuid(), "VM directory owner mismatch")
    require(data.st_mode & 0o077 == 0, "VM directory must have private permissions")


def _inputs(workspace: Path, plan_dir: Path, snapshot_dir: Path, evidence: Path) -> None:
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GASLUX_Q4OS_NATIVE_COW_VIEW_ONLY") == "yes",
        "Native Calamares COW view requires disposable Actions-only opt-in",
    )
    _owner_dir(workspace)
    require(workspace.name.startswith("gaslux-q4os-graphics-"), "Not a fresh Q4OS GUI workspace")
    for folder in (plan_dir, snapshot_dir, evidence):
        require(folder.is_absolute() and not folder.is_symlink(), "Unsafe evidence location")
        require(folder.parent.is_dir() and folder.parent.stat().st_uid == os.getuid(), "Foreign evidence parent")
        require(folder != workspace and folder != plan_dir if folder == snapshot_dir else True,
                "Evidence and snapshot cannot collide")
    require(plan_dir != snapshot_dir and evidence not in (plan_dir, snapshot_dir),
            "Recovery artifact destinations overlap")
    require(
        (workspace / "efi-disk.img").is_file()
        and not (workspace / "efi-disk.img").is_symlink(),
        "No transaction-owned synthetic base GPT",
    )


def prepare(workspace: Path, plan_dir: Path, snapshot_dir: Path, evidence: Path) -> dict:
    _inputs(workspace, plan_dir, snapshot_dir, evidence)
    require(
        all(not p.exists() and not p.is_symlink() for p in
            (plan_dir, snapshot_dir, workspace / OVERLAY, workspace / SERIAL_FILE)),
        "Refuse preexisting signed plan, snapshot or overlay",
    )
    _owner_dir(evidence)
    base = workspace / "efi-disk.img"
    before = sparse_content_sha256(base)
    plan_result = signed_plan_lab(workspace, plan_dir, run_id="q4os-actions-" + os.environ["GITHUB_RUN_ID"])
    require(plan_result["installationAuthorized"] is False, "Unexpected installed-write authority")
    snapshot_result = snapshot_lab(workspace, plan_dir, snapshot_dir)
    require(snapshot_result["restoreCompareVerified"] is True, "No independently restored checkpoint")
    plan, raw, verification = _verify_plan(workspace, plan_dir)
    require(verification["gptMetadataVerified"] is True, "Invalid signed GPT")
    require(plan["installationAuthorized"] is False and plan["calamaresJobsAuthorized"] is False,
            "Signed target unexpectedly permits native job execution")
    serial = expected_virtio_serial(plan)
    (workspace / SERIAL_FILE).write_text(serial + "\n", encoding="ascii")
    _fsync_file(workspace / SERIAL_FILE)
    overlay = workspace / OVERLAY
    process([
        "qemu-img", "create", "-f", "qcow2", "-F", "raw",
        "-b", str(base), str(overlay),
    ])
    info = _qemu_img_info(overlay)
    require(
        info.get("format") == "qcow2"
        and info.get("backing-filename") == str(base)
        and info.get("backing-filename-format") == "raw"
        and info.get("virtual-size") == DISK_BYTES,
        "Unknown QEMU Calamares preview overlay backing chain",
    )
    _fsync_file(overlay)
    _fsync_directory(workspace)
    base_after = sparse_content_sha256(base)
    require(before == base_after, "Backing changed while preparing recoverable COW")
    report = {
        "schemaVersion": 1,
        "distributionId": "q4os",
        "operation": "native-calamares-synthetic-cow-partition-view-only",
        "runId": plan["runId"],
        "planSha256": hashlib.sha256(raw).hexdigest(),
        "virtioSerial": serial,
        "baseSparseSha256": before,
        "selfContainedSnapshotVerified": True,
        "snapshotRestoredAndCompared": True,
        "guestVisibleSerialVerifiedInLive": False,
        "calamaresPagesViewed": False,
        "partitionChoiceSelectedInMemory": False,
        "calamaresJobsExecuted": False,
        "linuxRootPartitionCreated": False,
        "installationAuthorized": False,
        "windowsDiskAttached": False,
        "windowsEspWritesAuthorized": False,
        "guestDiskWritesAuthorized": False,
        "rollbackVerified": False,
    }
    _write_json_durable(evidence / AUDIT, report)
    print("GASLUX_Q4OS_NATIVE_COW_SIGNED_CHECKPOINT=PASS", flush=True)
    print("GASLUX_Q4OS_NATIVE_COW_INSTALLATION_AUTHORIZED=NO", flush=True)
    return report


def verify(workspace: Path, plan_dir: Path, snapshot_dir: Path, evidence: Path) -> dict:
    _inputs(workspace, plan_dir, snapshot_dir, evidence)
    for folder in (plan_dir, snapshot_dir, evidence):
        _owner_dir(folder)
    base = workspace / "efi-disk.img"
    overlay = workspace / OVERLAY
    require(overlay.is_file() and not overlay.is_symlink(), "Missing owned COW file")
    raw_audit = (evidence / AUDIT).read_bytes()
    report = json.loads(raw_audit)
    require(
        report["operation"] == "native-calamares-synthetic-cow-partition-view-only"
        and report["installationAuthorized"] is False,
        "Foreign or mutable Calamares preview checkpoint",
    )
    plan, raw_plan, verification = _verify_plan(workspace, plan_dir)
    require(verification["signatureVerified"] is True, "Signed plan cannot be reverified")
    require(hashlib.sha256(raw_plan).hexdigest() == report["planSha256"],
            "Signed plan changed across native Calamares GUI session")
    require(sparse_content_sha256(base) == report["baseSparseSha256"],
            "Guest changed backing image instead of exclusively owned overlay")
    process(["qemu-img", "check", str(overlay)])
    process([
        "qemu-img", "compare", "-f", "qcow2", "-F", "raw",
        str(overlay), str(base),
    ])
    # Selecting a radio-button is never storage authorization. If Calamares
    # wrote anything during this preview, compare exits 1 and we fail hard.
    snapshot = snapshot_dir / "q4os-recovery-snapshot.qcow2"
    require(snapshot.is_file() and not snapshot.is_symlink(), "Missing self-contained recovery")
    process([
        "qemu-img", "compare", "-f", "qcow2", "-F", "raw", str(snapshot), str(base)
    ])
    require(
        plan["installationAuthorized"] is False
        and plan["calamaresJobsAuthorized"] is False
        and plan["windowsEspWritesAuthorized"] is False,
        "Calamares or Windows writes unexpectedly authorized",
    )
    overlay.unlink()
    _fsync_directory(workspace)
    require(not overlay.exists() and sparse_content_sha256(base) == report["baseSparseSha256"],
            "Guest overlay discard failed to preserve original GPT")
    report.update({
        "calamaresPagesViewed": True,
        "partitionChoiceSelectedInMemory": True,
        "guestCOWUnchanged": True,
        "originalSignedBaseUnchanged": True,
        "recoverySnapshotStillMatchesBase": True,
        "overlayDiscarded": True,
        "installationAuthorized": False,
        "calamaresJobsExecuted": False,
        "windowsDiskAttached": False,
        "rollbackVerified": False,
    })
    _write_json_durable(evidence / AUDIT, report)
    print("GASLUX_Q4OS_NATIVE_COW_PREVIEW_NO_WRITES=PASS", flush=True)
    print("GASLUX_Q4OS_NATIVE_COW_SNAPSHOT_BASE_REVALIDATED=PASS", flush=True)
    print("GASLUX_Q4OS_NATIVE_CALAMARES_INSTALLATION=NOT_EXECUTED", flush=True)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["prepare", "verify"])
    parser.add_argument("workspace", type=Path)
    parser.add_argument("plan_dir", type=Path)
    parser.add_argument("snapshot_dir", type=Path)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "prepare":
            prepare(args.workspace, args.plan_dir, args.snapshot_dir, args.evidence)
        else:
            verify(args.workspace, args.plan_dir, args.snapshot_dir, args.evidence)
    except (CalamaresCowViewRefusal, ValueError, OSError, subprocess.SubprocessError) as exc:
        print("GASLUX_Q4OS_NATIVE_COW_VIEW_REFUSED=" + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
