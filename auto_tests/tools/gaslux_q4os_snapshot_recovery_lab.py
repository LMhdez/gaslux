"""Create, restore and verify a self-contained synthetic Q4OS snapshot; host-only writes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets" / "live"))

from gaslux_q4os_qemu_identity_lab import (  # noqa: E402
    DISK_BYTES,
    Q4osQemuLabRefusal,
    _fsync_directory,
    _fsync_then_chmod,
    _verify_plan,
    sparse_content_sha256,
)
from gaslux_q4os_snapshot_manifest import (  # noqa: E402
    RESTORE_NAME,
    SNAPSHOT_NAME,
    Q4osSnapshotRecoveryRefusal,
    canonical_manifest,
    sign_manifest,
    verify_signed_manifest,
)
from gaslux_q4os_vm_target_plan import Q4osPlanRefusal  # noqa: E402
from q4os_guest_identity_agent import GuestProbeError, inspect_gpt_fd  # noqa: E402

ESP_TYPE_GUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"


class Q4osSnapshotLabRefusal(RuntimeError):
    """Raised when the host-only snapshot and restore rehearsal is unsafe."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise Q4osSnapshotLabRefusal(reason)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: list[str], *, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise Q4osSnapshotLabRefusal(
            f"Snapshot lab command failed: {Path(command[0]).name}: {exc}"
        ) from exc


def _write_bytes_durable(path: Path, payload: bytes, mode: int = 0o600) -> None:
    temporary = path.with_name(path.name + ".tmp")
    _require(not path.exists() and not path.is_symlink(), "Evidence file already exists")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(fd)
        os.chmod(temporary, mode)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def verify_restored_gpt(plan: dict[str, Any], gpt: dict[str, Any]) -> dict[str, Any]:
    _require(gpt.get("diskGuid") == plan["diskGuid"], "Restored disk GUID mismatch")
    partitions = gpt.get("partitions")
    _require(
        isinstance(partitions, list) and len(partitions) == 1,
        "Restored partition count mismatch",
    )
    esp = partitions[0]
    expected = {
        "number": 1,
        "startLba": plan["espStartLba"],
        "endLba": plan["espEndLba"],
        "typeGuid": ESP_TYPE_GUID,
        "partGuid": plan["espGuid"],
        "label": plan["espName"],
        "filesystem": "vfat",
    }
    _require(esp == expected, "Restored ESP identity or geometry mismatch")
    return {
        "restoredDiskGuid": gpt["diskGuid"],
        "restoredEspGuid": esp["partGuid"],
        "restoredEspStartLba": esp["startLba"],
        "restoredEspEndLba": esp["endLba"],
        "restoredEspLabel": esp["label"],
    }


def run_lab(workspace: Path, plan_dir: Path, evidence: Path) -> dict[str, Any]:
    _require(
        os.environ.get("GITHUB_ACTIONS") == "true",
        "Snapshot lab is restricted to GitHub Actions",
    )
    _require(
        workspace.is_absolute() and workspace.is_dir() and not workspace.is_symlink(),
        "Unsafe workspace",
    )
    _require(
        plan_dir.is_absolute() and plan_dir.is_dir() and not plan_dir.is_symlink(),
        "Unsafe signed-plan directory",
    )
    _require(workspace.stat().st_uid == os.getuid(), "Workspace is not runner-owned")
    _require(plan_dir.stat().st_uid == os.getuid(), "Plan directory is not runner-owned")
    _require(
        not evidence.exists() and not evidence.is_symlink(),
        "Evidence directory already exists",
    )
    evidence.mkdir(mode=0o700)
    disk = workspace / "efi-disk.img"
    snapshot = evidence / SNAPSHOT_NAME
    restored = workspace / RESTORE_NAME

    try:
        plan, raw_plan, verification = _verify_plan(workspace, plan_dir)
        _require(
            verification.get("signatureVerified") is True,
            "Signed target plan is not verified",
        )
        _require(verification.get("gptMetadataVerified") is True, "Target GPT is not verified")
        _require(
            plan.get("installationAuthorized") is False,
            "Installation authority must remain false",
        )
        _require(
            plan.get("calamaresJobsAuthorized") is False,
            "Calamares authority must remain false",
        )
        _require(
            plan.get("windowsEspWritesAuthorized") is False,
            "Windows ESP write authority must remain false",
        )
        _require(plan.get("diskSizeBytes") == DISK_BYTES, "Unexpected target disk size")
        base_before = sparse_content_sha256(disk)
        _fsync_then_chmod(disk, 0o400)

        _run(
            [
                "qemu-img",
                "convert",
                "-f",
                "raw",
                "-O",
                "qcow2",
                "-c",
                "-S",
                "4k",
                str(disk),
                str(snapshot),
            ],
            timeout=600,
        )
        info = json.loads(
            _run(["qemu-img", "info", "--output=json", str(snapshot)]).stdout
        )
        _require(info.get("format") == "qcow2", "Snapshot format mismatch")
        _require(info.get("virtual-size") == DISK_BYTES, "Snapshot virtual size mismatch")
        _require(info.get("backing-filename") in (None, ""), "Snapshot is not self-contained")
        _run(["qemu-img", "check", str(snapshot)], timeout=120)
        _fsync_then_chmod(snapshot, 0o400)
        _fsync_directory(evidence)
        snapshot_hash = _sha256_file(snapshot)
        snapshot_size = snapshot.stat().st_size
        _require(snapshot_size > 0, "Snapshot file is empty")

        _run(
            [
                "qemu-img",
                "convert",
                "-f",
                "qcow2",
                "-O",
                "raw",
                "-S",
                "4k",
                str(snapshot),
                str(restored),
            ],
            timeout=600,
        )
        _fsync_then_chmod(restored, 0o400)
        _fsync_directory(workspace)
        _run(
            [
                "qemu-img",
                "compare",
                "-f",
                "raw",
                "-F",
                "raw",
                str(disk),
                str(restored),
            ],
            timeout=600,
        )
        _run(["sgdisk", "--verify", str(restored)], timeout=60)
        restored_fd = os.open(restored, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            restored_gpt = inspect_gpt_fd(
                restored_fd, disk_size_bytes=DISK_BYTES, sector_bytes=512
            )
        except GuestProbeError as exc:
            raise Q4osSnapshotLabRefusal(
                "Restored GPT/FAT32 verification failed"
            ) from exc
        finally:
            os.close(restored_fd)
        restored_fields = verify_restored_gpt(plan, restored_gpt)
        base_after = sparse_content_sha256(disk)
        _require(base_before == base_after, "Original base image changed during snapshot/restore")
        _plan_after, raw_plan_after, verification_after = _verify_plan(workspace, plan_dir)
        _require(raw_plan_after == raw_plan, "Signed plan changed during snapshot/restore")
        _require(
            verification_after.get("signatureVerified") is True,
            "Signed plan revalidation failed",
        )
        _require(
            verification_after.get("gptMetadataVerified") is True,
            "Base GPT revalidation failed",
        )

        restored.unlink()
        _fsync_directory(workspace)
        _require(
            not restored.exists() and not restored.is_symlink(),
            "Restore scratch file was not removed",
        )
        _require(
            _sha256_file(snapshot) == snapshot_hash,
            "Snapshot changed after restore verification",
        )

        manifest: dict[str, Any] = {
            "schemaVersion": 1,
            "operation": "self-contained-read-only-snapshot",
            "runId": plan["runId"],
            "nonce": plan["nonce"],
            "planSha256": hashlib.sha256(raw_plan).hexdigest(),
            "snapshotFilename": SNAPSHOT_NAME,
            "snapshotSha256": snapshot_hash,
            "snapshotFileSizeBytes": snapshot_size,
            "snapshotFormat": "qcow2",
            "snapshotVirtualSizeBytes": DISK_BYTES,
            "snapshotBackingFile": None,
            "snapshotSelfContained": True,
            "snapshotIntegrityVerified": True,
            "snapshotDurableForRunnerJob": True,
            "snapshotArtifactPrepared": True,
            "artifactRetentionDays": 7,
            "restorePerformed": True,
            "restoreTargetFilename": RESTORE_NAME,
            "restoreTargetIsNewHostFile": True,
            "restoreCompareVerified": True,
            "restoredGptVerified": True,
            **restored_fields,
            "baseImageSparseSha256Before": base_before,
            "baseImageSparseSha256After": base_after,
            "baseImageUnchanged": True,
            "manifestSigned": True,
            "planSignatureVerified": True,
            "gptMetadataVerified": True,
            "guestBooted": False,
            "guestDiskWrites": False,
            "diskWritesAuthorized": False,
            "installationAuthorized": False,
            "calamaresJobsAuthorized": False,
            "windowsEspWritesAuthorized": False,
            "rollbackVerified": False,
        }
        private_key = Ed25519PrivateKey.generate()
        raw_manifest, signature, public_key, fingerprint = sign_manifest(
            manifest, private_key
        )
        verified = verify_signed_manifest(
            raw_manifest, signature, public_key, fingerprint
        )
        _require(verified == manifest, "Snapshot manifest signature self-check failed")
        _write_bytes_durable(
            evidence / "q4os-recovery-snapshot-manifest.json", raw_manifest
        )
        _write_bytes_durable(
            evidence / "q4os-recovery-snapshot-manifest.ed25519", signature
        )
        _write_bytes_durable(
            evidence / "q4os-recovery-snapshot-public-key.bin", public_key
        )
        _write_bytes_durable(
            evidence / "q4os-recovery-snapshot-public-key.sha256",
            (fingerprint + "\n").encode("ascii"),
        )
        _write_bytes_durable(
            evidence / "q4os-recovery-snapshot-verification.json",
            canonical_manifest(
                {
                    "manifestSignatureVerified": True,
                    "snapshotSha256Verified": True,
                    "restoreCompareVerified": True,
                    "restoredGptVerified": True,
                    "baseImageUnchanged": True,
                    "snapshotSelfContained": True,
                    "snapshotDurableForRunnerJob": True,
                    "snapshotArtifactPrepared": True,
                    "guestDiskWrites": False,
                    "diskWritesAuthorized": False,
                    "rollbackVerified": False,
                }
            ),
        )
        result = {
            "snapshotSha256": snapshot_hash,
            "snapshotFileSizeBytes": snapshot_size,
            "snapshotVirtualSizeBytes": DISK_BYTES,
            "snapshotSelfContained": True,
            "restoreCompareVerified": True,
            "restoredGptVerified": True,
            "baseImageUnchanged": True,
            "snapshotDurableForRunnerJob": True,
            "snapshotArtifactPrepared": True,
            "manifestSignatureVerified": True,
            "guestDiskWrites": False,
            "diskWritesAuthorized": False,
            "rollbackVerified": False,
        }
        print("GASLUX_Q4OS_SNAPSHOT=PASS")
        print("GASLUX_Q4OS_RESTORE_COMPARE=PASS")
        print("GASLUX_Q4OS_RESTORED_GPT=PASS")
        print("GASLUX_Q4OS_BASE_UNCHANGED=PASS")
        print("GASLUX_Q4OS_SNAPSHOT_SIGNATURE=PASS")
        print("GASLUX_Q4OS_GUEST_WRITES=FALSE")
        print("GASLUX_Q4OS_ROLLBACK_VERIFIED=FALSE")
        print(json.dumps(result, sort_keys=True))
        return result
    except (
        Q4osQemuLabRefusal,
        Q4osPlanRefusal,
        Q4osSnapshotRecoveryRefusal,
        OSError,
        ValueError,
        subprocess.SubprocessError,
    ) as exc:
        raise Q4osSnapshotLabRefusal(str(exc)) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("plan_dir", type=Path)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    try:
        run_lab(args.workspace, args.plan_dir, args.evidence)
    except Q4osSnapshotLabRefusal as exc:
        print(f"Q4OS snapshot recovery lab refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
