#!/usr/bin/env python3
"""Issue a second Ed25519 grant for one disposable Windows-backed COW root.

This host-only issuer never opens a block device. It binds the grant to the
verified Windows fourth boot, exact immutable QCOW2 backing file, fifth ext4
PARTUUID/UUID, signed read-only plan, and hashes of every guest program.
The grant authorizes pacstrap ONLY in a GitHub-hosted disposable QEMU overlay.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Any

from cachyos_windows_shared_archiso_handoff import (
    SharedDiskHandoffRejected, canonical, validate_plan,
)
from cachyos_windows_cow_checkpoint import (
    CHECKPOINT_DIR, OVERLAY_NAME, sha256_file,
)
from cachyos_windows_overlay_reboot import (
    audit_complete_third_serial, gpt_windows,
)
from windows_cachyos_qcow2_gpt_readonly import (
    VIRTUAL_BYTES, qcow2_file_identity,
)
from cachyos_windows_archiso_signed_plan_lab import read_windows_file_hashes

CONSENT = "I_ACCEPT_CACHYOS_SHARED_ROOT_PACSTRAP_ON_DISPOSABLE_WINDOWS_COW"
BASE_NAME = "only-disposable-windows-target.qcow2"
NVARS_NAME = "ovmf-variables.fd"
GRANT_NAME = "root-write-grant.json"
SIGNATURE_NAME = "root-write-grant.sig"

PROGRAM_FIELDS = {
    "cachyos_windows_shared_root_pacstrap.py": "sharedRootPacstrapSha256",
    "cachyos_windows_shared_archiso_handoff.py": "archisoHandoffVerifierSha256",
    "cachyos_windows_shared_archiso_guest_probe.py": "archisoGuestProbeSha256",
    "windows_cachyos_qcow2_gpt_readonly.py": "gptReaderSha256",
    "strict-pacman.py": "strictPacmanBuilderSha256",
    "pacman-trust.py": "pacmanTrustGuardSha256",
    "gaslux-install.sh": "guestInstallScriptSha256",
    "gaslux-launch.sh": "guestLaunchScriptSha256",
}


class GrantIssueError(ValueError):
    """A host checkpoint or root-write grant cannot be authenticated."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise GrantIssueError(reason)


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_digest(document: dict[str, Any]) -> tuple[bytes, str]:
    raw = canonical(document)
    return raw, sha_bytes(raw)


def _run(argv: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv, capture_output=True, text=True, check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise GrantIssueError("host proof command unavailable: " + argv[0]) from error


def _owned_regular(path: Path, parent: Path, name: str, mode: int | None = None) -> os.stat_result:
    require(path.parent == parent and path.name == name and
            not path.is_symlink() and path.is_file(),
            "foreign or redirected host checkpoint file: " + name)
    item = path.lstat()
    require(stat.S_ISREG(item.st_mode) and item.st_uid == os.getuid()
            and item.st_nlink == 1 and item.st_size > 0,
            "checkpoint is not an exclusive owned regular file: " + name)
    if mode is not None:
        require(stat.S_IMODE(item.st_mode) == mode,
                "unexpected checkpoint permissions: " + name)
    return item


def _qemu_info(path: Path) -> dict[str, Any]:
    result = _run(["qemu-img", "info", "-f", "qcow2", "--output=json", str(path)])
    require(result.returncode == 0 and len(result.stdout) < 32768,
            "qemu-img could not inspect owned QCOW2")
    try:
        value = json.loads(result.stdout)
    except ValueError as error:
        raise GrantIssueError("qemu-img returned invalid JSON") from error
    require(type(value) is dict, "qemu-img info is not an object")
    return value


def _qemu_check(path: Path) -> str:
    result = _run(["qemu-img", "check", "-f", "qcow2", str(path)], timeout=300)
    output = (result.stdout + "\n" + result.stderr).strip()
    require(result.returncode == 0 and len(output) < 32768
            and "No errors were found" in output,
            "QCOW2 consistency check failed")
    return output


def _verify_plan_signature(plan_path: Path, signature_path: Path,
                            public_key: Path, private_key: Path) -> dict[str, Any]:
    raw = plan_path.read_bytes()
    require(0 < len(raw) <= 16384 and raw.endswith(b"\n"),
            "signed plan missing or oversized")
    try:
        plan = json.loads(raw)
    except ValueError as error:
        raise GrantIssueError("invalid signed plan JSON") from error
    require(type(plan) is dict and canonical(plan) == raw,
            "signed plan is not canonical")
    validate_plan(plan)
    _owned_regular(plan_path, plan_path.parent, "plan.json")
    _owned_regular(signature_path, signature_path.parent, "plan.sig")
    _owned_regular(public_key, public_key.parent, "public.pem")
    _owned_regular(private_key, private_key.parent, "private.pem", 0o600)
    require(signature_path.stat().st_size == 64,
            "plan Ed25519 signature has invalid length")
    verify = _run([
        "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
        "-sigfile", str(signature_path), "-rawin", "-in", str(plan_path),
    ], timeout=20)
    require(verify.returncode == 0, "host rejected the signed plan")
    pub_from_private = _run([
        "openssl", "pkey", "-in", str(private_key), "-pubout", "-outform", "DER",
    ], timeout=20)
    pub_der = _run([
        "openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER",
    ], timeout=20)
    require(pub_from_private.returncode == 0 and pub_der.returncode == 0
            and pub_from_private.stdout == pub_der.stdout,
            "ephemeral Ed25519 private/public key pair does not match")
    return plan


def _validate_windows_evidence(
    plan: dict[str, Any], geometry: dict[str, Any], checkpoint: dict[str, Any],
    staged: dict[str, Any], third: dict[str, Any], ext4: dict[str, Any],
    fourth: dict[str, Any], fourth_serial: Path,
) -> str:
    require(all(type(value) is dict for value in
                (geometry, checkpoint, staged, third, ext4, fourth)),
            "missing structured Windows/COW evidence")
    require(
        geometry.get("candidateWindowsGptPrimaryAndBackupConsistent") is True
        and len(geometry.get("windowsPartitions", [])) == 4
        and geometry.get("storageWritesAuthorized") is False
        and checkpoint.get("candidateWindowsCowCheckpointPrepared") is True
        and checkpoint.get("trialOverlayInitiallyMatchesWindows") is True
        and checkpoint.get("windowsBaselineUnchangedDuringCheckpoint") is True
        and checkpoint.get("snapshotIndependentlyRestorable") is False
        and staged.get("overlayGptLinuxRootEntryPrepared") is True
        and staged.get("onlyDisposableOverlayModified") is True
        and staged.get("windowsPartitionEntriesUnchanged") is True
        and staged.get("bothGptMirrorsAfterStageVerified") is True
        and staged.get("windowsBackingQcow2Unchanged") is True
        and staged.get("windowsUefiVariablesUnchanged") is True
        and staged.get("linuxRoot", {}).get("index") == 5
        and ext4.get("onlyOwnedOverlayFifthPartitionFormatted") is True
        and ext4.get("linuxRootFilesystemFormatted") is True
        and ext4.get("rootFilesystem", {}).get("filesystemType") == "ext4"
        and ext4.get("rootFilesystem", {}).get("allFourWindowsPartitionSha256Unchanged") is True
        and ext4.get("windowsBackingQcow2UnchangedAfterExt4") is True
        and ext4.get("windowsOriginalUefiUnchangedAfterExt4") is True
        and fourth.get("windowsBootAfterExt4Verified") is True
        and fourth.get("windowsBcdWinreEspAfterExt4Verified") is True
        and fourth.get("fourthGuestCleanShutdownVerified") is True
        and fourth.get("fifthExt4UuidSurvivedWindowsBoot") is True
        and fourth.get("windowsGptUnchangedAfterExt4Boot") is True
        and fourth.get("windowsBackingUnchangedAfterExt4Boot") is True
        and fourth.get("originalWindowsUefiUnchangedAfterExt4Boot") is True,
        "host grant requires the real fourth Windows boot and exact ext4 proof",
    )
    for proof in (geometry, checkpoint, staged, third, ext4, fourth):
        require(proof.get("cachyosInstalled", False) is False
                and proof.get("sameDiskDualBootVerified", False) is False
                and proof.get("storageWritesAuthorized", False) is False
                and proof.get("releaseEligible", False) is False,
                "upstream evidence falsely claims an installation or production authority")
    require(fourth.get("windowsRecoveryAfterLinuxVerified") is False
            and fourth.get("rollbackProven") is False,
            "Windows recovery/rollback must remain unclaimed")
    require(fourth_serial.is_file() and not fourth_serial.is_symlink()
            and fourth_serial.stat().st_size <= 512_000,
            "missing or oversized fourth Windows COM1 witness")
    digest = audit_complete_third_serial(fourth_serial)
    require(digest == fourth.get("fourthGuestSerialSha256"),
            "fourth Windows COM1 does not match the shutdown witness")
    require(plan["partitions"][4]["uniqueGuid"] ==
            staged["linuxRoot"]["uniqueGuid"]
            and plan["rootFsUuid"] ==
            ext4["rootFilesystem"]["filesystemUuid"],
            "signed plan differs from staged fifth ext4 identity")
    return digest


def issue_root_write_grant(
    *,
    plan_path: Path,
    plan_signature: Path,
    public_key: Path,
    private_key: Path,
    base: Path,
    overlay: Path,
    nvram: Path,
    workspace: Path,
    geometry: dict[str, Any],
    checkpoint: dict[str, Any],
    staged: dict[str, Any],
    third: dict[str, Any],
    ext4: dict[str, Any],
    fourth: dict[str, Any],
    fourth_serial: Path,
    programs: dict[str, Path],
) -> dict[str, Any]:
    """Create and sign a strict, single-root, disposable COW grant."""
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("GASLUX_CACHYOS_SHARED_ROOT_PACSTRAP_CONSENT") == CONSENT,
        "explicit hosted GitHub Windows-COW pacstrap consent required",
    )
    runner_temp = Path(os.environ.get("RUNNER_TEMP", ""))
    require(runner_temp.is_absolute() and runner_temp.is_dir()
            and not runner_temp.is_symlink() and runner_temp.resolve() == runner_temp
            and base.parent.parent == runner_temp
            and base.parent.name.startswith("gaslux-win-x64-")
            and base.parent.is_dir() and not base.parent.is_symlink()
            and base.parent.stat().st_uid == os.getuid()
            and stat.S_IMODE(base.parent.stat().st_mode) == 0o700,
            "Windows QCOW2 is not in a private hosted-runner workspace")
    require(workspace.is_absolute() and workspace.is_dir()
            and not workspace.is_symlink() and workspace.resolve() == workspace
            and workspace.parent == base.parent
            and stat.S_IMODE(workspace.stat().st_mode) == 0o700,
            "handoff workspace is not private and transaction-local")
    checkpoint_dir = base.parent / CHECKPOINT_DIR
    require(overlay.parent == checkpoint_dir and checkpoint_dir.is_dir()
            and not checkpoint_dir.is_symlink()
            and checkpoint_dir.stat().st_uid == os.getuid()
            and stat.S_IMODE(checkpoint_dir.stat().st_mode) == 0o700,
            "overlay does not belong to the private Windows COW checkpoint")
    base_stat = _owned_regular(base, base.parent, BASE_NAME, 0o400)
    overlay_stat = _owned_regular(overlay, checkpoint_dir, OVERLAY_NAME, 0o600)
    _owned_regular(nvram, base.parent, NVARS_NAME)
    baseline_vars = checkpoint_dir / "windows-ovmf-baseline.fd"
    _owned_regular(baseline_vars, checkpoint_dir, baseline_vars.name, 0o400)
    require(programs.keys() == PROGRAM_FIELDS.keys(),
            "guest program manifest is incomplete or has unexpected entries")
    program_hashes: dict[str, str] = {}
    for name, path in programs.items():
        require(path.is_file() and not path.is_symlink()
                and path.stat().st_size > 100
                and path.stat().st_size < 2 * 1024 * 1024,
                "missing or unexpected guest program: " + name)
        program_hashes[PROGRAM_FIELDS[name]] = sha256_file(path)

    plan = _verify_plan_signature(plan_path, plan_signature, public_key, private_key)
    require(plan["labOnly"] is True and plan["writeAuthority"] is False
            and plan["targetVirtioSerial"] == "GASLUXWINDOWSCOWLAB"
            and plan["diskVirtualBytes"] == VIRTUAL_BYTES,
            "only the inert signed Windows-COW lab plan can be extended")
    fourth_digest = _validate_windows_evidence(
        plan, geometry, checkpoint, staged, third, ext4, fourth, fourth_serial,
    )
    require(plan["rootFsUuid"] == ext4["rootFilesystem"]["filesystemUuid"]
            and plan["partitions"][4]["uniqueGuid"] ==
                staged["linuxRoot"]["uniqueGuid"],
            "signed root UUID/PARTUUID does not match the fifth ext4 partition")

    base_info = _qemu_info(base)
    overlay_info = _qemu_info(overlay)
    require(base_info.get("format") == "qcow2"
            and base_info.get("virtual-size") == VIRTUAL_BYTES
            and not base_info.get("backing-filename")
            and not base_info.get("full-backing-filename")
            and not base_info.get("encrypted", False),
            "Windows source image is not a standalone pinned QCOW2")
    require(overlay_info.get("format") == "qcow2"
            and overlay_info.get("virtual-size") == VIRTUAL_BYTES
            and overlay_info.get("backing-filename") == str(base)
            and overlay_info.get("backing-filename-format") == "qcow2"
            and not overlay_info.get("encrypted", False),
            "trial overlay does not have the exact protected Windows backing")
    base_identity = qcow2_file_identity(base)
    overlay_identity = qcow2_file_identity(overlay)
    base_sha = sha256_file(base)
    nvram_sha = sha256_file(nvram)
    vars_sha = sha256_file(baseline_vars)
    require(vars_sha == checkpoint.get("uefiVarsCopySha256")
            and nvram_sha == vars_sha,
            "Windows OVMF baseline differs from the protected checkpoint")
    check_output = _qemu_check(overlay)
    require(_qemu_info(base) == base_info and _qemu_info(overlay) == overlay_info
            and qcow2_file_identity(base) == base_identity
            and qcow2_file_identity(overlay) == overlay_identity
            and sha256_file(base) == base_sha
            and sha256_file(nvram) == nvram_sha,
            "QCOW2 or Windows UEFI changed during host backing verification")

    with tempfile.TemporaryDirectory(prefix="gaslux-root-grant-gpt-",
                                     dir=base.parent) as tmp:
        front, back = gpt_windows(overlay, Path(tmp))
    require(sha_bytes(front + back) == plan["gptWindowsSha256"],
            "overlay GPT bytes differ from the signed plan")
    observed_windows = read_windows_file_hashes(overlay)
    require(observed_windows == plan["windowsHashes"],
            "Windows ESP/BCD/loader/WinRE hashes differ from signed plan")
    require(sha256_file(base) == base_sha
            and qcow2_file_identity(base) == base_identity,
            "Windows backing changed during protected file verification")

    checkpoint_doc = {
        "schemaVersion": 1,
        "runId": plan["runId"],
        "bootNonce": plan["bootNonce"],
        "checkpointStrategy": "readonly-windows-base-plus-discardable-external-qcow2-overlay",
        "windowsBaseSha256": base_sha,
        "windowsBaseFileIdentity": list(base_identity),
        "originalOvmfVariablesSha256": nvram_sha,
        "baselineOvmfVariablesSha256": vars_sha,
        "windowsGeometryEvidenceSha256": canonical_digest(geometry)[1],
        "cowCheckpointEvidenceSha256": canonical_digest(checkpoint)[1],
        "fifthGptStageEvidenceSha256": canonical_digest(staged)[1],
        "thirdWindowsBootEvidenceSha256": canonical_digest(third)[1],
        "fifthExt4EvidenceSha256": canonical_digest(ext4)[1],
        "fourthWindowsBootEvidenceSha256": canonical_digest(fourth)[1],
        "fourthWindowsSerialSha256": fourth_digest,
        "windowsPartitionFileHashes": plan["windowsHashes"],
        "snapshotIndependentlyRestorable": False,
        "overlayDiscardAndWindowsBaselineRebootRequired": True,
        "windowsRecoveryAfterLinuxVerified": False,
        "productionRollbackVerified": False,
    }
    checkpoint_bytes, checkpoint_sha = canonical_digest(checkpoint_doc)
    overlay_doc = {
        "schemaVersion": 1,
        "runId": plan["runId"],
        "base": {
            "name": base.name, "sha256": base_sha,
            "device": base_stat.st_dev, "inode": base_stat.st_ino,
            "sizeBytes": base_stat.st_size, "mode": stat.S_IMODE(base_stat.st_mode),
            "readonly": True,
        },
        "overlay": {
            "name": overlay.name, "device": overlay_stat.st_dev,
            "inode": overlay_stat.st_ino, "sizeBytes": overlay_stat.st_size,
            "mode": stat.S_IMODE(overlay_stat.st_mode),
            "backingFilename": overlay_info["backing-filename"],
            "backingFormat": overlay_info["backing-filename-format"],
            "virtualSizeBytes": overlay_info["virtual-size"],
        },
        "qemuImgBaseInfoSha256": sha_bytes(canonical(base_info)),
        "qemuImgOverlayInfoSha256": sha_bytes(canonical(overlay_info)),
        "qemuImgCheckSha256": sha_bytes(check_output.encode("utf-8")),
        "overlayBackingChainVerified": True,
        "overlayDiscardable": True,
        "onlyTrialOverlayMayBeGuestWritable": True,
        "windowsBaseSha256Rechecked": True,
        "windowsEspWritesAllowed": False,
    }
    overlay_bytes, overlay_sha = canonical_digest(overlay_doc)
    grant = {
        "schemaVersion": 1,
        "labOnly": True,
        "operation": "pacstrap-only-preexisting-fifth-ext4",
        "runId": plan["runId"],
        "bootNonce": plan["bootNonce"],
        "signedPlanSha256": sha256_file(plan_path),
        "targetVirtioSerial": plan["targetVirtioSerial"],
        "rootPartuuid": plan["partitions"][4]["uniqueGuid"],
        "rootFsUuid": plan["rootFsUuid"],
        "sourceWindowsGptSha256": plan["gptWindowsSha256"],
        "hostCheckpointSha256": checkpoint_sha,
        "hostOverlayBackingProofSha256": overlay_sha,
        "sourceImageReadOnly": True,
        "discardableOverlay": True,
        "windowsEspWritesAllowed": False,
        **program_hashes,
    }
    grant_path = workspace / GRANT_NAME
    signature_path = workspace / SIGNATURE_NAME
    checkpoint_path = workspace / "host-checkpoint.json"
    overlay_path = workspace / "host-overlay-backing-proof.json"
    for path in (grant_path, signature_path, checkpoint_path, overlay_path):
        require(not path.exists() and not path.is_symlink(),
                "refusing to reuse a host grant artifact")
    checkpoint_path.write_bytes(checkpoint_bytes)
    overlay_path.write_bytes(overlay_bytes)
    grant_path.write_bytes(canonical(grant))
    for path in (checkpoint_path, overlay_path, grant_path):
        os.chmod(path, 0o600)
    sign = _run([
        "openssl", "pkeyutl", "-sign", "-inkey", str(private_key),
        "-rawin", "-in", str(grant_path), "-out", str(signature_path),
    ], timeout=20)
    require(sign.returncode == 0 and signature_path.is_file()
            and not signature_path.is_symlink()
            and signature_path.stat().st_size == 64,
            "could not sign the exact host root-write grant")
    os.chmod(signature_path, 0o600)
    verify = _run([
        "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
        "-sigfile", str(signature_path), "-rawin", "-in", str(grant_path),
    ], timeout=20)
    require(verify.returncode == 0,
            "new Ed25519 root-write grant did not verify")
    require(sha256_file(base) == base_sha
            and qcow2_file_identity(base) == base_identity
            and sha256_file(nvram) == nvram_sha,
            "Windows base or firmware changed while issuing the root grant")
    return {
        "rootWriteGrantIssued": True,
        "rootWriteGrantSha256": sha256_file(grant_path),
        "rootWriteGrantSignatureSha256": sha256_file(signature_path),
        "hostCheckpointSha256": checkpoint_sha,
        "hostOverlayBackingProofSha256": overlay_sha,
        "signedPlanSha256": sha256_file(plan_path),
        "fourthWindowsBootSerialSha256": fourth_digest,
        "windowsBaseSha256": base_sha,
        "windowsUefiBaselineSha256": nvram_sha,
        "sourceImageReadOnly": True,
        "discardableOverlay": True,
        "windowsEspWritesAllowed": False,
        "pacstrapExecuted": False,
        "productionStorageWritesAuthorized": False,
        "sameDiskDualBootVerified": False,
        "releaseEligible": False,
    }


if __name__ == "__main__":
    raise SystemExit("Library only: never signs a production or physical-disk grant.")
