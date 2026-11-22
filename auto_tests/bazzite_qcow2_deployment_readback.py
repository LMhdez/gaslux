"""Bazzite detached QCOW2 byte readback, without deployment authority.

Consumes an already-open regular-file O_RDONLY descriptor, NEVER a pathname,
guest report, self-attestation, subprocess, QEMU launcher or disk writer.
Reads QCOW2 host bytes, NOT virtual disk sectors. No GPT or filesystem proof
can follow from the header, QMP JSON, OSTree path or RPM claim alone.
The shared Safety/Integrator authenticated destination contract is missing.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import stat
import struct
from pathlib import Path

from bazzite_deployment_provenance_boundary import BOOTC_SHA256, OCI_MANIFEST

MAX_HEADER_READ = 1024 * 1024
MAX_HASH_READ = 16 * 1024**3
MAX_VIRTUAL_BYTES = 64 * 1024**4
MAX_CLAIM = 32 * 1024
QCOW_MAGIC = b"QFI\xfb"
NO_WRITE = (
    "installationAuthorized",
    "partitionWriteAuthorized",
    "guestCommandChannelAuthorized",
    "gptMetadataWriteAuthorized",
    "windowsEspWriteAuthorized",
    "nvramWriteAuthorized",
    "nativeInstallationVerified",
    "sameDiskDualBootVerified",
    "rollbackProven",
    "stable",
)


class Refusal(ValueError):
    """No promotion to deployment, boot, recovery or source identity."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise Refusal(reason)


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _bytes(fd: int, count: int, start: int) -> bytes:
    _require(0 <= start <= MAX_HEADER_READ, "INVALID_QCOW2_OFFSET")
    _require(0 <= count <= MAX_HEADER_READ - start, "UNBOUNDED_QCOW2_HEADER_READ")
    data = os.pread(fd, count, start)
    _require(len(data) == count, "TRUNCATED_QCOW2_HEADER")
    return data


def inspect_qcow2_fd(fd: int) -> dict:
    """Measure the actual open FD; output is local bytes, not trusted provenance.

    No path reopens and no QEMU. Caller supplies and owns a pinned descriptor.
    The caller cannot establish independent ownership simply by invoking us.
    """
    _require(os.name == "posix" and type(fd) is int and fd >= 0, "FD_INVALID")
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        _require((flags & os.O_ACCMODE) == os.O_RDONLY, "FD_NOT_READONLY")
        _require(not flags & getattr(os, "O_PATH", 0), "FD_IS_O_PATH")
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "FD_NOT_OWNABLE")
        _require(104 <= before.st_size <= MAX_HASH_READ, "QCOW2_SIZE_OUT_OF_BOUNDS")
        header = _bytes(fd, 104, 0)
        _require(header[:4] == QCOW_MAGIC, "FOREIGN_OR_RAW_IMAGE")
        version = struct.unpack_from(">I", header, 4)[0]
        _require(version in (2, 3), "UNSUPPORTED_QCOW2_VERSION")
        backing_offset = struct.unpack_from(">Q", header, 8)[0]
        backing_len = struct.unpack_from(">I", header, 16)[0]
        bits = struct.unpack_from(">I", header, 20)[0]
        virtual = struct.unpack_from(">Q", header, 24)[0]
        crypt = struct.unpack_from(">I", header, 32)[0]
        snapshot_count = struct.unpack_from(">I", header, 60)[0]
        _require(9 <= bits <= 21, "UNSUPPORTED_QCOW2_CLUSTER_BITS")
        _require(virtual >= 34 * 512 and virtual <= MAX_VIRTUAL_BYTES, "INVALID_VIRTUAL_SIZE")
        _require(crypt == 0, "ENCRYPTED_QCOW2_UNSUPPORTED")
        _require(snapshot_count == 0, "QCOW2_INTERNAL_SNAPSHOTS_UNVERIFIED")
        if version == 3:
            incompatible, _compatible, autoclear, _order, head_len = struct.unpack_from(
                ">QQQII", header, 72
            )
            _require(incompatible == 0 and autoclear == 0, "QCOW2_FEATURES_UNVERIFIED")
            _require(head_len == 104, "QCOW2_EXTENDED_HEADER_UNVERIFIED")
        else:
            # V2 does not define the v3 header extensions or feature flags.
            head_len = 72
        _require(backing_len == 0 and backing_offset == 0, "QCOW2_BACKING_UNVERIFIED")
        _require(head_len <= 1 << bits, "QCOW2_HEADER_LARGER_THAN_CLUSTER")
        _require(
            all(
                struct.unpack_from(">Q", header, pos)[0] < before.st_size
                for pos in (40, 48)
                if struct.unpack_from(">Q", header, pos)[0] != 0
            ),
            "QCOW2_INTERNAL_TABLE_OUTSIDE_IMAGE",
        )
        _require(before.st_size <= MAX_HASH_READ, "QCOW2_HASH_BUDGET_EXCEEDED")
        digest = hashlib.sha256()
        done = 0
        while done < before.st_size:
            data = os.pread(fd, min(1024 * 1024, before.st_size - done), done)
            _require(bool(data), "SHORT_READ_QCOW2_HASH")
            done += len(data)
            digest.update(data)
        _require(_identity(before) == _identity(os.fstat(fd)), "QCOW2_CHANGED_DURING_READ")
        return {
            "observationLevel": "LOCAL_REGULAR_FD_QCOW2_BYTES_ONLY",
            "fileSizeBytes": before.st_size,
            "fdDev": before.st_dev,
            "fdInode": before.st_ino,
            "qcow2Sha256": digest.hexdigest(),
            "qcow2Version": version,
            "virtualSizeBytes": virtual,
            "clusterSizeBytes": 1 << bits,
            "hasBackingFile": False,
            "hasSnapshots": False,
            "logicalSectorBytesVerified": False,
            "backingChainAuthenticated": False,
            "qemuBackendFdAuthenticated": False,
            "guestDiskBytesObserved": False,
            "gptPrimaryAndBackupVerified": False,
            "filesystemOrDeploymentObserved": False,
        }
    except (OSError, struct.error) as exc:
        raise Refusal("QCOW2_READ_FAILURE") from exc


def _decision(reason: str) -> dict:
    return {
        "decision": "BLOCKED_NO_AUTHENTICATED_DEPLOYMENT_QCOW2",
        "reason": reason,
        "ociManifest": OCI_MANIFEST,
        "sourceBootcSha256": BOOTC_SHA256,
        "originOciRpmEvidenceInherited": True,
        "qcow2ArtifactAuthenticated": False,
        "detachedQemuIndependentlyVerified": False,
        "qcow2IdentityAndGeometryVerified": False,
        "guestDiskBytesObserved": False,
        "gptPrimaryAndBackupVerified": False,
        "btrfsUuidAndSubvolumesVerified": False,
        "ostreeDeploymentChecksumVerified": False,
        "installedBootcRpmIdentityVerified": False,
        "efiFilesBelongToDeploymentVerified": False,
        "bootloaderAndNVRAMWriteSetVerified": False,
        "secureBootStateVerified": False,
        "recoveryCheckpointVerified": False,
        "sameDiskDualBootVerified": False,
        "guestChannelAuthenticated": False,
        **{key: False for key in NO_WRITE},
    }


def assess(
    *,
    observed_fd: dict | None = None,
    claim: dict | None = None,
) -> dict:
    """Compare local host *measurements* with claimed pins, without authority.

    Neither a caller-supplied JSON nor its locally calculated hash can attest
    a deployment or satisfy the missing Safety/Integrator transaction contract.
    """
    result = _decision("NO_AUTHENTICATED_DEPLOYMENT_ARTIFACT_OR_TRANSACTION")
    if claim is None:
        return result
    if type(claim) is not dict:
        result["reason"] = "MALFORMED_DEPLOYMENT_CLAIM"
        return result
    if claim.get("firmware") != "uefi" or claim.get("partitionTable") != "gpt":
        result["reason"] = "BIOS_MBR_REQUEST_OR_UNVERIFIED_FIRMWARE"
        return result
    if type(claim.get("sectorBytes")) is not int or claim["sectorBytes"] not in (512, 4096):
        result["reason"] = "SECTOR_GEOMETRY_MISMATCH"
        return result
    if not isinstance(claim.get("transactionId"), str) or not claim["transactionId"]:
        result["reason"] = "MISSING_TRANSACTION_ID"
        return result
    if claim.get("recoveryCheckpointVerified") is not True:
        result["reason"] = "MISSING_RECOVERY_CHECKPOINT"
        return result
    if type(observed_fd) is not dict:
        result["reason"] = "NO_QCOW2_FD_BYTES_MEASURED"
        return result
    pins = claim.get("hostFile")
    if (
        type(pins) is not dict
        or type(pins.get("dev")) is not int
        or type(pins.get("inode")) is not int
        or type(pins.get("sizeBytes")) is not int
        or type(pins.get("sha256")) is not str
        or any(
            (observed_fd.get(local) != pins[pinned])
            for local, pinned in (
                ("fdDev", "dev"),
                ("fdInode", "inode"),
                ("fileSizeBytes", "sizeBytes"),
                ("qcow2Sha256", "sha256"),
            )
        )
    ):
        result["reason"] = "FOREIGN_QCOW2"
        return result
    if observed_fd.get("hasBackingFile") is not False or claim.get("backing") != "none":
        result["reason"] = "QCOW2_BACKING_SWAP_OR_UNVERIFIED_CHAIN"
        return result
    for name, reason in (
        ("gptGuidMatchesFdBytes", "WRONG_GPT_GUID_UNPROVEN"),
        ("guestSectorMatchesFdBytes", "SECTOR_GEOMETRY_MISMATCH"),
        ("efiOwnedByTransaction", "FOREIGN_EFI_FILE_UNPROVEN"),
        ("rpmBootcMatchesOci", "RPM_IDENTITY_MISMATCH_UNPROVEN"),
        ("ostreeDeploymentMatchesOci", "OSTREE_DEPLOYMENT_MISMATCH_UNPROVEN"),
    ):
        if claim.get(name) is not True:
            result["reason"] = reason
            return result
    result["locallyMeasuredQcow2Sha256"] = observed_fd["qcow2Sha256"]
    result["reason"] = "UNAUTHENTICATED_CLAIMS_CANNOT_PROVE_GPT_BTRFS_OSTREE_RPM_EFI_OR_INSTALLER"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # No --image/path input until a reviewed FD-backed shared authority exists.
    # Even with a local QCOW2 FD, no execution/installation authority is possible.
    args.output.write_text(json.dumps(assess(), indent=2, sort_keys=True) + "\n")
    print("BLOCKED_NO_AUTHENTICATED_DEPLOYMENT_QCOW2")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
