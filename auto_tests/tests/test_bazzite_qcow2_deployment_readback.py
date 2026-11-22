"""BZD-QCOW2-DEPLOYMENT-READBACK-01: NO deployed QCOW2 or writer.

Only throwaway *QCOW2 header* files are built; never a GPT disk, Atomic rootfs
or faux installed deployment. Local FD measurements do not confer trust.
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))
from bazzite_qcow2_deployment_readback import (  # noqa: E402
    NO_WRITE,
    Refusal,
    assess,
    inspect_qcow2_fd,
)


def header(*, backing: bool = False, version: int = 3) -> bytes:
    """Structural QCOW2 header only, no actual GPT, filesystem or deployment."""
    data = bytearray(4096)
    data[:4] = b"QFI\xfb"
    struct.pack_into(">I", data, 4, version)
    struct.pack_into(">I", data, 20, 16)
    struct.pack_into(">Q", data, 24, 64 * 1024 * 1024)
    if backing:
        struct.pack_into(">QI", data, 8, 512, len(b"base.qcow2"))
        data[512 : 512 + len(b"base.qcow2")] = b"base.qcow2"
    if version == 3:
        struct.pack_into(">I", data, 100, 104)
    return bytes(data)


@pytest.fixture
def local_fd(tmp_path):
    path = tmp_path / "qcow2-header-only.bin"
    path.write_bytes(header())
    fd = os.open(path, os.O_RDONLY)
    try:
        yield fd, path
    finally:
        os.close(fd)


def claim(observed: dict) -> dict:
    return {
        "firmware": "uefi",
        "partitionTable": "gpt",
        "sectorBytes": 512,
        "transactionId": "synthetic-no-writer-reference-not-proof",
        "recoveryCheckpointVerified": True,
        "hostFile": {
            "dev": observed["fdDev"],
            "inode": observed["fdInode"],
            "sizeBytes": observed["fileSizeBytes"],
            "sha256": observed["qcow2Sha256"],
        },
        "backing": "none",
        "gptGuidMatchesFdBytes": True,
        "guestSectorMatchesFdBytes": True,
        "efiOwnedByTransaction": True,
        "rpmBootcMatchesOci": True,
        "ostreeDeploymentMatchesOci": True,
    }


def assert_denied(result: dict):
    assert result["decision"] == "BLOCKED_NO_AUTHENTICATED_DEPLOYMENT_QCOW2"
    assert result["qcow2ArtifactAuthenticated"] is False
    assert result["detachedQemuIndependentlyVerified"] is False
    assert result["gptPrimaryAndBackupVerified"] is False
    assert result["nativeInstallationVerified"] is False
    assert result["sameDiskDualBootVerified"] is False
    assert result["rollbackProven"] is False
    assert all(result[key] is False for key in NO_WRITE)


def test_actual_readonly_fd_qcow2_header_bytes_not_installed_disk(local_fd):
    fd, path = local_fd
    measured = inspect_qcow2_fd(fd)
    assert measured["fileSizeBytes"] == path.stat().st_size
    assert measured["qcow2Version"] == 3
    assert measured["virtualSizeBytes"] == 64 * 1024 * 1024
    assert measured["backingChainAuthenticated"] is False
    assert measured["gptPrimaryAndBackupVerified"] is False
    assert measured["filesystemOrDeploymentObserved"] is False
    result = assess(observed_fd=measured, claim=claim(measured))
    assert result["reason"].startswith("UNAUTHENTICATED_CLAIMS")
    assert result["callerSuppliedQcow2Sha256Unattested"] == measured["qcow2Sha256"]
    assert_denied(result)


def test_a_foreign_qcow2_inode_never_confers_source_identity(local_fd, tmp_path):
    fd, _path = local_fd
    measured = inspect_qcow2_fd(fd)
    wrong = claim(measured)
    wrong["hostFile"]["inode"] += 1
    result = assess(observed_fd=measured, claim=wrong)
    assert result["reason"] == "FOREIGN_QCOW2"
    assert_denied(result)
    another = tmp_path / "foreign-qcow2.bin"
    another.write_bytes(header())
    other_fd = os.open(another, os.O_RDONLY)
    try:
        other = inspect_qcow2_fd(other_fd)
    finally:
        os.close(other_fd)
    assert other["qcow2Sha256"] == measured["qcow2Sha256"]
    assert other["fdInode"] != measured["fdInode"]
    assert assess(observed_fd=other, claim=claim(measured))["reason"] == "FOREIGN_QCOW2"


def test_b_backing_swap_is_refused_before_guest_or_efi_read(tmp_path):
    path = tmp_path / "qcow2-unverified-backing"
    path.write_bytes(header(backing=True))
    fd = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(Refusal, match="QCOW2_BACKING_UNVERIFIED"):
            inspect_qcow2_fd(fd)
    finally:
        os.close(fd)


@pytest.mark.parametrize(
    ("case", "replacement", "expected"),
    [
        ("gptGuidMatchesFdBytes", False, "WRONG_GPT_GUID_UNPROVEN"),
        ("guestSectorMatchesFdBytes", False, "SECTOR_GEOMETRY_MISMATCH"),
        ("rpmBootcMatchesOci", False, "RPM_IDENTITY_MISMATCH_UNPROVEN"),
        ("ostreeDeploymentMatchesOci", False, "OSTREE_DEPLOYMENT_MISMATCH_UNPROVEN"),
        ("efiOwnedByTransaction", False, "FOREIGN_EFI_FILE_UNPROVEN"),
        ("recoveryCheckpointVerified", False, "MISSING_RECOVERY_CHECKPOINT"),
        ("firmware", "bios", "BIOS_MBR_REQUEST_OR_UNVERIFIED_FIRMWARE"),
        ("partitionTable", "mbr", "BIOS_MBR_REQUEST_OR_UNVERIFIED_FIRMWARE"),
        ("sectorBytes", 2048, "SECTOR_GEOMETRY_MISMATCH"),
        ("sectorBytes", True, "SECTOR_GEOMETRY_MISMATCH"),
        ("backing", "base-swapped.qcow2", "QCOW2_BACKING_SWAP_OR_UNVERIFIED_CHAIN"),
    ],
)
def test_c_to_j_negative_claims_always_fail_closed(local_fd, case, replacement, expected):
    measured = inspect_qcow2_fd(local_fd[0])
    value = claim(measured)
    value[case] = replacement
    result = assess(observed_fd=measured, claim=value)
    assert result["reason"] == expected
    assert_denied(result)


def test_e_unauthenticated_deployment_without_real_host_fd():
    result = assess(claim={"nativeInstallationVerified": True})
    assert result["reason"] == "BIOS_MBR_REQUEST_OR_UNVERIFIED_FIRMWARE"
    assert_denied(result)


def test_j_without_recovery_checkpoint_fails_before_host_claim(local_fd):
    measured = inspect_qcow2_fd(local_fd[0])
    value = claim(measured)
    value.pop("recoveryCheckpointVerified")
    result = assess(observed_fd=measured, claim=value)
    assert result["reason"] == "MISSING_RECOVERY_CHECKPOINT"
    assert_denied(result)


@pytest.mark.parametrize(
    ("raw", "msg"),
    [
        (b"\0" * 4096, "FOREIGN_OR_RAW_IMAGE"),
        (header(version=5), "UNSUPPORTED_QCOW2_VERSION"),
    ],
)
def test_wrong_image_type_never_parsed_as_deployment(raw, msg, tmp_path):
    path = tmp_path / "refused-qcow2"
    path.write_bytes(raw)
    fd = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(Refusal, match=msg):
            inspect_qcow2_fd(fd)
    finally:
        os.close(fd)


def test_fd_writable_refused_before_reads(local_fd):
    path = local_fd[1]
    writer = os.open(path, os.O_RDWR)
    try:
        with pytest.raises(Refusal, match="FD_NOT_READONLY"):
            inspect_qcow2_fd(writer)
    finally:
        os.close(writer)


def test_none_or_untrusted_source_never_authenticates_deployment(local_fd):
    measured = inspect_qcow2_fd(local_fd[0])
    assert_denied(assess())
    assert_denied(assess(observed_fd=measured, claim=None))
    claim_data = claim(measured)
    claim_data["externalAttestationVerified"] = True
    claim_data["guestMeasurementSigned"] = True
    claim_data["nativeInstallationVerified"] = True
    claim_data["stable"] = True
    result = assess(observed_fd=measured, claim=claim_data)
    assert_denied(result)


def test_cli_never_accepts_qcow2_path_or_guest_execution(tmp_path):
    output = tmp_path / "result.json"
    script = ROOT / "auto_tests/bazzite_qcow2_deployment_readback.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--output", str(output)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 3
    assert_denied(__import__("json").loads(output.read_text()))
    proc = subprocess.run(
        [sys.executable, str(script), "--image", "/dev/sda", "--output", str(output)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode != 0
