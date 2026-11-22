"""Real previously signed OCI/RPM readback cannot authenticate installed QCOW2."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))
from bazzite_deployment_provenance_boundary import (  # noqa: E402
    NO_AUTHORITY,
    SOURCE_REPORT_SHA256,
    Refusal,
    _decode,
    _valid_source_fields,
    assess,
)

# CI downloads the exact historical real runner artifact, not a synthetic
# representation or mutable OCI tag. Missing environment is a hard test error.
REPORT_PATH = Path(os.environ["GASLUX_PINNED_OCI_REPORT"])


def report() -> bytes:
    return REPORT_PATH.read_bytes()


def denied(result: dict) -> None:
    assert result["nativeDeploymentVerified"] is False
    assert result["qcow2IdentityAndGeometryVerified"] is False
    assert result["realWindowsBootVerified"] is False
    assert result["realLinuxBootVerified"] is False
    assert result["rollbackProven"] is False
    assert result["stable"] is False
    assert all(result[key] is False for key in NO_AUTHORITY)


def test_real_pinned_ci_artifact_matched_without_deployment():
    assert hashlib.sha256(report()).hexdigest() == SOURCE_REPORT_SHA256
    result = assess(report())
    assert result["decision"] == "SOURCE_ARTIFACT_MATCHED_DEPLOYMENT_UNPROVEN"
    assert result["sourceArtifactByteMatched"] is True
    assert result["bootcRpmBindingInSourceArtifact"] is True
    assert result["sourceCosignReverifiedInThisStep"] is False
    denied(result)


@pytest.mark.parametrize(
    "claim",
    [
        {"installationAuthorized": True, "nativeDeploymentVerified": True},
        {"firmware": "bios", "partitionTable": "mbr", "nativeDeploymentVerified": True},
        {"firmware": "uefi", "partitionTable": "gpt", "diskGuid": "FAKE", "espPreserved": True},
        {"selectedDisk": "/dev/sda", "qcow2DiskWasWritten": True, "bootcInstallSucceeded": True},
        {"signedBy": "runner", "sourceImage": "ghcr.io/ublue-os/bazzite:stable"},
        {"sourceImageDigest": "sha256:" + "a" * 64, "rollbackProven": True},
        {"bootc": "1.17.1", "ostreeCommit": "sha256:" + "b" * 64, "firstBootVerified": True},
        {"bootloaderInstalled": True, "efiMicrosoftIntact": True, "qcow2Image": "none"},
        {"secureBootEnabled": True, "mokEnrollmentAutomatic": True},
    ],
)
def test_untrusted_guest_or_runner_deployment_claim_denied(claim):
    result = assess(report(), untrusted_deployment_bytes=json.dumps(claim).encode())
    assert result["decision"] == "BLOCKED_UNAUTHENTICATED_DEPLOYMENT"
    assert result["sourceArtifactByteMatched"] is True
    denied(result)


@pytest.mark.parametrize(
    "forged",
    [b"", b"[]", b"{}", b"not json", b'{"x":1,"x":2}', b"\x00" * 300],
)
def test_substituted_source_bytes_never_count_as_signed_oci(forged):
    result = assess(forged)
    assert result["decision"] == "REFUSED_SOURCE_EVIDENCE"
    denied(result)


def test_semantic_tampering_invalidates_source_even_with_matching_shape():
    source = json.loads(report())
    for key, val in [
        ("installationAuthorized", True),
        ("nativeInstallationVerified", True),
        ("diffIdsVerified", 255),
        ("allUncompressedLayerDigestsVerified", 1),
        ("configDigest", "sha256:" + "0" * 64),
        ("manifestDigest", "sha256:" + "0" * 64),
    ]:
        modified = dict(source)
        modified[key] = val
        with pytest.raises(Refusal):
            _valid_source_fields(modified)
    modified = json.loads(report())
    modified["bootcRpmIdentity"]["rpmPackage"]["fileSha256"] = "0" * 64
    with pytest.raises(Refusal):
        _valid_source_fields(modified)
    modified = json.loads(report())
    modified["bootcRpmIdentity"]["status"] = "BOOTC_PACKAGE_BINDING_UNPROVEN"
    with pytest.raises(Refusal):
        _valid_source_fields(modified)


def test_duplicate_json_key_rejected():
    with pytest.raises(Refusal, match="Duplicate JSON property"):
        _decode(b'{"nativeInstallationVerified":true,"nativeInstallationVerified":false}', "test")


def test_malformed_deployment_report_is_rejected():
    result = assess(report(), untrusted_deployment_bytes=b'{"disk":"A","disk":"B"}')
    assert result["decision"] == "REFUSED_UNTRUSTED_DEPLOYMENT_REPORT"
    denied(result)


def _cli(tmp_path, source):
    output = tmp_path / "assessment.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "auto_tests/bazzite_deployment_provenance_boundary.py"),
            "--oci-report",
            str(source),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return proc.returncode, json.loads(output.read_text())


def test_cli_source_only_exits_two_but_never_approves(tmp_path):
    code, result = _cli(tmp_path, REPORT_PATH)
    assert code == 2
    assert result["decision"] == "SOURCE_ARTIFACT_MATCHED_DEPLOYMENT_UNPROVEN"
    denied(result)


def test_cli_wrong_artifact_and_symlink_both_exit_three(tmp_path):
    modified = tmp_path / "altered.json"
    modified.write_bytes(report() + b" ")
    code, result = _cli(tmp_path, modified)
    assert code == 3
    denied(result)
    link = tmp_path / "link.json"
    link.symlink_to(REPORT_PATH)
    code, result = _cli(tmp_path, link)
    assert code == 3
    denied(result)
