"""Adversarial contract for passive Bazzite 45 ISO live boot."""

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bazzite_iso45_passive_gate import Refusal, classify, validate_record, verify_iso_file


def records():
    sha = "6120b6edc2d87e7bdccf8dfddc8b156552cd50b152cb0a9e9dedb37fb947cbe5"
    manifest = "sha256:492f83c738838861464685aed341783c2ea2266c82a9f19f0c867fd301783fd4"
    config = "sha256:938000b71e57a251c3720e90ad7422b6636b1cbcbecc928479c0a8f32350badb"
    candidate = {
        "result": "A",
        "evidenceRecordOnly": True,
        "installationAuthorized": False,
        "artifact": {
            "sha256": sha,
            "sizeBytes": 8377878528,
            "version": "45.20261117.1",
        },
        "payload": {"digest": manifest, "configDigest": config},
        "publicReadback": {
            "workflowRunId": 44759529218,
            "terminalRunExitCode": 0,
            "terminalZipSha256": (
                "1ad0ccbfec8b2316c89aac9bf58067d73a2541d734c7fcff3e053dd55757fee2"
            ),
            "failureStage": "complete",
            "failureReason": None,
        },
    }
    report = {
        "result": "A",
        "installationAuthorized": False,
        "runStatus": {"exitCode": "0", "failedStage": "complete"},
        "workflowOutcomes": dict.fromkeys(
            (
                "contracts",
                "cosignIsoInstaller",
                "cosignPayloadInstaller",
                "ghcrAuthentication",
                "readback",
            ),
            "success",
        ),
        "candidate": {
            "expectedIsoSha256": sha,
            "expectedPayloadDigest": manifest,
            "expectedConfigDigest": config,
        },
        "embeddedPayload": {
            "manifestDigest": manifest,
            "configDigestFromManifest": config,
            "verifiedConfigBlob": {
                "configDigest": config,
                "configBytesSha256Verified": True,
            },
            "configBlobRetrievedFromISO": False,
        },
        "publicReadback": {
            "embeddedPayloadVerified": True,
            "isoMountedReadOnly": True,
        },
        "policy": {
            "isoBooted": False,
            "diskWrites": False,
            "nvramWrites": False,
        },
    }
    facts = {
        "sha256": sha,
        "sizeBytes": 8377878528,
        **dict.fromkeys(
            (
                "checksumVerified",
                "cosignIsoVerified",
                "isoAttestationVerified",
                "payloadCosignVerified",
                "payloadAttestationVerified",
                "payloadConfigBlobVerified",
                "embeddedPayloadVerified",
                "isoMountedReadOnly",
            ),
            True,
        ),
    }
    return candidate, report, facts


def test_authentic_readback_yields_provenance_only():
    result = validate_record(*records())
    assert result["readbackResult"] == "A"
    assert result["installationAuthorized"] is False
    assert result["guestCommandChannelAuthorized"] is False


@pytest.mark.parametrize(
    ("source", "path", "value"),
    [
        (0, ("result",), "B"),
        (0, ("publicReadback", "workflowRunId"), 0),
        (0, ("publicReadback", "terminalRunExitCode"), 2),
        (0, ("publicReadback", "failureStage"), "embedded-manifest-config-extraction"),
        (0, ("artifact", "sha256"), "f" * 64),
        (0, ("artifact", "sizeBytes"), 8377878527),
        (0, ("payload", "digest"), "sha256:" + "0" * 64),
        (1, ("result",), "B"),
        (1, ("installationAuthorized",), True),
        (1, ("runStatus", "failedStage"), "download"),
        (1, ("workflowOutcomes", "readback"), "failure"),
        (1, ("candidate", "expectedConfigDigest"), "sha256:" + "0" * 64),
        (1, ("embeddedPayload", "manifestDigest"), "sha256:" + "0" * 64),
        (1, ("embeddedPayload", "configBlobRetrievedFromISO"), True),
        (1, ("embeddedPayload", "verifiedConfigBlob", "configBytesSha256Verified"), False),
        (1, ("policy", "isoBooted"), True),
        (2, ("sha256",), "f" * 64),
        (2, ("isoMountedReadOnly",), False),
    ],
)
def test_refuse_untrusted_or_mismatched_identity(source, path, value):
    rec = list(copy.deepcopy(records()))
    target = rec[source]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(Refusal):
        validate_record(*rec)


def test_refuse_obsolete_failure_from_earlier_readback():
    c, r, f = records()
    c["publicReadback"]["runFailedStage"] = "embedded-manifest-config-extraction"
    with pytest.raises(Refusal, match="Stale"):
        validate_record(c, r, f)


def test_foreign_iso_is_refused_before_hashing(tmp_path):
    foreign = tmp_path / "elsewhere.iso"
    foreign.write_bytes(b"wrong-image")
    with pytest.raises(Refusal, match="Foreign ISO path"):
        verify_iso_file(foreign, tmp_path)


def test_ambiguous_screen_never_proves_bazzite_live():
    result = classify(["UEFI firmware\nBazzite menu"], guest_running=True)
    assert result["result"] == "C"
    assert result["installationAuthorized"] is False
    assert result["installerInterfaceIdentified"] is False


def test_boot_screen_without_installer_yields_b():
    result = classify(["Welcome to Bazzite live session"], guest_running=True, evidence_authenticated=True)
    assert result["result"] == "B"
    assert result["getActionsObserved"] is False


def test_observed_installation_page_without_control_yields_a():
    result = classify(["Bazzite installation destination"], guest_running=True, evidence_authenticated=True, destination_screen_verified=True)
    assert result["result"] == "A"
    assert result["installationAuthorized"] is False


def test_ocr_without_running_guest_is_not_proof():
    result = classify(["Bazzite installation destination"], guest_running=False)
    assert result["result"] == "C"


def test_qemu_serial_file_backend_uses_qemu_chardev_syntax():
    script = Path(__file__).resolve().parents[1] / "bazzite_iso45_passive_boot.sh"
    source = script.read_text(encoding="utf-8")
    assert '-serial "file:$EVIDENCE/iso45-serial.txt"' in source
    assert '-serial "file=$EVIDENCE/iso45-serial.txt"' not in source
    assert "-nic none" in source
    assert "-S -no-reboot" in source
    assert "readonly=on,id=owned" in source
    assert "readonly=on,id=optical" in source

def test_actual_portal_ocr_recognized_without_destination_authority():
    ocr = (
        "Drive! Bazzite Portal\\nSearch Apps and Actions\\n"
        "Welcome! Install Applications Get Media Apps Manage Bazzite\\n"
        "Read the Bazzite Docs\\n"
    )
    result = classify([ocr], guest_running=True, evidence_authenticated=True)
    assert result["result"] == "B"
    assert result["liveEnvironmentRecognized"] is True
    assert result["installerInterfaceIdentified"] is False
    assert result["installationAuthorized"] is False


def test_partial_portal_or_generic_desktop_is_not_sufficient():
    for text in ("Bazzite Portal", "Manage Bazzite", "Install to Hard Drive", "Desktop"):
        assert classify([text], guest_running=True)["result"] == "C"

def test_any_unbound_ocr_cannot_claim_live_or_installer():
    for content in (
        "Bazzite Portal\nManage Bazzite\nRead the Bazzite Docs\nSearch Apps and Actions",
        "Bazzite installation destination",
    ):
        outcome = classify([content], guest_running=True)
        assert outcome["result"] == "C"
        assert outcome["installationAuthorized"] is False


def test_installer_destination_requires_independently_reviewed_frame():
    result = classify(
        ["Bazzite installation destination"],
        guest_running=True,
        evidence_authenticated=True,
        destination_screen_verified=False,
    )
    assert result["result"] == "C"
    assert result["installerInterfaceIdentified"] is False
