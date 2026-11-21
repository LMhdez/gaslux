"""Adversarial offline replay of the exact, SHA-pinned ISO45 Actions artifact."""

import copy
import io
import json
import os
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bazzite_iso45_evidence_replay import FRAME_SHA256, Refusal, inspect_evidence, replay, sha

CANDIDATE = Path(__file__).resolve().parents[1] / "bazzite_official_iso_candidate_20261117.json"


@pytest.fixture
def original():
    filename = os.getenv("BAZZITE_ISO45_REPLAY_ZIP")
    if not filename:
        pytest.skip("Original ZIP not supplied; CI fetches the pinned 2.5 MB artifact")
    path = Path(filename)
    with zipfile.ZipFile(path) as z:
        members = {name: z.read(name) for name in z.namelist()}
    candidate = json.loads(CANDIDATE.read_text())
    assert replay(path, candidate)["result"] == "B"
    return path, members, candidate


def tamper_json(members, name, key, value):
    altered = dict(members)
    body = json.loads(altered[name])
    body[key] = value
    altered[name] = json.dumps(body).encode()
    return altered


def test_original_replay_proves_live_not_installer(original):
    _, _, candidate = original
    result = replay(original[0], candidate)
    assert result["originalResult"] == "C"
    assert result["visualLiveDesktopObserved"] is True
    assert result["installerDestinationObserved"] is False
    assert result["anacondaProcessVerified"] is False
    assert result["getActionsObserved"] is False
    assert result["writeSetVerified"] is False
    assert result["installationAuthorized"] is False
    assert result["frameSha256"] == list(FRAME_SHA256)
    assert result["syntheticOverlayDiscarded"] is True


def test_wrong_zip_bytes_refused(original, tmp_path):
    path, _, candidate = original
    bad = tmp_path / "changed.zip"
    bad.write_bytes(path.read_bytes() + b"x")
    with pytest.raises(Refusal, match="SHA256"):
        replay(bad, candidate)


@pytest.mark.parametrize("name", [
    "iso45-screen-0.png",
    "iso45-ocr-5.txt",
    "iso45-serial.txt",
    "iso45-preboot-topology.txt",
    "iso45-synthetic-discard.json",
    "bazzite-iso-public-readback.json",
])
def test_missing_member_refused(original, name):
    _, members, candidate = original
    altered = dict(members)
    del altered[name]
    with pytest.raises(Refusal):
        inspect_evidence(altered, candidate)


def test_png_substitution_refused(original):
    _, members, candidate = original
    altered = dict(members)
    altered["iso45-screen-0.png"] = members["iso45-screen-1.png"]
    with pytest.raises(Refusal, match="Unapproved screenshot"):
        inspect_evidence(altered, candidate)


def test_png_corruption_refused(original):
    _, members, candidate = original
    altered = dict(members)
    altered["iso45-screen-2.png"] = b"not a PNG"
    with pytest.raises(Refusal):
        inspect_evidence(altered, candidate)


def test_capture_order_refused(original):
    _, members, candidate = original
    altered = dict(members)
    original_lines = members["iso45-screen-sha256.txt"].splitlines()
    original_lines[0], original_lines[1] = original_lines[1], original_lines[0]
    altered["iso45-screen-sha256.txt"] = b"\n".join(original_lines)
    with pytest.raises(Refusal, match="order"):
        inspect_evidence(altered, candidate)


def test_ocr_injection_without_png_identity_cannot_pass(original):
    _, members, candidate = original
    altered = dict(members)
    altered["iso45-ocr-0.txt"] = b"Bazzite Portal\nManage Bazzite\nSearch Apps and Actions"
    altered["iso45-screen-0.png"] = b"fake-visual"
    with pytest.raises(Refusal, match="Unapproved screenshot"):
        inspect_evidence(altered, candidate)


def test_grub_only_is_not_a_live_desktop(original):
    _, members, candidate = original
    altered = dict(members)
    for i in range(6):
        altered[f"iso45-ocr-{i}.txt"] = b"GRUB version 2.12 Bazzite menu"
    with pytest.raises(Refusal, match="corroborated"):
        inspect_evidence(altered, candidate)


@pytest.mark.parametrize(("name", "key", "value"), [
    ("iso45-boot-preflight.json", "isoSha256", "f" * 64),
    ("iso45-passive-boot-result.json", "provenanceResult", "B"),
    ("iso45-passive-boot-result.json", "getActionsObserved", True),
    ("iso45-passive-boot-result.json", "installationAuthorized", True),
    ("iso45-passive-boot-result.json", "guestCommandChannelAuthorized", True),
    ("iso45-passive-boot-result.json", "installerInterfaceIdentified", True),
    ("iso45-passive-boot-result.json", "noWindowsDiskAttached", False),
    ("iso45-synthetic-discard.json", "overlayDiscarded", False),
    ("iso45-synthetic-after.json", "baseUnchanged", False),
])
def test_mutator_or_cross_run_claim_refused(original, name, key, value):
    _, members, candidate = original
    with pytest.raises(Refusal):
        inspect_evidence(tamper_json(members, name, key, value), candidate)


def test_wrong_signed_iso_provenance_refused(original):
    _, members, candidate = original
    altered = copy.deepcopy(candidate)
    altered["publicReadback"]["workflowRunId"] = 12345
    with pytest.raises(Refusal):
        inspect_evidence(members, altered)


def test_missing_qemu_runtime_refused(original):
    _, members, candidate = original
    altered = dict(members)
    altered["iso45-monitor-0.txt"] = b"VM status: paused"
    with pytest.raises(Refusal, match="VM not running"):
        inspect_evidence(altered, candidate)


def test_generic_desktop_text_does_not_pass(original):
    _, members, candidate = original
    altered = dict(members)
    for i in range(6):
        altered[f"iso45-ocr-{i}.txt"] = b"Welcome to Linux\nInstall to Hard Drive"
    with pytest.raises(Refusal, match="corroborated"):
        inspect_evidence(altered, candidate)


def test_fake_destination_in_ocr_does_not_upgrade_b_to_a(original):
    _, members, candidate = original
    altered = dict(members)
    altered["iso45-ocr-1.txt"] += b"\nBazzite installation destination\n"
    with pytest.raises(Refusal, match="corroborated"):
        inspect_evidence(altered, candidate)


def test_sha_helper_is_exact(original):
    _, members, _ = original
    assert sha(members["iso45-screen-0.png"]) == FRAME_SHA256[0]
