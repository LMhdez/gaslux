"""CACHY-BCD-682 independent forensic gates; no boot, QEMU, writer or hive bytes.

Runs the unchanged real #314 A/B comparator and #263 read-only summarizer
from a pinned checkout. Synthetic byte fixtures never establish process identity.
The additional context gate is TEST-ONLY: Integrator 3 must authenticate its
inputs before it can be used to reason about genuine Windows A/B captures.
"""

from __future__ import annotations

import copy
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(os.environ["GASLUX_CACHY314_ROOT"]).resolve()
sys.path.insert(0, str(ROOT / "auto_tests/tools"))
from windows_cachyos_bcd_ab_control import (  # noqa: E402
    BcdAbControlError,
    compare_bcd_ab,
    validate_bcd_forensic,
)
from windows_cachyos_postpacstrap_windows import (  # noqa: E402
    summarize_bcd_difference,
)

HISTORICAL = {
    "sourceRun": 44900941635,
    "controlInitialSha256": "7017e17de91070a7c91b1e725a7b7437bb0df74676437e11862362388d1d172f",
    "treatmentInitialSha256": "7017e17de91070a7c91b1e725a7b7437bb0df74676437e11862362388d1d172f",
    "controlAfterSha256": "ed11faf6d3f76e55b9e3db49dab7194d203f940262a28ca87ed7362f332be30d",
    "treatmentAfterSha256": "be917b89b38c8cf23f9d6a7524921fd7de1f0449cfa7aaf5f6d07d2106d08ed2",
    "changedByteCount": 682,
    "changedRunCount": 189,
    "changedOffsetSetSha256": "c499a5a15454a30afceda835609464a9d8e050dde2fb3643f83f1581250cd2b2",
    "fullBcdHiveBytesPublished": False,
    "processIdentityAuthenticated": False,
}


def _hive(marker: int) -> bytes:
    value = bytearray(28672)
    value[:4] = b"regf"
    for i in range(682):
        value[4096 + i] = marker
    return bytes(value)


def _matched():
    baseline = _hive(0)
    a = summarize_bcd_difference(baseline, _hive(1))
    b = summarize_bcd_difference(baseline, _hive(2))
    return a, b


def _context():
    """Untrusted contextual fixture; not authenticated provenance."""
    return {
        "transactionA": "a" * 32,
        "transactionB": "a" * 32,
        "checkpointSha256A": "1" * 64,
        "checkpointSha256B": "1" * 64,
        "initialOverlaySha256A": "2" * 64,
        "initialOverlaySha256B": "2" * 64,
        "initialBcdSha256A": "3" * 64,
        "initialBcdSha256B": "3" * 64,
        "ovmfInodeA": 101,
        "ovmfInodeB": 102,
        "ovmfInitialSha256A": "4" * 64,
        "ovmfInitialSha256B": "4" * 64,
        "tpmStateInodeA": 201,
        "tpmStateInodeB": 202,
        "tpmInitialSha256A": "5" * 64,
        "tpmInitialSha256B": "5" * 64,
        "capturePhaseA": "immediately-after-fifth-Windows-boot",
        "capturePhaseB": "immediately-after-fifth-Windows-boot",
        "bootOrdinalA": 5,
        "bootOrdinalB": 5,
        "writerAuthenticatedA": False,
        "writerAuthenticatedB": False,
        "sourceAuthenticated": False,
    }


class CausalEvidenceUnavailable(ValueError):
    """Test-only denial of causal claims, never an authorization interface."""


def _check_matched_context(value: dict, *, require_writer: bool = False) -> str:
    """Structural A/B control; not a substitute for signed evidence or writer ID."""
    exact = set(_context())
    if type(value) is not dict or set(value) != exact:
        raise CausalEvidenceUnavailable("incomplete cross-arm provenance")
    matches = (
        ("transactionA", "transactionB"),
        ("checkpointSha256A", "checkpointSha256B"),
        ("initialOverlaySha256A", "initialOverlaySha256B"),
        ("initialBcdSha256A", "initialBcdSha256B"),
        ("ovmfInitialSha256A", "ovmfInitialSha256B"),
        ("tpmInitialSha256A", "tpmInitialSha256B"),
        ("capturePhaseA", "capturePhaseB"),
        ("bootOrdinalA", "bootOrdinalB"),
    )
    if any(value[left] != value[right] for left, right in matches):
        raise CausalEvidenceUnavailable("unmatched checkpoint or observation phase")
    if (
        type(value["ovmfInodeA"]) is not int
        or type(value["ovmfInodeB"]) is not int
        or type(value["tpmStateInodeA"]) is not int
        or type(value["tpmStateInodeB"]) is not int
        or value["ovmfInodeA"] == value["ovmfInodeB"]
        or value["tpmStateInodeA"] == value["tpmStateInodeB"]
    ):
        raise CausalEvidenceUnavailable("shared OVMF or TPM object")
    if require_writer and not (
        value["writerAuthenticatedA"] is True
        and value["writerAuthenticatedB"] is True
        and value["sourceAuthenticated"] is True
    ):
        raise CausalEvidenceUnavailable("writer/source not independently authenticated")
    return "STRUCTURAL_AB_ONLY_NOT_CAUSAL"


def test_historical_682_offsets_are_common_but_final_bytes_differ():
    assert HISTORICAL["controlInitialSha256"] == HISTORICAL["treatmentInitialSha256"]
    assert HISTORICAL["controlAfterSha256"] != HISTORICAL["treatmentAfterSha256"]
    assert HISTORICAL["changedByteCount"] == 682
    assert HISTORICAL["changedRunCount"] == 189
    assert HISTORICAL["fullBcdHiveBytesPublished"] is False
    assert HISTORICAL["processIdentityAuthenticated"] is False


def test_synthetic_positive_control_is_diagnostic_and_not_all_deny():
    control, treatment = _matched()
    summary = compare_bcd_ab(control, treatment)
    assert summary["initialBcdEqual"] is True
    assert summary["controlBcdChanged"] is True
    assert summary["treatmentBcdChanged"] is True
    assert summary["changedOffsetManifestEqual"] is True
    assert summary["controlAndTreatmentPostBootBcdEqual"] is False
    assert summary["processAttributionProven"] is False
    assert summary["approvedMutation"] is False
    assert summary["releaseEligible"] is False
    assert _check_matched_context(_context()) == "STRUCTURAL_AB_ONLY_NOT_CAUSAL"


def test_bcd_mutation_without_matching_control_does_not_become_safe():
    baseline = _hive(0)
    control = summarize_bcd_difference(baseline, baseline)
    treatment = summarize_bcd_difference(baseline, _hive(1))
    conclusion = compare_bcd_ab(control, treatment)
    assert conclusion["classification"].startswith("TREATMENT_ONLY_BCD_MUTATION")
    assert conclusion["approvedMutation"] is False
    assert conclusion["processAttributionProven"] is False


def test_identical_postboot_bcd_does_not_authorize_mutation():
    before = _hive(0)
    after = _hive(1)
    witness = summarize_bcd_difference(before, after)
    result = compare_bcd_ab(witness, copy.deepcopy(witness))
    assert "NO_ADDITIONAL_CACHYOS_BCD_DELTA" in result["classification"]
    assert result["approvedMutation"] is False
    assert result["processAttributionProven"] is False
    assert result["releaseEligible"] is False


def test_mismatched_initial_bcd_never_proves_cachyos_authorship():
    control, treatment = _matched()
    treatment = summarize_bcd_difference(_hive(3), _hive(2))
    result = compare_bcd_ab(control, treatment)
    assert result["classification"] == "INVALID_INITIAL_BCD_MISMATCH"
    assert result["approvedMutation"] is False


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("transactionB", "b" * 32),
        ("checkpointSha256B", "6" * 64),
        ("initialOverlaySha256B", "7" * 64),
        ("initialBcdSha256B", "8" * 64),
        ("ovmfInitialSha256B", "9" * 64),
        ("tpmInitialSha256B", "0" * 64),
        ("capturePhaseB", "late-after-another-reboot"),
        ("bootOrdinalB", 6),
        ("ovmfInodeB", 101),
        ("tpmStateInodeB", 201),
    ],
)
def test_cross_arm_mismatch_refused_in_test_only_context_gate(field, replacement):
    case = _context()
    case[field] = replacement
    with pytest.raises(CausalEvidenceUnavailable):
        _check_matched_context(case)


def test_writer_identity_absence_refuses_causal_proof():
    with pytest.raises(CausalEvidenceUnavailable, match="writer/source"):
        _check_matched_context(_context(), require_writer=True)


def test_claimed_writer_flags_are_not_cryptographic_provenance():
    case = _context()
    case.update(
        writerAuthenticatedA=True,
        writerAuthenticatedB=True,
        sourceAuthenticated=True,
    )
    assert (
        _check_matched_context(case, require_writer=True)
        == "STRUCTURAL_AB_ONLY_NOT_CAUSAL"
    )


@pytest.mark.parametrize(
    "field", ["changedByteCount", "prebootBcdSha256", "approvedMutation"]
)
def test_malformed_or_promoted_real_bcd_evidence_refused(field):
    control, _ = _matched()
    if field == "changedByteCount":
        control[field] = 0
    elif field == "prebootBcdSha256":
        control[field] = "bad"
    else:
        control[field] = True
    with pytest.raises(BcdAbControlError):
        validate_bcd_forensic(control)


def test_truncated_manifest_cannot_reconstruct_original_hive():
    control, _ = _matched()
    assert "prebootBcdSha256" in control
    assert "postbootBcdSha256" in control
    assert "prebootBcdHive" not in control
    assert "postbootBcdHive" not in control
    assert control["productionStorageWritesAuthorized"] is False
