"""Contract for the official Bazzite 45 ISO evidence snapshot.

This is a diagnostic ledger, not a trust anchor or installer authorization.
"""

import json
import re
from pathlib import Path

CANDIDATE = Path(__file__).resolve().parents[1] / "bazzite_official_iso_candidate_20261117.json"
SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")


def load_candidate():
    return json.loads(CANDIDATE.read_text(encoding="utf-8"))


def test_official_build_candidate_has_consistent_pinned_identities():
    evidence = load_candidate()
    assert evidence["distribution"] == "bazzite"
    assert evidence["artifact"]["version"] == "45.20261117.1"
    assert evidence["artifact"]["architecture"] == "x86_64"
    assert evidence["artifact"]["sha256"] == evidence["artifact"]["provenance"]["subjectSha256"]
    assert SHA256.fullmatch(evidence["payload"]["digest"])
    assert SHA256.fullmatch(evidence["payload"]["configDigest"])
    assert evidence["payload"]["digest"] != evidence["payload"]["configDigest"]
    assert evidence["relationship"]["configDigestCrossMatchedInOfficialBuildLogs"] is True


def test_candidate_remains_blocked_until_public_iso_and_payload_are_read_back():
    evidence = load_candidate()
    assert evidence["evidenceRecordOnly"] is True
    assert evidence["result"] == "B"
    assert evidence["artifact"]["sizeBytes"] is None
    assert evidence["artifact"]["signature"]["publicReadbackVerified"] is False
    assert evidence["artifact"]["signature"]["verifiedAgainstLocalIsoBytes"] is False
    assert evidence["artifact"]["provenance"]["verifiedAgainstLocalIsoBytes"] is False
    assert evidence["relationship"]["embeddedOciManifestReadBackVerified"] is False
    assert evidence["relationship"]["isoAttestationResolvedPayloadDigestIndependentlyVerified"] is False
    assert evidence["relationship"]["cryptographicIsoToPayloadBindingVerified"] is False
    assert evidence["installationAuthorized"] is False


def test_candidate_never_confuses_oci_digest_with_iso_digest():
    evidence = load_candidate()
    assert evidence["artifact"]["sha256"] != evidence["payload"]["digest"].removeprefix("sha256:")
    assert evidence["artifact"]["sha256"] != evidence["payload"]["configDigest"].removeprefix("sha256:")
    assert evidence["payload"]["digest"] != evidence["payload"]["configDigest"]
