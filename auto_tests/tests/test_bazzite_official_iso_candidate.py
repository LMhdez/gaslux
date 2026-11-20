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


def test_authenticated_public_iso_record_is_still_not_an_installation_grant():
    evidence = load_candidate()
    assert evidence["evidenceRecordOnly"] is True
    assert evidence["result"] == "A"
    assert evidence["artifact"]["sizeBytes"] == 8377878528
    assert evidence["artifact"]["signature"]["publicReadbackVerified"] is True
    assert evidence["artifact"]["signature"]["verifiedAgainstLocalIsoBytes"] is True
    assert evidence["publicReadback"]["sha256MatchesPinnedBuildSubject"] is True
    assert evidence["publicReadback"]["officialChecksumVerified"] is True
    assert evidence["publicReadback"]["detachedCosignSignatureVerified"] is True
    assert evidence["publicReadback"]["githubIsoAttestationVerified"] is True
    assert evidence["publicReadback"]["payloadCosignSignatureVerified"] is True
    assert evidence["publicReadback"]["payloadAttestationVerified"] is True
    assert evidence["publicReadback"]["embeddedOciManifestReadBackVerified"] is True
    assert evidence["publicReadback"]["embeddedManifestBytesVerified"] is True
    assert evidence["publicReadback"]["payloadConfigBlobVerified"] is True
    assert evidence["publicReadback"]["workflowRunId"] == 44759529218
    assert evidence["publicReadback"]["evidenceArtifactId"] == 14641606769
    assert evidence["artifact"]["provenance"]["verifiedAgainstLocalIsoBytes"] is True
    assert evidence["relationship"]["embeddedOciManifestReadBackVerified"] is True
    assert (
        evidence["relationship"]["isoAttestationResolvedPayloadDigestIndependentlyVerified"]
        is False
    )
    assert evidence["relationship"]["cryptographicIsoToPayloadBindingVerified"] is True
    assert evidence["publicReadback"]["isoToPayloadBindingVerified"] is True
    assert evidence["publicReadback"]["installationAuthorized"] is False
    assert evidence["support"]["gasluxSupport"] == "experimental-unverified"
    assert evidence["installationAuthorized"] is False


def test_candidate_never_confuses_oci_digest_with_iso_digest():
    evidence = load_candidate()
    assert evidence["artifact"]["sha256"] != evidence["payload"]["digest"].removeprefix("sha256:")
    assert evidence["artifact"]["sha256"] != evidence["payload"]["configDigest"].removeprefix(
        "sha256:"
    )
    assert evidence["payload"]["digest"] != evidence["payload"]["configDigest"]


def test_terminal_run_evidence_is_consistent_without_fictitious_embedded_config():
    evidence = load_candidate()
    readback = evidence["publicReadback"]
    assert evidence["result"] == readback["result"] == "A"
    assert readback["workflowRunId"] == 44759529218
    assert readback["terminalZipSha256"] == (
        "1ad0ccbfec8b2316c89aac9bf58067d73a2541d734c7fcff3e053dd55757fee2"
    )
    assert readback["terminalRunExitCode"] == 0
    assert readback["failureStage"] == "complete"
    assert readback["failureReason"] is None
    assert "runFailedStage" not in readback
    assert "runFailureReason" not in readback
    assert readback["embeddedManifestBytesVerified"] is True
    assert readback["embeddedConfigBlobVerified"] is False
    assert readback["configBlobRetrievedFromISO"] is False
    assert readback["payloadConfigBlobVerified"] is True
    assert readback["configBlobVerificationSource"] == (
        "ghcr-immutable-oci-config-digest-crosschecked-with-embedded-iso-manifest"
    )
    assert evidence["relationship"]["embeddedOciManifestReadBackVerified"] is True
    assert evidence["relationship"]["isoAttestationResolvedPayloadDigestIndependentlyVerified"] is False
    assert evidence["installationAuthorized"] is False
