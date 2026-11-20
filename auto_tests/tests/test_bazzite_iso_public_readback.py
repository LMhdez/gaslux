import hashlib
import json

import pytest

from auto_tests.bazzite_iso_public_readback import (
    PAYLOAD_IMAGE,
    PREDICATE_TYPE,
    ReadbackError,
    parse_checksum,
    validate_attestation_report,
    validate_metadata,
    validate_run_metadata,
    verify_embedded_blobs,
)


def test_checksum_requires_exact_iso_name_and_single_digest():
    digest = "a" * 64
    assert parse_checksum(f"{digest}  bazzite-stable-live-amd64.iso\n".encode()) == digest
    with pytest.raises(ReadbackError):
        parse_checksum(f"{digest}  other.iso\n".encode())
    with pytest.raises(ReadbackError):
        parse_checksum(
            f"{digest}  bazzite-stable-live-amd64.iso\n{digest}  bazzite-stable-live-amd64.iso\n".encode()
        )


def test_metadata_binds_exact_iso_and_attestation():
    data = json.dumps(
        {
            "iso": "bazzite-stable-live-amd64.iso",
            "attestation_url": "https://github.com/ublue-os/bazzite/attestations/68711578",
            "build_date": "2026-11-17T00:00:00Z",
        }
    ).encode()
    assert validate_metadata(data)["iso"] == "bazzite-stable-live-amd64.iso"
    forged = json.loads(data)
    forged["iso"] = "different.iso"
    with pytest.raises(ReadbackError):
        validate_metadata(json.dumps(forged).encode())


def test_upstream_run_requires_exact_workflow_and_source_commit():
    valid = {
        "id": 44121421800,
        "path": ".github/workflows/build_iso.yml",
        "head_sha": "5d71c4376169910c25bc06a3537f4780521e7435",
        "head_branch": "main",
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "html_url": "https://github.com/ublue-os/bazzite/actions/runs/44121421800",
    }
    assert validate_run_metadata(valid, run_id="44121421800", workflow="build_iso")["conclusion"] == "success"
    forged = dict(valid, head_sha="0" * 40)
    with pytest.raises(ReadbackError):
        validate_run_metadata(forged, run_id="44121421800", workflow="build_iso")


def _attestation(digest="b" * 64, predicate_type=PREDICATE_TYPE):
    return [
        {
            "verificationResult": {
                "statement": {
                    "_type": "https://in-toto.io/Statement/v1",
                    "subject": [{"name": "bazzite.iso", "digest": {"sha256": digest}}],
                    "predicateType": predicate_type,
                    "predicate": {},
                },
                "signature": {"certificate": {"issuer": "https://token.actions.githubusercontent.com"}},
                "verifiedTimestamps": [{"kind": "rekor"}],
            }
        }
    ]


def test_attestation_requires_matching_subject_predicate_and_certificate():
    result = validate_attestation_report(
        _attestation(),
        expected_digest="sha256:" + "b" * 64,
        expected_workflow="github.com/ublue-os/bazzite/.github/workflows/build_iso.yml",
    )
    assert result["verifiedByGhCli"] is True
    assert result["predicateType"] == PREDICATE_TYPE
    with pytest.raises(ReadbackError):
        validate_attestation_report(
            _attestation("c" * 64),
            expected_digest="sha256:" + "b" * 64,
            expected_workflow="github.com/ublue-os/bazzite/.github/workflows/build_iso.yml",
        )
    with pytest.raises(ReadbackError):
        validate_attestation_report(
            _attestation(predicate_type="https://example.invalid/predicate"),
            expected_digest="sha256:" + "b" * 64,
            expected_workflow="github.com/ublue-os/bazzite/.github/workflows/build_iso.yml",
        )


def _embedded_fixture(version="45.20261117.1"):
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"Labels": {"org.opencontainers.image.version": version}},
    }
    config_bytes = json.dumps(config, separators=(",", ":")).encode()
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": len(config_bytes),
        },
        "layers": [],
    }
    manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()
    manifest_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    image = {
        "id": config_digest,
        "names": [f"{PAYLOAD_IMAGE}:stable"],
    }
    return image, manifest_bytes, config_bytes, manifest_digest, config_digest


def test_embedded_manifest_and_config_are_hash_bound():
    image, manifest, config, manifest_digest, config_digest = _embedded_fixture()
    result = verify_embedded_blobs(
        image,
        manifest,
        config,
        expected_manifest_digest=manifest_digest,
        expected_config_digest=config_digest,
        expected_version="45.20261117.1",
    )
    assert result["manifestSha256"] == manifest_digest.removeprefix("sha256:")
    assert result["configDigest"] == config_digest
    assert result["embeddedVersionLabel"] == "45.20261117.1"


def test_embedded_payload_rejects_wrong_manifest_config_and_version():
    image, manifest, config, manifest_digest, config_digest = _embedded_fixture()
    with pytest.raises(ReadbackError):
        verify_embedded_blobs(
            image,
            manifest,
            config,
            expected_manifest_digest="sha256:" + "0" * 64,
            expected_config_digest=config_digest,
            expected_version="45.20261117.1",
        )
    with pytest.raises(ReadbackError):
        verify_embedded_blobs(
            image,
            manifest,
            config,
            expected_manifest_digest=manifest_digest,
            expected_config_digest="sha256:" + "0" * 64,
            expected_version="45.20261117.1",
        )
    wrong_image = dict(image, id="0" * 64)
    with pytest.raises(ReadbackError):
        verify_embedded_blobs(
            wrong_image,
            manifest,
            config,
            expected_manifest_digest=manifest_digest,
            expected_config_digest=config_digest,
            expected_version="45.20261117.1",
        )
    wrong_version_image, wrong_manifest, wrong_config, wrong_md, wrong_cd = _embedded_fixture("45.20261116.1")
    with pytest.raises(ReadbackError):
        verify_embedded_blobs(
            wrong_version_image,
            wrong_manifest,
            wrong_config,
            expected_manifest_digest=wrong_md,
            expected_config_digest=wrong_cd,
            expected_version="45.20261117.1",
        )
