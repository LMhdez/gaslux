#!/usr/bin/env python3
"""Fail-closed validators for the Bazzite public ISO readback workflow."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

ISO_NAME = "bazzite-stable-live-amd64.iso"
ISO_SHA256 = "6120b6edc2d87e7bdccf8dfddc8b156552cd50b152cb0a9e9dedb37fb947cbe5"
ISO_ATTESTATION_ID = "68711578"
SOURCE_COMMIT = "5d71c4376169910c25bc06a3537f4780521e7435"
PAYLOAD_VERSION = "45.20261117.1"
ISO_COSIGN_VERSION = "v2.6.5"
PAYLOAD_COSIGN_VERSION = "v3.1.3"
PAYLOAD_IMAGE = "ghcr.io/ublue-os/bazzite"
PAYLOAD_TAG = f"{PAYLOAD_IMAGE}:stable-{PAYLOAD_VERSION}"
PAYLOAD_DIGEST = "sha256:492f83c738838861464685aed341783c2ea2266c82a9f19f0c867fd301783fd4"
CONFIG_DIGEST = "sha256:938000b71e57a251c3720e90ad7422b6636b1cbcbecc928479c0a8f32350badb"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
REPOSITORY = "ublue-os/bazzite"


class ReadbackError(ValueError):
    """A public readback or provenance check failed closed."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_checksum(data: bytes, iso_name: str = ISO_NAME) -> str:
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ReadbackError("Checksum sidecar is not ASCII") from exc
    matches = []
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+\*?(.+)", line.strip())
        if match and Path(match.group(2)).name == iso_name:
            matches.append(match.group(1).lower())
    if len(matches) != 1:
        raise ReadbackError("Checksum sidecar must contain exactly one matching ISO entry")
    return matches[0]


def validate_metadata(data: bytes) -> dict[str, str]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReadbackError("ISO metadata JSON is invalid") from exc
    expected_url = f"https://github.com/{REPOSITORY}/attestations/{ISO_ATTESTATION_ID}"
    if not isinstance(value, dict) or value.get("iso") != ISO_NAME:
        raise ReadbackError("ISO metadata does not identify the pinned ISO")
    if value.get("attestation_url") != expected_url:
        raise ReadbackError("ISO metadata points to an unexpected attestation")
    if not isinstance(value.get("build_date"), str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value["build_date"]
    ):
        raise ReadbackError("ISO metadata build_date is missing or malformed")
    return {
        "iso": ISO_NAME,
        "attestation_url": expected_url,
        "build_date": value["build_date"],
    }


def validate_run_metadata(value: dict[str, Any], *, run_id: str, workflow: str) -> dict[str, Any]:
    expected_path = f".github/workflows/{workflow}.yml"
    if str(value.get("id")) != run_id:
        raise ReadbackError("Upstream Actions run ID mismatch")
    if value.get("path") != expected_path or value.get("head_sha") != SOURCE_COMMIT:
        raise ReadbackError("Upstream workflow path or source commit mismatch")
    if value.get("head_branch") != "main" or value.get("event") != "workflow_dispatch":
        raise ReadbackError("Upstream run was not dispatched from main")
    if value.get("status") != "completed" or value.get("conclusion") != "success":
        raise ReadbackError("Upstream build run did not complete successfully")
    return {
        "runId": run_id,
        "workflow": expected_path,
        "sourceCommit": SOURCE_COMMIT,
        "sourceRef": "refs/heads/main",
        "event": "workflow_dispatch",
        "conclusion": "success",
        "url": value.get("html_url"),
    }


def validate_attestation_report(
    value: Any, *, expected_digest: str, expected_workflow: str
) -> dict[str, Any]:
    entries = value if isinstance(value, list) else [value]
    found = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        verification = entry.get("verificationResult")
        statement = verification.get("statement") if isinstance(verification, dict) else None
        if not isinstance(statement, dict) or statement.get("predicateType") != PREDICATE_TYPE:
            continue
        subjects = statement.get("subject")
        if not isinstance(subjects, list):
            continue
        if any(
            isinstance(subject, dict)
            and isinstance(subject.get("digest"), dict)
            and subject["digest"].get("sha256") == expected_digest.removeprefix("sha256:")
            for subject in subjects
        ):
            found.append((entry, verification, statement))
    if len(found) != 1:
        raise ReadbackError("No unique SLSA provenance statement matches the downloaded digest")
    _, verification, statement = found[0]
    signature = verification.get("signature")
    certificate = signature.get("certificate") if isinstance(signature, dict) else None
    if not isinstance(certificate, dict) or not certificate:
        raise ReadbackError("Verified attestation JSON has no parsed signing certificate")
    timestamps = verification.get("verifiedTimestamps")
    if not isinstance(timestamps, list) or not timestamps:
        raise ReadbackError(
            "Verified attestation has no independently verified transparency timestamp"
        )
    if expected_workflow.endswith("/build_iso.yml"):
        expected_identity = (
            "https://github.com/ublue-os/bazzite/.github/workflows/build_iso.yml@refs/heads/main"
        )
        expected_run_id = "44121421800"
    elif expected_workflow.endswith("/build.yml"):
        expected_identity = (
            "https://github.com/ublue-os/bazzite/.github/workflows/build.yml@refs/heads/main"
        )
        expected_run_id = "44115557508"
    else:
        raise ReadbackError("Unexpected upstream signer workflow policy")
    certificate_checks = {
        "subjectAlternativeName": expected_identity,
        "issuer": "https://token.actions.githubusercontent.com",
        "githubWorkflowRepository": REPOSITORY,
        "githubWorkflowRef": "refs/heads/main",
        "sourceRepositoryURI": "https://github.com/ublue-os/bazzite",
        "sourceRepositoryDigest": SOURCE_COMMIT,
        "runnerEnvironment": "github-hosted",
    }
    for field, expected in certificate_checks.items():
        if certificate.get(field) != expected:
            raise ReadbackError(f"Attestation certificate {field} does not match pinned provenance")
    invocation = certificate.get("runInvocationURI", "")
    if f"/actions/runs/{expected_run_id}/" not in invocation:
        raise ReadbackError(
            "Attestation certificate invocation does not match the pinned upstream run"
        )
    return {
        "verifiedByGhCli": True,
        "predicateType": PREDICATE_TYPE,
        "subjectDigest": expected_digest,
        "signerWorkflowPolicy": expected_workflow,
        "certificateIdentity": certificate["subjectAlternativeName"],
        "sourceRepositoryDigest": certificate["sourceRepositoryDigest"],
        "sourceRepositoryRef": certificate["githubWorkflowRef"],
        "runInvocationURI": invocation,
        "runnerEnvironment": certificate["runnerEnvironment"],
        "verifiedTimestampCount": len(timestamps),
        "statementType": statement.get("_type"),
    }


def verify_embedded_blobs(
    image: dict[str, Any],
    manifest_bytes: bytes,
    config_bytes: bytes,
    *,
    expected_manifest_digest: str,
    expected_config_digest: str,
    expected_version: str,
) -> dict[str, Any]:
    image_id = str(image.get("id", "")).removeprefix("sha256:")
    config_hex = expected_config_digest.removeprefix("sha256:")
    if image_id != config_hex:
        raise ReadbackError("Embedded storage image ID does not match the pinned config digest")
    try:
        manifest = json.loads(manifest_bytes)
        config = json.loads(config_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReadbackError("Embedded OCI manifest or config is invalid") from exc
    manifest_sha = sha256_bytes(manifest_bytes)
    config_sha = sha256_bytes(config_bytes)
    if f"sha256:{manifest_sha}" != expected_manifest_digest:
        raise ReadbackError("Embedded OCI manifest digest mismatch")
    if f"sha256:{config_sha}" != expected_config_digest:
        raise ReadbackError("Embedded OCI config digest mismatch")
    manifest_config = manifest.get("config")
    if (
        not isinstance(manifest_config, dict)
        or manifest_config.get("digest") != expected_config_digest
    ):
        raise ReadbackError("Embedded manifest references a different config")
    labels = config.get("config", {}).get("Labels") or {}
    version_label = labels.get("org.opencontainers.image.version") or labels.get("version")
    if version_label is not None and version_label != expected_version:
        raise ReadbackError("Embedded OCI config has an unexpected version label")
    return {
        "storageImageId": image_id,
        "manifestSha256": manifest_sha,
        "configDigest": expected_config_digest,
        "configSha256": config_sha,
        "embeddedVersionLabel": version_label,
    }


def _unsquashfs(squashfs: Path, *args: str, binary: bool = False):
    try:
        command = (
            ["unsquashfs", "-cat", str(squashfs), *args[1:]]
            if args and args[0] == "-cat"
            else ["unsquashfs", *args, str(squashfs)]
        )
        return subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=not binary,
            timeout=900,
        ).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ReadbackError(f"unsquashfs read-only inspection failed: {exc}") from exc


def inspect_embedded_payload(
    squashfs: Path, *, diagnostics_path: Path | None = None
) -> dict[str, Any]:
    listing = _unsquashfs(squashfs, "-ll")
    paths = set()
    for line in listing.splitlines():
        if "squashfs-root/" in line:
            paths.add(line.split("squashfs-root/", 1)[1].strip())
    diagnostics: dict[str, Any] = {
        "listingEntryCount": len(paths),
        "storageRelatedPaths": sorted(
            path for path in paths
            if "containers/storage" in path
            or "overlay-images" in path
            or path.endswith("/images.json")
        )[:500],
        "imagesJsonCandidates": sorted(
            path for path in paths if path.endswith("images.json")
        )[:100],
    }

    def fail(message: str) -> None:
        if diagnostics_path is not None:
            diagnostics_path.parent.mkdir(parents=True, exist_ok=True)
            diagnostics_path.write_text(
                json.dumps(diagnostics, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        raise ReadbackError(message)

    image_files = sorted(p for p in paths if p.endswith("/overlay-images/images.json"))
    if len(image_files) != 1:
        fail("No unique embedded containers/storage images.json was found")
    images_path = image_files[0]
    images_bytes = _unsquashfs(squashfs, "-cat", images_path, binary=True)
    try:
        images_doc = json.loads(images_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail("Embedded images.json is invalid")
        raise AssertionError from exc
    images = images_doc.get("images") if isinstance(images_doc, dict) else images_doc
    if not isinstance(images, list):
        fail("Embedded images.json has an unsupported shape")
    names = {f"{PAYLOAD_IMAGE}:stable", PAYLOAD_TAG}
    matches = [
        item
        for item in images
        if isinstance(item, dict) and names.intersection(set(item.get("names") or []))
    ]
    diagnostics["imagesJsonPath"] = images_path
    diagnostics["imageRecordCount"] = len(images)
    diagnostics["matchingImageCount"] = len(matches)
    if len(matches) != 1:
        diagnostics["matchingNames"] = sorted(
            {
                name
                for item in images if isinstance(item, dict)
                for name in item.get("names", [])
                if "bazzite" in str(name).lower()
            }
        )[:100]
        fail("ISO does not contain one unique Bazzite install payload")
    image = matches[0]
    image_id = str(image.get("id", "")).removeprefix("sha256:")
    image_dir = Path(images_path).parent / image_id
    big_data_names = image.get("bigDataNames") or []
    candidates = {
        str(image_dir / "manifest"),
        str(image_dir / "manifest.json"),
        str(image_dir / "config"),
        str(image_dir / "config.json"),
    }
    for name in big_data_names:
        if isinstance(name, str) and name and "/" not in name and name not in {".", ".."}:
            candidates.add(str(image_dir / name))
    existing = sorted(path for path in candidates if path in paths)
    diagnostics["imageRecord"] = {
        "id": image_id,
        "names": sorted(image.get("names") or []),
        "recordKeys": sorted(image.keys()),
        "bigDataNames": big_data_names,
        "bigDataSizes": image.get("bigDataSizes"),
        "bigDataDigests": image.get("bigDataDigests"),
        "imageDirectory": str(image_dir),
        "candidateBlobPaths": sorted(candidates),
        "existingCandidatePaths": existing,
    }
    manifests = sorted(
        path for path in candidates
        if path in paths and Path(path).name in {"manifest", "manifest.json"}
    )
    configs = sorted(
        path for path in candidates
        if path in paths and Path(path).name in {"config", "config.json"}
    )
    if len(manifests) != 1 or len(configs) != 1:
        fail("ISO storage metadata does not expose one manifest and one config blob")
    manifest_bytes = _unsquashfs(squashfs, "-cat", manifests[0], binary=True)
    config_bytes = _unsquashfs(squashfs, "-cat", configs[0], binary=True)
    blob_evidence = verify_embedded_blobs(
        image,
        manifest_bytes,
        config_bytes,
        expected_manifest_digest=PAYLOAD_DIGEST,
        expected_config_digest=CONFIG_DIGEST,
        expected_version=PAYLOAD_VERSION,
    )
    result = {
        "image": PAYLOAD_IMAGE,
        "names": sorted(set(image.get("names") or [])),
        **blob_evidence,
        "manifestPath": manifests[0],
        "configPath": configs[0],
        "imagesJsonPath": images_path,
        "isoBooted": False,
        "readOnlySquashfsInspection": True,
    }
    if diagnostics_path is not None:
        diagnostics_path.parent.mkdir(parents=True, exist_ok=True)
        diagnostics_path.write_text(
            json.dumps(diagnostics, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return result
