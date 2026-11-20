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


def parse_checksum(data: bytes, iso_name: str = ISO_NAME) -> str:
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ReadbackError("Checksum sidecar is not ASCII") from exc
    matches = []
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64})\\s+\\*?(.+)", line.strip())
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
        r"\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z", value["build_date"]
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
    entry, verification, statement = found[0]
    certificate = verification.get("signature", {}).get("certificate", {})
    if not isinstance(certificate, dict) or not certificate:
        raise ReadbackError("Verified attestation JSON has no parsed signing certificate")
    return {
        "verifiedByGhCli": True,
        "predicateType": PREDICATE_TYPE,
        "subjectDigest": expected_digest,
        "signerWorkflowPolicy": expected_workflow,
        "certificatePresent": True,
        "verifiedTimestampCount": len(verification.get("verifiedTimestamps", [])),
        "statementType": statement.get("_type"),
    }


def _unsquashfs(squashfs: Path, *args: str, binary: bool = False):
    try:
        return subprocess.run(
            ["unsquashfs", *args, str(squashfs)],
            check=True,
            capture_output=True,
            text=not binary,
            timeout=900,
        ).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ReadbackError(f"unsquashfs read-only inspection failed: {exc}") from exc


def inspect_embedded_payload(squashfs: Path) -> dict[str, Any]:
    listing = _unsquashfs(squashfs, "-ll")
    paths = set()
    for line in listing.splitlines():
        if "squashfs-root/" in line:
            paths.add(line.split("squashfs-root/", 1)[1].strip())
    image_files = sorted(p for p in paths if p.endswith("/overlay-images/images.json"))
    if len(image_files) != 1:
        raise ReadbackError("No unique embedded containers/storage images.json was found")
    images_path = image_files[0]
    images_bytes = _unsquashfs(squashfs, "-cat", images_path, binary=True)
    try:
        images_doc = json.loads(images_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReadbackError("Embedded images.json is invalid") from exc
    images = images_doc.get("images") if isinstance(images_doc, dict) else images_doc
    if not isinstance(images, list):
        raise ReadbackError("Embedded images.json has an unsupported shape")
    names = {f"{PAYLOAD_IMAGE}:stable", PAYLOAD_TAG}
    matches = [
        item for item in images
        if isinstance(item, dict) and names.intersection(set(item.get("names") or []))
    ]
    if len(matches) != 1:
        raise ReadbackError("ISO does not contain one unique Bazzite install payload")
    image = matches[0]
    image_id = str(image.get("id", "")).removeprefix("sha256:")
    config_hex = CONFIG_DIGEST.removeprefix("sha256:")
    if image_id != config_hex:
        raise ReadbackError("Embedded storage image ID does not match the pinned config digest")

    image_dir = Path(images_path).parent / image_id
    candidates = {
        str(image_dir / "manifest"),
        str(image_dir / "manifest.json"),
        str(image_dir / "config"),
        str(image_dir / "config.json"),
    }
    for name in image.get("bigDataNames") or []:
        if name in {"manifest", "manifest.json", "config", "config.json"}:
            candidates.add(str(image_dir / name))
    manifests = sorted(
        p for p in candidates if p in paths and Path(p).name in {"manifest", "manifest.json"}
    )
    configs = sorted(
        p for p in candidates if p in paths and Path(p).name in {"config", "config.json"}
    )
    if len(manifests) != 1 or len(configs) != 1:
        raise ReadbackError("ISO storage metadata does not expose one manifest and one config blob")
    manifest_bytes = _unsquashfs(squashfs, "-cat", manifests[0], binary=True)
    config_bytes = _unsquashfs(squashfs, "-cat", configs[0], binary=True)
    try:
        manifest = json.loads(manifest_bytes)
        config = json.loads(config_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReadbackError("Embedded OCI manifest or config is invalid") from exc
    manifest_sha = sha256_bytes(manifest_bytes)
    config_sha = sha256_bytes(config_bytes)
    if f"sha256:{manifest_sha}" != PAYLOAD_DIGEST:
        raise ReadbackError("Embedded OCI manifest digest mismatch")
    if f"sha256:{config_sha}" != CONFIG_DIGEST:
        raise ReadbackError("Embedded OCI config digest mismatch")
    if not isinstance(manifest.get("config"), dict) or manifest["config"].get("digest") != CONFIG_DIGEST:
        raise ReadbackError("Embedded manifest references a different config")
    labels = config.get("config", {}).get("Labels") or {}
    version_label = labels.get("org.opencontainers.image.version") or labels.get("version")
    if version_label is not None and version_label != PAYLOAD_VERSION:
        raise ReadbackError("Embedded OCI config has an unexpected version label")
    return {
        "image": PAYLOAD_IMAGE,
        "names": sorted(set(image.get("names") or [])),
        "storageImageId": image_id,
        "manifestSha256": manifest_sha,
        "configDigest": CONFIG_DIGEST,
        "configSha256": config_sha,
        "embeddedVersionLabel": version_label,
        "manifestPath": manifests[0],
        "configPath": configs[0],
        "imagesJsonPath": images_path,
        "isoBooted": False,
        "readOnlySquashfsInspection": True,
    }
