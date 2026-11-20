#!/usr/bin/env python3
"""Fail-closed preflight for ONE passive, no-input Bazzite 45 QEMU live-ISO boot.

This consumes the current run's signed ISO + OCI readback. It cannot authorize
installation, guest control, partition writes, or a D-Bus command channel.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from bazzite_iso_public_readback import (
    CONFIG_DIGEST,
    ISO_NAME,
    ISO_SHA256,
    PAYLOAD_DIGEST,
    PAYLOAD_VERSION,
)

ISO_SIZE = 8377878528
SERIAL = "GLXBAZRO001"
SHA = re.compile(r"[0-9a-f]{64}\Z")


class Refusal(ValueError):
    """Missing provenance, foreign file or unsupported operation."""


def _deny(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def validate_record(candidate: dict, report: dict, facts: dict) -> dict:
    """Require a terminal Result A and the exact embedded OCI digest chain."""
    if not all(isinstance(x, dict) for x in (candidate, report, facts)):
        raise Refusal("Missing bounded proof documents")
    public = candidate.get("publicReadback")
    payload = report.get("embeddedPayload")
    source = report.get("publicReadback")
    run = report.get("runStatus")
    if not all(isinstance(x, dict) for x in (public, payload, source, run)):
        raise Refusal("Missing ISO readback proof")
    if candidate.get("result") != "A" or report.get("result") != "A":
        raise Refusal("Not an authenticated Result A")
    if not (
        candidate.get("evidenceRecordOnly") is True
        and candidate.get("installationAuthorized") is False
        and report.get("installationAuthorized") is False
    ):
        raise Refusal("Unsafe installation authority")
    if not (
        public.get("workflowRunId") == 44759529218
        and public.get("terminalRunExitCode") == 0
        and public.get("terminalZipSha256")
        == "1ad0ccbfec8b2316c89aac9bf58067d73a2541d734c7fcff3e053dd55757fee2"
    ):
        raise Refusal("Unreconciled terminal provenance ledger")
    if any(key in public for key in ("runFailedStage", "runFailureReason")):
        raise Refusal("Stale failed-run state")
    if not (
        run == {"exitCode": "0", "failedStage": "complete"}
        and public.get("failureStage") == "complete"
        and public.get("failureReason") is None
    ):
        raise Refusal("Incomplete run")
    outcomes = report.get("workflowOutcomes")
    if not (
        isinstance(outcomes, dict)
        and len(outcomes) == 5
        and all(value == "success" for value in outcomes.values())
    ):
        raise Refusal("Missing upstream Cosign/OCI verification stage")
    if not (
        report.get("candidate", {}).get("expectedIsoSha256") == ISO_SHA256
        and candidate.get("artifact", {}).get("sha256") == ISO_SHA256
        and candidate.get("artifact", {}).get("sizeBytes") == ISO_SIZE
        and candidate.get("artifact", {}).get("version") == PAYLOAD_VERSION
    ):
        raise Refusal("Wrong version, size or ISO digest")
    if not (
        report.get("candidate", {}).get("expectedPayloadDigest") == PAYLOAD_DIGEST
        and report.get("candidate", {}).get("expectedConfigDigest") == CONFIG_DIGEST
        and candidate.get("payload", {}).get("digest") == PAYLOAD_DIGEST
        and candidate.get("payload", {}).get("configDigest") == CONFIG_DIGEST
    ):
        raise Refusal("Wrong signed Atomic payload")
    required = (
        "checksumVerified",
        "cosignIsoVerified",
        "isoAttestationVerified",
        "payloadCosignVerified",
        "payloadAttestationVerified",
        "payloadConfigBlobVerified",
        "embeddedPayloadVerified",
        "isoMountedReadOnly",
    )
    if not (
        facts.get("sha256") == ISO_SHA256
        and facts.get("sizeBytes") == ISO_SIZE
        and all(facts.get(name) is True for name in required)
    ):
        raise Refusal("Unsigned or incomplete ISO verification")
    config_blob = payload.get("verifiedConfigBlob")
    if not (
        isinstance(config_blob, dict)
        and payload.get("manifestDigest") == PAYLOAD_DIGEST
        and payload.get("configDigestFromManifest") == CONFIG_DIGEST
        and config_blob.get("configDigest") == CONFIG_DIGEST
        and config_blob.get("configBytesSha256Verified") is True
        and payload.get("configBlobRetrievedFromISO") is False
        and source.get("embeddedPayloadVerified") is True
        and source.get("isoMountedReadOnly") is True
    ):
        raise Refusal("Embedded OCI chain not authenticated")
    policy = report.get("policy")
    if not (
        isinstance(policy, dict)
        and policy.get("isoBooted") is False
        and policy.get("diskWrites") is False
        and policy.get("nvramWrites") is False
    ):
        raise Refusal("Unexpected past runtime authority")
    return {
        "readbackResult": "A",
        "isoSha256": ISO_SHA256,
        "ociManifestDigest": PAYLOAD_DIGEST,
        "configDigest": CONFIG_DIGEST,
        "installationAuthorized": False,
        "guestCommandChannelAuthorized": False,
    }


def verify_iso_file(path: Path, runner_temp: Path) -> dict:
    """Only read the pinned ISO located inside the current runner's workdir."""
    runner = runner_temp.resolve(strict=True)
    expected = runner / "bazzite-iso-public-readback-work" / ISO_NAME
    _deny(not path.is_symlink() and path.absolute() == expected, "Foreign ISO path")
    _deny(not expected.is_symlink() and expected.is_file(), "Missing or redirected ISO")
    info = os.stat(expected, follow_symlinks=False)
    _deny(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == ISO_SIZE,
        "ISO inode, link count or size mismatch",
    )
    digest = hashlib.sha256()
    with expected.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    _deny(digest.hexdigest() == ISO_SHA256, "ISO bytes differ from signed version")
    return {"sha256": digest.hexdigest(), "sizeBytes": info.st_size, "isoReadOnly": True}


def classify(ocr_records: list[str], guest_running: bool) -> dict:
    """OCR is passive evidence only; neither OCR nor graphics authorize clicks."""
    combined = "\n".join(ocr_records).casefold()
    bazzite = "bazzite" in combined
    installer = bazzite and any(
        mark in combined
        for mark in (
            "select installation target",
            "installation destination",
            "choose installation disk",
            "select a destination",
        )
    )
    live = bazzite and any(
        mark in combined
        for mark in (
            "live session",
            "welcome to bazzite",
            "install bazzite",
            "bazzite desktop",
            "live desktop",
        )
    )
    if guest_running and installer:
        result, reason = "A", "Bazzite installer destination screen observed passively"
    elif guest_running and live:
        result, reason = "B", "Bazzite live UI observed; installer not identified"
    else:
        result, reason = "C", "Bazzite live environment not proven by bounded OCR"
    return {
        "result": result,
        "reason": reason,
        "liveEnvironmentRecognized": bool(guest_running and (installer or live)),
        "installerInterfaceIdentified": bool(guest_running and installer),
        "anacondaDbusServiceObserved": False,
        "getActionsObserved": False,
        "guestCommandChannelAuthorized": False,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "nvramWriteAuthorized": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--facts", type=Path, required=True)
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--runner-temp", type=Path, required=True)
    args = parser.parse_args()
    try:
        records = []
        for path in (args.candidate, args.report, args.facts):
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
                raise Refusal("Missing or redirected evidence record")
            records.append(json.loads(path.read_text(encoding="utf-8")))
        proof = validate_record(*records)
        proof["measured"] = verify_iso_file(args.iso, args.runner_temp)
    except (Refusal, OSError, ValueError, UnicodeError, KeyError, TypeError) as exc:
        parser.exit(2, f"REFUSED_NO_BOOT: {exc}\n")
    print(json.dumps(proof, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
