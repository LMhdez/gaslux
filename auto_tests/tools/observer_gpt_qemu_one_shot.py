#!/usr/bin/env python3
"""One-shot synthetic GPT QEMU authorization and evidence verifier; never a writer."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import zlib
from datetime import datetime
from pathlib import Path

AUDITED = "dd3e7bf26e36499f89701393773df464ce713e4f"
SAFETY = "0be04192acd542646a5b6cd952e01620379edf5d"
REPO = "LMhdez/gaslux"
ACTOR = "LMhdez"
REF = "refs/heads/qemu-approved/observer-gpt-dd3e7bf2-20261121"
FILE = ".github/gpt-qemu-approvals/observer-gpt-dd3e7bf2-20261121.json"
REVIEW = "https://github.com/LMhdez/gaslux/pull/272#pullrequestreview-6004845263"
SIZE = 64 * 1024 * 1024
SECTOR = 512


class Refused(ValueError):
    """A negative authorization or provenance check is terminal."""


def require(check: bool, reason: str) -> None:
    if not check:
        raise Refused(reason)


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_approval() -> dict:
    return {
        "authorizationKind": "ONE_SYNTHETIC_GPT_READONLY_QEMU",
        "repository": REPO,
        "approvedCodeSha": AUDITED,
        "safetySourceSha": SAFETY,
        "authorizationRef": REF,
        "reviewUrl": REVIEW,
        "humanApproved": True,
        "singleRun": True,
        "inputAuthorized": False,
        "diskWritesAuthorized": False,
        "productionInstallationAuthorized": False,
        "productionWriteAuthorized": False,
    }


def validate_trigger(event: dict, approval: dict, env: dict) -> None:
    require(env.get("GITHUB_ACTOR") == ACTOR, "WRONG_GITHUB_ACTOR")
    require(env.get("GITHUB_REPOSITORY") == REPO, "WRONG_GITHUB_REPOSITORY")
    require(env.get("GITHUB_RUN_ATTEMPT") == "1", "RERUN_REFUSED")
    require(env.get("GITHUB_ACTIONS") == "true", "NOT_GITHUB_ACTIONS")
    require(env.get("RUNNER_ENVIRONMENT") == "github-hosted", "WRONG_RUNNER")
    require(event.get("ref") == REF, "WRONG_AUTHORIZATION_BRANCH")
    require(event.get("repository", {}).get("full_name") == REPO, "WRONG_EVENT_REPO")
    require(
        event.get("created") is False
        and event.get("deleted") is False
        and event.get("forced") is False,
        "BRANCH_CREATION_OR_FORCE_PUSH_REFUSED",
    )
    previous, current = event.get("before"), event.get("after")
    require(
        isinstance(previous, str)
        and isinstance(current, str)
        and bool(re.fullmatch("[a-f0-9]{40}", previous))
        and bool(re.fullmatch("[a-f0-9]{40}", current))
        and previous != "0" * 40
        and previous != current,
        "UNBOUND_COMMIT_IDENTITY",
    )
    commits = event.get("commits")
    require(
        type(commits) is list
        and len(commits) == 1
        and commits[0].get("id") == current
        and event.get("head_commit", {}).get("id") == current,
        "NOT_ONE_COMMIT",
    )
    require(
        commits[0].get("added") == [FILE]
        and commits[0].get("modified") == []
        and commits[0].get("removed") == [],
        "AUTHORIZATION_MUST_BE_ONE_NEW_FILE",
    )
    require(approval == expected_approval(), "APPROVAL_CONTENT_INVALID")


def validate_git(
    root: Path,
    event: dict,
    *,
    trusted_preparation_sha: str | None = None,
    trusted_authorization_sha: str | None = None,
    unused_external_grant: bool = False,
) -> None:
    """Require exact pins supplied by a separately protected controller.

    A GitHub event or untrusted approval JSON MUST NEVER be used as the source
    of these pins. The current feature-branch workflow is permanently disabled;
    until the protected controller and its durable single-use grant exist,
    preflight cannot pass. This method cannot authenticate its own caller.
    """
    require(
        isinstance(trusted_preparation_sha, str)
        and bool(re.fullmatch("[a-f0-9]{40}", trusted_preparation_sha)),
        "TRUSTED_PREPARATION_MISSING",
    )
    require(
        isinstance(trusted_authorization_sha, str)
        and bool(re.fullmatch("[a-f0-9]{40}", trusted_authorization_sha)),
        "TRUSTED_AUTHORIZATION_COMMIT_MISSING",
    )
    require(unused_external_grant is True, "EXTERNAL_SINGLE_USE_GRANT_MISSING_OR_CONSUMED")

    def git(*args: str) -> str:
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()

    require(
        event.get("before") == trusted_preparation_sha,
        "UNAPPROVED_PREPARATION_PARENT",
    )
    require(
        event.get("after") == trusted_authorization_sha,
        "UNAPPROVED_AUTHORIZATION_COMMIT",
    )
    require(git("rev-parse", "HEAD") == trusted_authorization_sha, "UNEXPECTED_TRIGGER_CHECKOUT")
    require(git("rev-parse", "HEAD^") == trusted_preparation_sha, "UNEXPECTED_PARENT_COMMIT")
    require(
        git("diff-tree", "--no-commit-id", "--name-status", "-r", "HEAD") == "A\t" + FILE,
        "GIT_DIFF_NOT_EXCLUSIVE_APPROVAL",
    )
    # Equality to the externally pinned preparation commit is mandatory.
    # Mere descendant checks accepted unreviewed workflow/preflight ancestors.
    require(git("rev-parse", "HEAD^") == trusted_preparation_sha, "UNAPPROVED_PARENT")
    require(
        not (root / FILE).is_symlink() and (root / FILE).is_file(),
        "APPROVAL_NOT_REGULAR_FILE",
    )


def verify_evidence(folder: Path) -> dict:
    """Recheck locally captured GPT sample hashes, CRCs, chronology and no-write claims."""
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    safety = json.loads((folder / "safety-gpt-provenance-v1.json").read_text(encoding="utf-8"))
    require(
        manifest.get("status") == "LABORATORY_ONLY"
        and manifest.get("classification") == "NOT_INDEPENDENT"
        and manifest.get("safetyAssessment") == "DIAGNOSTIC_ONLY"
        and manifest.get("sourceCommitSafety") == SAFETY
        and manifest.get("diskSynthetic") is True
        and manifest.get("windowsGenuine") is False,
        "LAB_CLASSIFICATION_INVALID",
    )
    for name in (
        "productionWriteAuthorized",
        "inputAuthorized",
        "diskWritesAuthorized",
        "productionInstallationAuthorized",
        "guestInputAuthorized",
        "diskWriterCalled",
    ):
        require(manifest.get(name) is False, "FORBIDDEN_AUTHORIZATION_" + name)
    for name in (
        "guestCapturedWithLibguestfsPreadDevice",
        "immediateCapturedFromFreshQcow2Export",
        "immediateQemuProcessAlreadyTerminated",
        "qemuProcessTerminated",
        "backingPreserved",
        "overlayPreserved",
    ):
        require(manifest.get(name) is True, "EVIDENCE_MISSING_" + name)
    require(
        manifest.get("guestInputs") == 0
        and manifest.get("qemu", {}).get("qemuKvmObserved") is True,
        "QEMU_PREAD_OR_KVM_MISSING",
    )
    require(
        safety.get("contractVersion") == 1
        and safety.get("classification") == "NOT_INDEPENDENT"
        and safety.get("writeAuthorized") is False
        and safety.get("purpose") == "read-only-diagnostic"
        and safety.get("qemu", {}).get("virtualSizeBytes") == SIZE
        and safety.get("qemu", {}).get("logicalSectorSizeBytes") == SECTOR,
        "SAFETY_V1_INVALID",
    )
    records = safety.get("measurements")
    require(
        type(records) is list
        and [m.get("source") for m in records] == ["host", "guest", "immediate"],
        "THREE_WAY_MEASUREMENTS_MISSING",
    )
    paths, times, identities = [], [], []
    for i, kind in enumerate(("host", "guest", "immediate")):
        name = kind + "-read-trace.json"
        path = folder / name
        trace = json.loads(path.read_text(encoding="utf-8"))
        digest = hashlib.sha256(
            json.dumps(trace, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
                "ascii"
            )
        ).hexdigest()
        require(
            trace.get("source") == kind
            and trace.get("readOnly") is True
            and trace.get("noInput") is True
            and trace.get("classification") == "NOT_INDEPENDENT"
            and trace.get("productionWriteAuthorized") is False
            and trace.get("fileSizeBytes") == SIZE
            and trace.get("logicalSectorSizeBytes") == SECTOR
            and records[i]["originProof"]["evidenceSha256"] == digest
            and manifest.get("fileSha256", {}).get(name) == sha(path),
            "TRACE_INVALID_" + kind,
        )
        for key in ("primaryHeader", "primaryArray", "backupHeader", "backupArray"):
            value = trace["samples"][key]
            data = base64.b64decode(trace["sampleBytesBase64"][key], validate=True)
            require(
                len(data) == value["lengthBytes"]
                and hashlib.sha256(data).hexdigest() == value["sha256"],
                "SAMPLE_SHA_INVALID_" + key,
            )
            if key.endswith("Header"):
                header_length = int.from_bytes(data[12:16], "little")
                require(92 <= header_length <= SECTOR, "BAD_GPT_HEADER_LENGTH")
                normalized = bytearray(data[:header_length])
                normalized[16:20] = b"\x00" * 4
                crc = zlib.crc32(normalized)
            else:
                crc = zlib.crc32(data)
            require(crc == value["crc32"], "SAMPLE_CRC_INVALID_" + key)
        require(
            trace["samples"]["primaryHeader"]["offsetBytes"] == SECTOR
            and trace["samples"]["backupHeader"]["offsetBytes"] == SIZE - SECTOR,
            "SAMPLE_OFFSET_INVALID",
        )
        paths.append(Path(trace["imageFile"]))
        identities.append((trace["fileDev"], trace["fileInode"]))
        times.append(datetime.fromisoformat(trace["observedAt"]))
    require(
        [p.name for p in paths] == ["host.raw", "guest-reconstructed.raw", "immediate.raw"]
        and len(set(map(str, paths))) == 3
        and paths[0].parent == paths[1].parent == paths[2].parent
        and len(set(identities)) == 3
        and times[0] <= times[1] <= times[2],
        "IMMEDIATE_NOT_FRESHLY_OBSERVED",
    )
    require(
        records[0]["gpt"] == records[1]["gpt"] == records[2]["gpt"]
        and records[0]["gptSectors"] == records[1]["gptSectors"] == records[2]["gptSectors"],
        "GPT_THREE_WAY_MISMATCH",
    )
    gpt = records[0]["gpt"]
    require(
        gpt["partitionStyle"] == "GPT"
        and gpt["sizeBytes"] == SIZE
        and gpt["logicalSectorSizeBytes"] == SECTOR
        and gpt["partitionTableId"].startswith("gpt:")
        and all(p.get("partGuid") for p in gpt["partitions"]),
        "GPT_GUID_GEOMETRY_INVALID",
    )
    chain = manifest["backingChain"]
    require(
        chain["format"] == "qcow2"
        and chain["backingFormat"] == "raw"
        and chain["virtualSizeBytes"] == SIZE
        and chain["overlaySha256"] == safety["backingChain"][0]["sha256"]
        and chain["backingSha256"] == safety["backingChain"][1]["sha256"]
        and manifest.get("fileSha256", {}).get("safety-gpt-provenance-v1.json")
        == sha(folder / "safety-gpt-provenance-v1.json"),
        "BACKING_OR_SAFETY_HASH_INVALID",
    )
    summary = json.loads((folder / "lab-result-summary.json").read_text(encoding="utf-8"))
    require(
        summary.get("status") == "LABORATORY_ONLY"
        and summary.get("classification") == "NOT_INDEPENDENT"
        and summary.get("diagnostic") == "DIAGNOSTIC_ONLY"
        and summary.get("guestRealPread") is True
        and summary.get("guestInputCount") == 0
        and summary.get("writerCalled") is False
        and summary.get("ephemeralDiskRemoved") is True,
        "LAB_RESULT_SUMMARY_INVALID",
    )
    return {
        "status": "READONLY_DIAGNOSTIC_VALIDATED",
        "auditedCodeSha": AUDITED,
        "pinnedSafetySha": SAFETY,
        "classification": "NOT_INDEPENDENT",
        "safetyAssessment": "DIAGNOSTIC_ONLY",
        "inputAuthorized": False,
        "diskWritesAuthorized": False,
        "productionInstallationAuthorized": False,
        "productionWriteAuthorized": False,
        "independentAttestation": False,
        "windowsGenuine": False,
        "rollbackProven": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("preflight", "verify"))
    parser.add_argument("--checkout", type=Path)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    folder = args.evidence.resolve(strict=True)
    require(folder.is_dir() and not folder.is_symlink(), "EVIDENCE_DIR_INVALID")
    if args.operation == "preflight":
        require(args.checkout is not None, "CHECKOUT_MISSING")
        root = args.checkout.resolve(strict=True)
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        approval = json.loads((root / FILE).read_text(encoding="utf-8"))
        validate_trigger(event, approval, dict(os.environ))
        # Deliberately no trusted preparation/authorization SHA nor durable
        # single-use grant is accepted from the branch, JSON or process env.
        # A separately protected default-branch controller must eventually
        # call validate_git with independently reviewed pins and an atomic
        # external grant before enabling any QEMU run. This entrypoint FAILS.
        validate_git(root, event)
        result = {
            "status": "AUTHORIZED_TRIGGER_ONLY",
            "auditedCodeSha": AUDITED,
            "pinnedSafetySha": SAFETY,
            "authorizationSha256": sha(root / FILE),
            "triggerSha": event["after"],
            "actor": ACTOR,
            "runAttempt": 1,
            "inputAuthorized": False,
            "diskWritesAuthorized": False,
            "productionInstallationAuthorized": False,
        }
        filename = "authorization-intent.json"
    else:
        result = verify_evidence(folder)
        filename = "evidence-verification.json"
    with (folder / filename).open("x", encoding="utf-8") as out:
        json.dump(result, out, sort_keys=True, indent=2)
        out.write("\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Refused, KeyError, ValueError, OSError, subprocess.CalledProcessError) as exc:
        print("BLOCKED_FAIL_CLOSED: " + str(exc), file=sys.stderr)
        raise SystemExit(2) from exc
