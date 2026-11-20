#!/usr/bin/env python3
"""Read-only verification of four pinned Q4OS historical GitHub Actions ZIPs.

Offline verifier: ZIP files and Actions artifact metadata must be supplied
separately. This program does not contact GitHub, QEMU, VNC or any guest.
"""

from __future__ import annotations

import argparse
import json
import stat
import zipfile
from pathlib import Path

from auto_tests.installer_observer import q4os
from auto_tests.installer_observer.evidence import Refusal, canonical, digest, parse, read
from auto_tests.installer_observer.screenshot import MAX_PNG, Screenshot

MAX_ARCHIVE = 16 * 1024 * 1024
EXPECTED_ARTIFACTS = (14587306682, 14586773677, 14590616864, 14589299655)
EXPECTED_RUNS = (44641233701, 44641233701, 44648406729, 44648406729)


def validate_archives(zip_dir: Path, metadata_dir: Path, originals: Path) -> dict:
    manifest = parse(read(q4os.MANIFEST))
    if digest(canonical(manifest)) != q4os.MANIFEST_SHA:
        raise Refusal("Pinned historical manifest changed")
    archive_by_id = {a["artifactId"]: a for a in manifest["archives"]}
    runs = manifest["runs"] + manifest["summaryRuns"]
    if len(archive_by_id) != 4 or len(runs) != 4:
        raise Refusal("Original four-session manifest is incomplete")
    if tuple(r["artifactId"] for r in runs) != EXPECTED_ARTIFACTS:
        raise Refusal("Historical artifact order or identity changed")
    if tuple(int(r["runId"]) for r in runs) != EXPECTED_RUNS:
        raise Refusal("Historical Actions run identity changed")
    frames = transitions = 0
    for run in runs:
        aid = run["artifactId"]
        expected = archive_by_id[aid]
        report_names = set(expected["reports"])
        png_names = {r["path"] for r in run["screenshots"]}
        if len(png_names) != len(run["screenshots"]) or any(
            not name.endswith(".png") for name in png_names
        ):
            raise Refusal("Duplicate or unexpected historical screenshot name")
        expected_names = report_names | png_names
        if len(expected_names) != len(png_names) + len(report_names):
            raise Refusal("Overlapping original PNG and report names")
        metadata = parse(read(metadata_dir / f"{aid}.json", 64 * 1024))
        workflow = metadata.get("workflow_run")
        if (
            metadata.get("id") != aid
            or metadata.get("name") != expected["name"]
            or metadata.get("expired") is not False
            or metadata.get("digest") != "sha256:" + expected["archiveSha256"]
            or not isinstance(workflow, dict)
            or workflow.get("id") != int(run["runId"])
            or workflow.get("head_sha") != expected["workflowCommit"]
        ):
            raise Refusal(f"GitHub artifact identity/provenance mismatch: {aid}")
        path = zip_dir / f"{aid}.zip"
        binary = read(path, MAX_ARCHIVE)
        if digest(binary) != expected["archiveSha256"]:
            raise Refusal(f"Historical ZIP SHA-256 mismatch: {aid}")
        try:
            with zipfile.ZipFile(path) as archive:
                members = archive.infolist()
                actual = [entry.filename for entry in members]
                required = {"evidence/" + name for name in expected_names}
                if len(set(actual)) != len(actual) or not required.issubset(actual):
                    raise Refusal(
                        f"Original artifact ZIP member mismatch: {aid}: "
                        f"missing={sorted(required - set(actual))}"
                    )
                # The pinned original ZIP includes additional QEMU/Calamares
                # inspection files. Those bytes are covered by the exact
                # archive SHA-256 and GitHub's independently recorded digest.
                # The verifier NEVER extracts or executes any member.
                total_uncompressed = 0
                for entry in members:
                    name = entry.filename
                    parts = name.split("/")
                    mode = (entry.external_attr >> 16) & 0o170000
                    total_uncompressed += entry.file_size
                    if (
                        entry.is_dir()
                        or mode not in (0, stat.S_IFREG)
                        or not all(parts)
                        or any(part in (".", "..") for part in parts)
                        or parts[0] not in ("evidence", "calamares-inspect")
                        or len(parts) < 2
                        or "\\" in name
                        or ":" in name
                        or entry.file_size > MAX_ARCHIVE
                        or total_uncompressed > 128 * 1024 * 1024
                    ):
                        raise Refusal(f"Unsafe historical ZIP member: {name!r}")
                    if name not in required:
                        continue
                    short_name = name.removeprefix("evidence/")
                    data = archive.read(entry)
                    local = read(originals / str(aid) / short_name, MAX_PNG)
                    if data != local:
                        raise Refusal(f"GitHub artifact differs from pinned Git blob: {aid}")
                    if short_name in report_names:
                        if digest(data) != expected["reports"][short_name]:
                            raise Refusal(f"Original report SHA-256 mismatch: {aid}")
                    else:
                        frame = next(x for x in run["screenshots"] if x["path"] == short_name)
                        Screenshot.decode(data, (1280, 800), frame["sha256"])
        except (zipfile.BadZipFile, EOFError, RuntimeError) as exc:
            raise Refusal(f"Historical ZIP invalid: {aid}") from exc
        frames += len(run["screenshots"])
        transitions += len(run["transitions"])
    if (frames, transitions) != (40, 36):
        raise Refusal("Historical screenshot/transition totals changed")
    return {
        "verified_artifacts": list(EXPECTED_ARTIFACTS),
        "screenshots": frames,
        "historical_edges": transitions,
        "guest_input_events": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip-dir", required=True, type=Path)
    parser.add_argument("--metadata-dir", required=True, type=Path)
    parser.add_argument("--originals", type=Path, default=q4os.ORIGINALS)
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                validate_archives(args.zip_dir, args.metadata_dir, args.originals), sort_keys=True
            )
        )
        return 0
    except (OSError, ValueError) as exc:
        parser.exit(1, f"REFUSE_Q4OS_ARCHIVE_PROVENANCE: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
