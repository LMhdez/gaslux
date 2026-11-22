#!/usr/bin/env python3
"""Offline, fail-closed matching of the four pinned Q4OS historical archives.

No guest, GUI, replay, network, extraction, storage writer, or external attestation.
Provided GitHub metadata is UNTRUSTED; equality cannot prove GitHub provenance.
"""
from __future__ import annotations

import argparse
import io
import json
import re
import stat
import struct
import zipfile
import zlib
from pathlib import Path

from auto_tests.installer_observer.evidence import Refusal, canonical, digest, parse, read

MANIFEST_SHA = "e28485fc2e2ce8536c5e8f4dab30c4f0b44de74a70dece9b4897155e43598956"
ARTIFACTS = (14587306682, 14586773677, 14590616864, 14589299655)
RUNS = (44641233701, 44641233701, 44648406729, 44648406729)
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_ENTRY = 16 * 1024 * 1024
MAX_PNG = 2 * 1024 * 1024
MAX_RATIO = 1000
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Refusal(reason)


def _pin_manifest(path: Path) -> dict:
    manifest = parse(read(path, 1024 * 1024))
    require(digest(canonical(manifest)) == MANIFEST_SHA, "Pinned manifest digest mismatch")
    require(manifest.get("distribution") == "q4os" and manifest.get("schemaVersion") == 1,
            "Wrong manifest identity")
    return manifest


def _name(name: str) -> bool:
    """Strictly canonical two-component member, not filesystem path interpretation."""
    parts = name.split("/")
    return (
        len(parts) == 2 and parts[0] in ("evidence", "calamares-inspect")
        and SAFE_NAME.fullmatch(parts[1]) is not None
        and parts[1] not in (".", "..")
        and not parts[1].endswith(".")
        and parts[1].split(".")[0].upper() not in {"CON", "PRN", "AUX", "NUL"}
    )


def _png(data: bytes) -> None:
    """Bounded, structural PNG check, without OCR or image processing."""
    require(len(data) <= MAX_PNG and data.startswith(PNG_SIGNATURE), "Invalid PNG signature/size")
    offset = 8
    seen = []
    width = height = None
    while offset < len(data):
        require(offset + 12 <= len(data), "Truncated PNG chunk")
        size = int.from_bytes(data[offset:offset + 4], "big")
        kind = data[offset + 4:offset + 8]
        end = offset + 12 + size
        require(size <= MAX_PNG and end <= len(data), "Oversized PNG chunk")
        payload = data[offset + 8:offset + 8 + size]
        crc = int.from_bytes(data[offset + 8 + size:end], "big")
        require(zlib.crc32(kind + payload) & 0xffffffff == crc, "Invalid PNG CRC")
        if not seen:
            require(kind == b"IHDR" and size == 13, "PNG IHDR absent")
            width, height = struct.unpack(">II", payload[:8])
            require((width, height) == (1280, 800), "Unexpected PNG resolution")
            require(
                payload[10:13] == b"\x00\x00\x00",
                "Unsupported PNG compression/filter/interlace",
            )
        if kind == b"IEND":
            require(size == 0 and end == len(data), "Nonterminal PNG IEND")
            seen.append(kind)
            break
        require(kind not in (b"IHDR", b"IEND") or not seen, "Duplicate PNG header")
        seen.append(kind)
        offset = end
    require(seen and seen[-1] == b"IEND" and b"IDAT" in seen, "Incomplete PNG")


def _check_zip(binary: bytes, expected: dict, run: dict, aid: int) -> None:
    reports = expected["reports"]
    shots = run["screenshots"]
    require(isinstance(reports, dict) and isinstance(shots, list), "Missing archive entries")
    expected_png = {s["path"]: s["sha256"] for s in shots}
    require(len(expected_png) == len(shots), "Duplicate screenshot declaration")
    require(all(SHA256.fullmatch(v) for v in (*reports.values(), *expected_png.values())),
            "Invalid pinned member digest")
    required = {"evidence/" + name for name in (*reports, *expected_png)}
    require(len(required) == len(reports) + len(expected_png), "Overlapping report and PNG")
    try:
        with zipfile.ZipFile(io.BytesIO(binary)) as archive:
            entries = archive.infolist()
            require(entries and len(entries) <= 512, "Invalid member count")
            names = [x.filename for x in entries]
            require(len(names) == len(set(names)), "Duplicate ZIP member")
            require(required.issubset(names), "Missing pinned ZIP member")
            total = 0
            for entry in entries:
                name = entry.filename
                mode = (entry.external_attr >> 16) & 0o170000
                require(_name(name) and not entry.is_dir() and mode in (0, stat.S_IFREG),
                        "Unsafe or unexpected ZIP member")
                require(not entry.flag_bits & 0x1, "Encrypted ZIP member")
                require(entry.file_size <= MAX_ENTRY and entry.compress_size <= MAX_ARCHIVE,
                        "Oversized ZIP member")
                require(entry.compress_size > 0 or entry.file_size == 0, "Invalid compressed size")
                require(entry.file_size <= MAX_RATIO * max(entry.compress_size, 1),
                        "Suspicious ZIP expansion ratio")
                total += entry.file_size
                require(total <= MAX_TOTAL, "ZIP expansion budget exceeded")
                if name not in required:
                    require(name.startswith("calamares-inspect/"), "Unexpected evidence member")
                    continue  # Historical inspection extras are inside pinned whole-ZIP SHA.
                raw = archive.read(entry)
                require(len(raw) == entry.file_size, "ZIP member length mismatch")
                short = name.removeprefix("evidence/")
                require(
                    digest(raw) == (reports[short] if short in reports else expected_png[short]),
                    "Pinned report/screenshot mismatch",
                )
                if short in expected_png:
                    _png(raw)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, RuntimeError, zlib.error) as exc:
        raise Refusal("Malformed historical ZIP") from exc


def validate_archives(manifest_path: Path, zip_dir: Path, metadata_dir: Path) -> dict:
    manifest = _pin_manifest(manifest_path)
    runs = manifest["runs"] + manifest["summaryRuns"]
    archives = manifest["archives"]
    require(len(runs) == len(archives) == 4, "Four pinned historical archives required")
    require(tuple(x["artifactId"] for x in runs) == ARTIFACTS, "Artifact identity/order changed")
    require(tuple(int(x["runId"]) for x in runs) == RUNS, "Run identity/order changed")
    require(tuple(x["artifactId"] for x in archives) == ARTIFACTS,
            "Archive manifest identity/order changed")
    frames = edges = 0
    for run, item in zip(runs, archives, strict=True):
        aid = run["artifactId"]
        require(item["artifactId"] == aid and SHA256.fullmatch(item["archiveSha256"]) is not None,
                "Invalid archive identity/hash")
        metadata = parse(read(metadata_dir / f"{aid}.json", 64 * 1024))
        workflow = metadata.get("workflow_run")
        require(
            metadata.get("id") == aid
            and metadata.get("name") == item["name"]
            and metadata.get("expired") is False
            and metadata.get("digest") == "sha256:" + item["archiveSha256"]
            and isinstance(workflow, dict)
            and workflow.get("id") == int(run["runId"])
            and workflow.get("head_sha") == item["workflowCommit"],
            "Supplied GitHub metadata mismatch",
        )
        # Pinned evidence.read() obtains bytes from an identity-checked open FD;
        # ZipFile never sees/reopens the original pathname after hashing.
        binary = read(zip_dir / f"{aid}.zip", MAX_ARCHIVE)
        require(digest(binary) == item["archiveSha256"], "Whole ZIP digest mismatch")
        _check_zip(binary, item, run, aid)
        frames += len(run["screenshots"])
        edges += len(run["transitions"])
    require((frames, edges) == (40, 36), "Pinned screenshot/transition counts changed")
    return {
        "decision": "HISTORICAL_ARTIFACT_MATCHED",
        "artifactIds": list(ARTIFACTS),
        "screenshots": frames,
        "transitions": edges,
        "externalProvenance": "EXTERNAL_PROVENANCE_UNPROVEN",
        "inputAuthorized": False,
        "diskWritesAuthorized": False,
        "trustBoundaryIndependent": False,
        "productionInstallationAuthorized": False,
        "releaseEligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--zip-dir", type=Path, required=True)
    parser.add_argument("--metadata-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(validate_archives(args.manifest, args.zip_dir, args.metadata_dir),
                         sort_keys=True))
        return 0
    except (Refusal, OSError, TypeError, KeyError, IndexError, OverflowError):
        # Never reflect attacker-supplied paths, ZIP filenames or raw exception strings.
        print(json.dumps({"decision": "REFUSE_Q4OS_ARCHIVE_PROVENANCE",
                          "externalProvenance": "EXTERNAL_PROVENANCE_UNPROVEN",
                          "inputAuthorized": False, "diskWritesAuthorized": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
