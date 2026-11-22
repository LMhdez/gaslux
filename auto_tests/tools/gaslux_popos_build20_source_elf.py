#!/usr/bin/env python3
"""Build-20 distinst package metadata audit. No installer execution or writes.

The ISO->ELF digest check authenticates bytes within a trusted offline
extraction, NOT the source commit that compiled them. Package version and
7-char Git suffix are candidates, never source-to-ELF cryptographic proof.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

from gaslux_popos_distinst_prewrite_gap import ELF_SHA256
from windows10_popos_official_iso_signed_lab import (
    PINNED_ISO_BYTES,
    PINNED_ISO_SHA256,
)

SOURCE_COMMIT_2026 = "282dfc441ee608e963930d0ce01f04b672ca4f71"
SOURCE_COMMITTED_UTC = "2026-09-16T20:49:49Z"
BUILD20_EARLIEST_PUBLIC_REFERENCE_UTC = "2025-10-10T03:39:24Z"
BUILD20_REFERENCE = "https://github.com/pop-os/pop/issues/3612"
MAX_STATUS_BYTES = 16 * 1024 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024
GIT_SUFFIX = re.compile(r"~([0-9a-f]{7,12})(?:$|[~+.-])")
VERSION = re.compile(r"[0-9A-Za-z.+:~_-]{1,160}\Z")


class Build20ProvenanceRefusal(ValueError):
    """Invalid evidence: fail closed without executing any target ELF."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise Build20ProvenanceRefusal(message)


def parse_dpkg_status(status: bytes) -> dict:
    """Extract only installed distinst's exact stanza from ISO-owned dpkg/status.

    This is NOT a signed repository package index, .buildinfo or source proof.
    """
    need(
        type(status) is bytes and 0 < len(status) <= MAX_STATUS_BYTES,
        "REFUSE_BUILD20: unbounded/invalid dpkg status",
    )
    try:
        data = status.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Build20ProvenanceRefusal("REFUSE_BUILD20: invalid dpkg status UTF-8") from exc
    matches = []
    for paragraph in re.split(r"\n\s*\n", data.replace("\r\n", "\n")):
        props: dict[str, str] = {}
        last: str | None = None
        for line in paragraph.splitlines():
            if not line:
                continue
            if line.startswith((" ", "\t")):
                need(last is not None, "REFUSE_BUILD20: orphan status continuation")
                props[last] += "\n" + line.strip()
                continue
            need(": " in line, "REFUSE_BUILD20: malformed package status line")
            name, value = line.split(": ", 1)
            need(name not in props and bool(name), "REFUSE_BUILD20: duplicate field")
            props[name] = value
            last = name
        if props.get("Package") == "distinst":
            matches.append(props)
    need(len(matches) == 1, "REFUSE_BUILD20: missing/ambiguous distinst package")
    row = matches[0]
    need(
        row.get("Status") == "install ok installed",
        "REFUSE_BUILD20: distinst not installed in live squashfs",
    )
    version = row.get("Version", "")
    need(VERSION.fullmatch(version) is not None, "REFUSE_BUILD20: invalid distinst binary version")
    need(
        row.get("Architecture") == "amd64",
        "REFUSE_BUILD20: unexpected distinst package architecture",
    )
    source = row.get("Source")
    need(
        source is None or re.fullmatch(r"[0-9A-Za-z.+:~_() -]{1,160}", source) is not None,
        "REFUSE_BUILD20: invalid source metadata",
    )
    dependencies = row.get("Depends", "")
    need(len(dependencies) <= 8192, "REFUSE_BUILD20: unbounded dependency metadata")
    suffixes = GIT_SUFFIX.findall(version)
    return {
        "package": "distinst",
        "version": version,
        "architecture": row["Architecture"],
        "sourceField": source,  # informational; absent for many .deb binaries
        "maintainer": row.get("Maintainer"),
        "depends": dependencies,
        "versionGitSuffixCandidates": suffixes,
        "aptOriginAuthenticated": False,
        "signedBuildinfoVerified": False,
        "sourceBuildEnvironmentReproduced": False,
    }


def _regular_owned(path: Path, limit: int, expected: int | None = None) -> int:
    need(
        isinstance(path, Path) and path.is_absolute() and not path.is_symlink(),
        "REFUSE_BUILD20: non-absolute/symlink input",
    )
    try:
        info = path.lstat()
    except OSError as exc:
        raise Build20ProvenanceRefusal("REFUSE_BUILD20: input unavailable") from exc
    need(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and 0 < info.st_size <= limit,
        "REFUSE_BUILD20: foreign, non-regular or unbounded input",
    )
    if expected is not None:
        need(info.st_size == expected, "REFUSE_BUILD20: unexpected file length")
    return info.st_size


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fd:
        for block in iter(lambda: fd.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect_build20_extraction(
    iso: Path,
    elf: Path,
    status: Path,
    workspace: Path,
) -> dict:
    """Only after hosted runner downloaded *and GPG-verified* the exact ISO.

    The script trusts the narrow workflow extraction origin; it does not
    authenticate same-UID adversaries or prove the source of any ELF.
    """
    runner = os.environ.get("RUNNER_TEMP", "")
    need(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and bool(runner)
        and isinstance(workspace, Path)
        and workspace.is_absolute()
        and workspace.parent == Path(runner)
        and workspace.name.startswith("gaslux-pop-build20-metadata-")
        and not workspace.is_symlink()
        and workspace.is_dir(),
        "REFUSE_BUILD20: not a hosted private source-metadata lab",
    )
    w = workspace.resolve(strict=True)
    need(
        workspace.stat().st_uid == os.geteuid() and stat.S_IMODE(workspace.stat().st_mode) == 0o700,
        "REFUSE_BUILD20: workspace must be private",
    )
    for path in (iso, elf, status):
        need(
            path.parent == workspace and path.parent.resolve(strict=True) == w,
            "REFUSE_BUILD20: input is not owned by workspace",
        )
    _regular_owned(iso, PINNED_ISO_BYTES, PINNED_ISO_BYTES)
    _regular_owned(elf, MAX_BINARY_BYTES)
    _regular_owned(status, MAX_STATUS_BYTES)
    need(
        sha256_file(iso) == PINNED_ISO_SHA256,
        "REFUSE_BUILD20: signed-ISO expected SHA-256 mismatch",
    )
    need(
        sha256_file(elf) == ELF_SHA256,
        "REFUSE_BUILD20: extracted ELF differs from build20 live pin",
    )
    raw_status = status.read_bytes()
    package = parse_dpkg_status(raw_status)
    return {
        "schemaVersion": 1,
        "scenario": "pop-distinst-build20-source-elf-readonly",
        "result": "SOURCE_TO_ELF_UNPROVEN",
        "isoFullSha256Matched": True,
        "elfFullSha256Matched": True,
        "isoSha256": PINNED_ISO_SHA256,
        "elfSha256": ELF_SHA256,
        "dpkgStatusSha256": hashlib.sha256(raw_status).hexdigest(),
        "packageMetadata": package,
        "upstreamCommitInspected": SOURCE_COMMIT_2026,
        "upstreamCommitDateUtc": SOURCE_COMMITTED_UTC,
        "build20PublicReferenceUtc": BUILD20_EARLIEST_PUBLIC_REFERENCE_UTC,
        "build20Reference": BUILD20_REFERENCE,
        "upstreamCommitPostdatesOriginalBuild20Reference": True,
        "isoGpgVerificationPerformedByWorkflow": False,
        "isoHashMatchesPreviouslySignedManifestPin": True,
        "cargoLockOfActualBuildVerified": False,
        "elfBuildIdSourceBindingVerified": False,
        "sourceToElfCorrespondenceVerified": False,
        "signedBuildinfoVerified": False,
        "aptRepositorySnapshotVerified": False,
        "firstPersistentWriteProvenForPinnedElf": False,
        "firstStateChangeProvenForPinnedElf": False,
        "distinstExecuted": False,
        "distinstExecutionAuthorized": False,
        "productionInstallationAuthorized": False,
        "sameDiskDualBootVerified": False,
        "stable": False,
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Offline Pop build20 source audit")
    parser.add_argument("--workspace", required=True)
    args = parser.parse_args()
    work = Path(args.workspace)
    result = inspect_build20_extraction(
        work / "build20.iso",
        work / "distinst.elf",
        work / "dpkg.status",
        work,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
