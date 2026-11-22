#!/usr/bin/env python3
"""Pinned upstream Bazzite/bootc documentation identity readback; DENY ONLY.

Source Git blob hashes prove only identity against an upstream Git snapshot.
They do not attest a live guest, Anaconda/bootc binary or disk safety.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
from pathlib import Path

BAZZITE_DOCS_SHA = "1a9b77a0633443424e9c939cf4bd50718d1c79a5"
BOOTC_DOCS_SHA = "0fe7b14f29f1a8e6868462a170b165611992e901"
NO_WRITE = (
    "installationAuthorized", "partitionWriteAuthorized",
    "gptMetadataWriteAuthorized", "windowsEspWriteAuthorized",
    "nvramWriteAuthorized", "secureBootEnrollmentAuthorized",
    "guestCommandChannelAuthorized",
)
# GitHub API confirmed each blob SHA at its immutable commit.
SOURCE_PINS = {
    "modern": (
        "ublue-os/docs.bazzite.gg", BAZZITE_DOCS_SHA,
        "src/General/Installation_Guide/install-guide.md",
        "a9a2982a962ba6ea103779e6d375f5b4423ec7e1",
        "automatic partitioning as it is the only option available in the live ISO",
    ),
    "legacy": (
        "ublue-os/docs.bazzite.gg", BAZZITE_DOCS_SHA,
        "src/General/Installation_Guide/legacy-install.md",
        "81b71fa91c42d88a919e5aad46dbd2e4bd36f610",
        "new installer not supporting manual partitioning",
    ),
    "to-disk": (
        "bootc-dev/bootc", BOOTC_DOCS_SHA,
        "docs/src/man/bootc-install-to-disk.8.md",
        "0d59dc4244b5e086f68ee7f39b082411c4114063",
        "The entire device will be wiped",
    ),
    "to-filesystem": (
        "bootc-dev/bootc", BOOTC_DOCS_SHA,
        "docs/src/man/bootc-install-to-filesystem.8.md",
        "e476808a17a7ff79d54cf2ecbfea7e56ca9786ce",
        "prepared and mounted by an external tool or script",
    ),
    "to-existing-root": (
        "bootc-dev/bootc", BOOTC_DOCS_SHA,
        "docs/src/man/bootc-install-to-existing-root.8.md",
        "ff7059422187a1d985f05a4d82ab589beb11517a",
        "partition will be wiped",
    ),
}


class Refusal(ValueError):
    """Source identity or safety classification invalid."""


def git_blob(data: bytes) -> str:
    prefix = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(prefix + data, usedforsecurity=False).hexdigest()


def read_sources(root: Path) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise Refusal("Missing or redirected upstream source directory")
    names = {f"{name}.md" for name in SOURCE_PINS}
    if {p.name for p in root.iterdir()} != names:
        raise Refusal("Unexpected or absent upstream source")
    entries = {}
    for name, (repo, commit, path, blob, phrase) in SOURCE_PINS.items():
        file = root / f"{name}.md"
        if file.is_symlink():
            raise Refusal("Symlink source")
        info = file.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 262144:
            raise Refusal("Unbounded or foreign file")
        data = file.read_bytes()
        if len(data) != info.st_size or git_blob(data) != blob:
            raise Refusal("Changed official Git blob")
        if phrase.casefold() not in data.decode("utf-8").casefold():
            raise Refusal("Official source missing required behavior")
        entries[name] = {
            "repo": repo, "commit": commit, "path": path,
            "gitBlob": blob, "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data), "runtimeAttested": False,
        }
    return entries


def classify(evidence: dict) -> dict:
    if not isinstance(evidence, dict) or set(evidence) != set(SOURCE_PINS):
        raise Refusal("Missing official sources")
    for name, (repo, commit, path, blob, _) in SOURCE_PINS.items():
        item = evidence[name]
        if not isinstance(item, dict) or any((
            item.get("repo") != repo,
            item.get("commit") != commit,
            item.get("path") != path,
            item.get("gitBlob") != blob,
            item.get("runtimeAttested") is not False,
        )):
            raise Refusal("Substituted source or forged runtime approval")
    cases = (
        ("ISO45_CUSTOM_GPT_4_6", "modern", "INCOMPATIBLE_ROUTE"),
        ("ISO45_AUTOMATIC_WINDOWS", "modern", "BLOCKED_BY_SAFETY_CONTRACT"),
        ("LEGACY_BLIVET", "legacy", "BLOCKED_BY_SAFETY_CONTRACT"),
        ("BOOTC_TO_DISK", "to-disk", "INCOMPATIBLE_ROUTE"),
        ("BOOTC_TO_EXISTING_ROOT", "to-existing-root", "INCOMPATIBLE_ROUTE"),
        ("BOOTC_TO_FILESYSTEM", "to-filesystem", "BLOCKED_BY_SAFETY_CONTRACT"),
    )
    rows = [{
        "route": route, "source": source, "status": status,
        "nativeWriteSetObserved": False, "windowsPreservationProven": False,
        "bazziteRuntimeCompatibilityProven": False,
        **{key: False for key in NO_WRITE},
    } for route, source, status in cases]
    return {
        "schemaVersion": 1,
        "sources": evidence,
        "routes": rows,
        "guestAuthenticated": False,
        "anacondaDbusObserved": False,
        "bootcRuntimeProven": False,
        **{key: False for key in NO_WRITE},
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sources-dir", type=Path, required=True)
    args = p.parse_args()
    try:
        decision = classify(read_sources(args.sources_dir))
    except (Refusal, OSError, ValueError, UnicodeError) as exc:
        p.exit(3, f"REFUSED_SOURCE: {exc}\n")
    print(json.dumps(decision, sort_keys=True, indent=2))
    raise SystemExit(2)  # Success is a permanent denial, never authorization.


if __name__ == "__main__":
    main()
