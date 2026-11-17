#!/usr/bin/env python3
"""Immutable GitHub Actions Windows 11 evidence ZIP: read-only candidate check.

The pinned ZIP is from a real successful disposable QEMU run, but even a
cryptographically consistent archive is NOT guest origin authentication or
authorization to repartition Windows, boot into CachyOS, or release Gaslux.
"""
from __future__ import annotations

import hashlib
import io
import json
import stat
import sys
import zipfile

from windows_cachyos_readonly_baseline_gate import (
    BaselineGateError, evaluate, unique_keys,
)

PROFILE = "win11_26h2_en_us_x64"
ARTIFACT_ID = 14335490721
ACTIONS_RUN = 44094951108
SOURCE_COMMIT = "35ef6de46b71524c6c05c8d9f3a9f87564529ce7"
ZIP_SHA256 = "55b40f86d4de9f40508b564f9029beb04788fd5d03832370ce3099d259953cc4"
PREFIX = PROFILE + "-"
EXPECTED = {
    PREFIX + "result.json": 65536,
    PREFIX + "serial.log": 16 * 1024 * 1024,
    PREFIX + "serial.sha256": 512,
    PREFIX + "initial-dvd-serial.log": 2_000_000,
    PREFIX + "initial-dvd-serial.sha256": 512,
}
MAX_ZIP = 3 * 1024 * 1024


def require(ok: bool, message: str) -> None:
    if not ok:
        raise BaselineGateError(message)


def inspect_archive(blob: bytes, pinned_sha: str = ZIP_SHA256) -> dict[str, object]:
    require(isinstance(blob, bytes) and 0 < len(blob) <= MAX_ZIP,
            "missing or oversized historical Windows evidence archive")
    require(hashlib.sha256(blob).hexdigest() == pinned_sha,
            "historical Windows evidence ZIP differs from Actions upload digest")
    with zipfile.ZipFile(io.BytesIO(blob), "r") as bundle:
        infos = bundle.infolist()
        require(len(infos) == len(EXPECTED), "unexpected Windows evidence file count")
        require(set(i.filename for i in infos) == set(EXPECTED),
                "Windows archive contains unknown, duplicate or missing paths")
        for info in infos:
            kind = (info.external_attr >> 16) & 0o170000
            require(not info.is_dir() and kind in (0, stat.S_IFREG)
                    and not info.flag_bits & 1
                    and 0 < info.file_size <= EXPECTED[info.filename],
                    "Windows archive contains unsafe evidence member")
        require(bundle.testzip() is None, "Windows archive CRC failure")
        members = {info.filename: bundle.read(info) for info in infos}
    report = json.loads(members[PREFIX + "result.json"],
                        object_pairs_hook=unique_keys)
    observed = evaluate(
        PROFILE,
        report,
        members[PREFIX + "serial.log"],
        members[PREFIX + "serial.sha256"],
        members[PREFIX + "initial-dvd-serial.log"],
        members[PREFIX + "initial-dvd-serial.sha256"],
    )
    require(observed["candidateWindowsFirstbootDocumentsConsistent"] is True,
            "historical installed Windows baseline documents inconsistent")
    for key in ("windowsGuestOriginAuthenticated", "windowsBootVerified",
                "windowsBcdWinreRestorationVerified", "sameDiskDualBootVerified",
                "storageWritesAuthorized", "releaseEligible"):
        require(observed[key] is False,
                "candidate document validation must not authorize writes: " + key)
    return observed


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: windows11_success_artifact_candidate_probe.py ZIP")
    from pathlib import Path
    source = Path(sys.argv[1])
    require(source.is_file() and not source.is_symlink(),
            "historical Windows archive must be a regular file")
    require(source.stat().st_size <= MAX_ZIP,
            "historical Windows archive exceeds bounded size")
    proof = inspect_archive(source.read_bytes())
    print(json.dumps({
        "historicalRun": ACTIONS_RUN,
        "historicalArtifactId": ARTIFACT_ID,
        "candidateWindowsFirstbootDocumentsConsistent":
            proof["candidateWindowsFirstbootDocumentsConsistent"],
        "windowsGuestOriginAuthenticated": False,
        "windowsBootVerified": False,
        "sameDiskDualBootVerified": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BaselineGateError, OSError, ValueError, KeyError,
            zipfile.BadZipFile, json.JSONDecodeError) as error:
        print(json.dumps({"candidateWindowsFirstbootDocumentsConsistent": False,
                          "storageWritesAuthorized": False,
                          "releaseEligible": False,
                          "error": str(error)}, sort_keys=True))
        raise SystemExit(2) from None
