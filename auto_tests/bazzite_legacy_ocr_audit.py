#!/usr/bin/env python3
"""Read-only audit of screenshot/OCR evidence from the prior Bazzite diskless VM."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from pathlib import Path

REQUIRED = {
    "distributionId": "bazzite",
    "labOnly": True,
    "noGuestHardDisk": True,
    "noGuestNetwork": True,
    "noInstallerInput": True,
    "fourNonblankGuestScreenshots": True,
    "isoCryptographicProvenanceVerified": False,
    "nativeLegacyInstallerVerified": False,
    "manualPartitioningInGuestVerified": False,
    "storageWriteSetVerified": False,
    "windowsEspPreservedInGuest": False,
    "installationAuthorized": False,
    "partitionWriteAuthorized": False,
    "windowsEspWriteAuthorized": False,
    "windowsDualBootVerified": False,
}
OBSERVED = (
    "bazziteTextObserved",
    "anacondaTextObserved",
    "blivetTextObserved",
    "installationUiCandidateObserved",
)
PNG = b"\x89PNG\r\n\x1a\n"


class EvidenceRefusal(ValueError):
    """Fail closed on contradictory or forged lab evidence."""


def _read(path: Path, limit: int, *, allow_empty: bool = False) -> bytes:
    if path.is_symlink():
        raise EvidenceRefusal("Symlink evidence file refused")
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > limit:
        raise EvidenceRefusal("Unsafe or oversized evidence file")
    if st.st_size == 0 and not allow_empty:
        raise EvidenceRefusal("Unsafe or oversized evidence file")
    return path.read_bytes()


def audit(directory: Path) -> dict:
    if directory.is_symlink() or not directory.is_dir():
        raise EvidenceRefusal("Expected a private evidence directory")
    source = json.loads(_read(directory / "guest-observation.json", 65536))
    if not isinstance(source, dict) or set(source) != set(REQUIRED) | set(OBSERVED):
        raise EvidenceRefusal("Unexpected observation fields")
    for key, value in REQUIRED.items():
        if type(source.get(key)) is not type(value) or source.get(key) != value:
            raise EvidenceRefusal("Observation contradicts diskless no-install contract")
    texts = []
    hashes = {}
    for phase in range(1, 5):
        raw = _read(directory / f"ocr-{phase}.txt", 32768, allow_empty=True)
        try:
            texts.append(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise EvidenceRefusal("Invalid OCR encoding") from exc
        screenshot = _read(directory / f"screen-{phase}.png", 5 * 1024 * 1024)
        if not screenshot.startswith(PNG):
            raise EvidenceRefusal("Invalid PNG evidence")
        hashes[f"screen-{phase}"] = hashlib.sha256(screenshot).hexdigest()
    combined = "\n".join(texts).lower()
    parsed = {
        "bazziteTextObserved": "bazzite" in combined,
        "anacondaTextObserved": "anaconda" in combined,
        "blivetTextObserved": "blivet" in combined,
        "installationUiCandidateObserved": "install" in combined,
    }
    if any(source[key] is not value for key, value in parsed.items()):
        raise EvidenceRefusal("OCR contradicts previously published visual evidence")
    install_versions = re.findall(r"\bbazzite\s+([0-9]{2,3})\s+installation\b", combined)
    welcome_versions = re.findall(r"\bwelcome to bazzite\s+([0-9]{2,3})\b", combined)
    if bool(install_versions) != bool(welcome_versions):
        raise EvidenceRefusal("Incomplete legacy installer version banner")
    if install_versions and len(set(install_versions + welcome_versions)) != 1:
        raise EvidenceRefusal("Conflicting legacy installer version banners")
    displayed_version = install_versions[0] if install_versions else None
    repeated_welcome = (
        sum(
            f"bazzite {displayed_version} installation" in text.lower()
            and f"welcome to bazzite {displayed_version}" in text.lower()
            for text in texts
        )
        >= 2
        if displayed_version
        else False
    )
    return {
        "distributionId": "bazzite",
        "evidenceType": "diskless-ovmf-ocr-second-review",
        "screenCount": 4,
        "legacyInstallerWelcomeVersionAdvertised": displayed_version,
        "repeatedLegacyInstallerWelcomeObserved": repeated_welcome,
        "advertisedVersionBoundToInstalledPayload": False,
        "screenSha256": hashes,
        "boundedOcrExcerpts": [text[:1200] for text in texts],
        **parsed,
        "anacondaSpecificTextCandidate": bool(
            re.search(r"anaconda|installation summary|installation destination", combined)
        ),
        "blivetSpecificTextCandidate": "blivet" in combined or "advanced custom" in combined,
        "actualInstallerBinaryVerified": False,
        "guestLinuxKernelBootVerified": False,
        "manualPartitioningInGuestVerified": False,
        "isoCryptographicProvenanceVerified": False,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "windowsEspPreservedInGuest": False,
        "windowsDualBootVerified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = audit(args.artifact_dir)
    except (EvidenceRefusal, OSError, ValueError, KeyError) as exc:
        parser.exit(2, f"REFUSED: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
