#!/usr/bin/env python3
"""Identify Bazzite 42 legacy storage UI without authorizing any installation.

A synthetic GPT disk may be attached to QEMU with readonly=on; this validator
only identifies the Installation Destination tile and reports observed text.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from bazzite_legacy_language_gate import _get_words


class StorageRefusal(ValueError):
    """Fail closed if the observed screen is not the expected legacy installer."""


def _ocr_identity(text: str) -> str:
    if not isinstance(text, str) or len(text.encode("utf-8")) > 32768:
        raise StorageRefusal("Unbounded screenshot OCR")
    return re.sub(r"\s+", " ", text).lower()


def locate_destination(ocr: str, tsv: str, width: int, height: int) -> dict:
    if type(width) is not int or type(height) is not int or (width, height) != (1280, 800):
        raise StorageRefusal("Unexpected guest framebuffer")
    if not isinstance(tsv, str) or len(tsv.encode("utf-8")) > 1024 * 1024:
        raise StorageRefusal("Unbounded word geometry")
    s = _ocr_identity(ocr)
    for marker in (
        "installation summary",
        "bazzite 42 installation",
        "installation destination",
        "begin installation",
    ):
        if marker not in s:
            raise StorageRefusal(f"Unknown installer summary: {marker}")
    words = _get_words(tsv)
    matches = []
    for first in words:
        if first["text"].lower() != "installation" or first["confidence"] < 85:
            continue
        left = first["left"]
        y = first["top"] + first["height"] // 2
        if not (660 <= left <= 700 and 310 <= y <= 350):
            continue
        neighbours = [
            other
            for other in words
            if other["text"].lower() == "destination"
            and other["confidence"] >= 80
            and 0 <= other["left"] - (left + first["width"]) <= 15
            and abs(other["top"] + other["height"] // 2 - y) <= 6
        ]
        if len(neighbours) == 1:
            last = neighbours[0]
            matches.append({"x": (left + last["left"] + last["width"]) // 2, "y": y})
    if len(matches) != 1 or not (705 <= matches[0]["x"] <= 780):
        raise StorageRefusal("Ambiguous or missing Installation Destination tile")
    return {
        "distributionId": "bazzite",
        "observedLegacyInstallerBanner": "42",
        "page": "installation-summary",
        "coordinate": matches[0],
        "targetUniquelyObserved": True,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "secureBootEnrollmentAuthorized": False,
    }


def observe_destination(ocr: str) -> dict:
    s = _ocr_identity(ocr)
    if "installation destination" not in s or "bazzite 42 installation" not in s:
        raise StorageRefusal("Not Bazzite 42 native storage destination page")
    if "device selection" not in s or "storage configuration" not in s:
        raise StorageRefusal("Missing native storage page anchors")
    # These are separate UI observations. Do not infer any disk can be used
    # or that the Blivet GUI executable was entered.
    return {
        "distributionId": "bazzite",
        "observedLegacyInstallerBanner": "42",
        "nativeStoragePageObserved": True,
        "automaticOptionTextObserved": "automatic" in s,
        "customOptionTextObserved": "custom" in s,
        "advancedCustomBlivetOptionTextObserved": (
            "advanced custom" in s and "blivet-gui" in s
        ),
        "zeroDisksTextObserved": bool(
            re.search(r"\b[0o]\s+disks?\s+selected\b", s)
            or "no disks detected" in s
        ),
        "diskModelText": s[:1400],
        "blivetGuiExecutableVerified": False,
        "guestDiskReadOnlyFlagVerified": False,
        "diskPartitioningAttempted": False,
        "beginInstallationActivated": False,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "secureBootEnrollmentAuthorized": False,
        "windowsDualBootVerified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=["summary", "destination"], required=True)
    parser.add_argument("--ocr", required=True, type=Path)
    parser.add_argument("--tsv", type=Path)
    parser.add_argument("--png", type=Path)
    parser.add_argument("--coords", type=Path)
    args = parser.parse_args()
    try:
        paths = [x for x in (args.ocr, args.tsv, args.png, args.coords) if x]
        if any(p.is_symlink() for p in paths):
            raise StorageRefusal("Symlink evidence refused")
        ocr = args.ocr.read_text(encoding="utf-8")
        if args.phase == "summary":
            if not (args.tsv and args.png and args.coords):
                raise StorageRefusal("Summary requires screenshot/TSV/coordinates")
            from PIL import Image

            if not (0 < args.png.stat().st_size <= 5 * 1024 * 1024):
                raise StorageRefusal("Unbounded PNG")
            with Image.open(args.png) as im:
                im.verify()
            with Image.open(args.png) as im:
                width, height = im.size
            result = locate_destination(
                ocr, args.tsv.read_text(encoding="utf-8"), width, height
            )
            xy = result["coordinate"]
            args.coords.write_text(f"{xy['x']} {xy['y']}\n", encoding="ascii")
        else:
            result = observe_destination(ocr)
    except (OSError, ValueError, UnicodeError) as exc:
        parser.exit(2, f"REFUSED: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
