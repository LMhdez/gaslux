#!/usr/bin/env python3
"""Locate the Bazzite legacy Installation Destination tile on a GPT lab guest.

This gate authorizes only one GUI navigation click. It does not identify a
physical disk, select a partition, or authorize installation or writes.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from bazzite_legacy_language_gate import _get_words

WIDTH = 1280
HEIGHT = 800


class StorageNavigationRefusal(ValueError):
    """Fail closed when the summary page or target tile is ambiguous."""


def locate_storage_tile(ocr: str, tsv: str, width: int, height: int) -> dict:
    if type(width) is not int or type(height) is not int or (width, height) != (WIDTH, HEIGHT):
        raise StorageNavigationRefusal("Unexpected installer framebuffer size")
    if len(ocr.encode("utf-8")) > 32768 or len(tsv.encode("utf-8")) > 1024 * 1024:
        raise StorageNavigationRefusal("Unbounded OCR input")
    normalized = re.sub(r"\\s+", " ", ocr).lower()
    for required in ("installation summary", "bazzite 42 installation", "installation destination",
                     "automatic partitioning selected", "no network devices available"):
        if required not in normalized:
            raise StorageNavigationRefusal(f"Missing GPT guest summary evidence: {required}")
    words = _get_words(tsv)
    matches = []
    for first in words:
        if first["text"].lower() != "installation" or first["confidence"] < 85:
            continue
        cy = first["top"] + first["height"] // 2
        if not (660 <= first["left"] <= 700 and 310 <= cy <= 350):
            continue
        second = [w for w in words if w["text"].lower() == "destination"
                  and w["confidence"] >= 85
                  and 0 <= w["left"] - (first["left"] + first["width"]) <= 15
                  and abs(w["top"] + w["height"] // 2 - cy) <= 6]
        if len(second) == 1:
            last = second[0]
            matches.append({"x": (first["left"] + last["left"] + last["width"]) // 2, "y": cy})
    if len(matches) != 1:
        raise StorageNavigationRefusal("No unique Installation Destination tile")
    point = matches[0]
    if not (705 <= point["x"] <= 780 and 310 <= point["y"] <= 350):
        raise StorageNavigationRefusal("Destination tile outside verified geometry")
    return {
        "distributionId": "bazzite",
        "advertisedVersion": "42",
        "screen": "installation-summary-gpt-lab",
        "automaticPartitioningWarningObserved": True,
        "noNetworkDevicesTextVerified": True,
        "destinationTargetUniquelyObserved": True,
        "coordinate": point,
        "labOnly": True,
        "syntheticGptGuestOnly": True,
        "diskIdentityIndependentlyVerified": False,
        "installerBinaryIdentityVerified": False,
        "isoProvenanceSignatureVerified": False,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("png", "ocr", "tsv", "coords"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    args = parser.parse_args()
    try:
        from PIL import Image
        paths = (args.png, args.ocr, args.tsv, args.coords)
        if any(p.is_symlink() for p in paths):
            raise StorageNavigationRefusal("Symlink evidence path refused")
        if not (0 < args.png.stat().st_size <= 5 * 1024 * 1024):
            raise StorageNavigationRefusal("Invalid screenshot size")
        with Image.open(args.png) as im:
            im.verify()
        with Image.open(args.png) as im:
            width, height = im.size
        result = locate_storage_tile(args.ocr.read_text(encoding="utf-8"),
                                     args.tsv.read_text(encoding="utf-8"), width, height)
        args.coords.write_text(f"{result['coordinate']['x']} {result['coordinate']['y']}\\n",
                               encoding="ascii")
    except (OSError, ValueError, UnicodeError) as exc:
        parser.exit(2, f"REFUSED: {exc}\\n")
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
