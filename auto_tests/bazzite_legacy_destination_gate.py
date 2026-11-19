#!/usr/bin/env python3
"""Locate the native Bazzite 42 Installation Destination entry in a diskless VM.

This is a read-only visual identity gate. A coordinate is not an installer
permission, disk identity, partitioning authorization or boot verification.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from bazzite_legacy_language_gate import _get_words

WIDTH = 1280
HEIGHT = 800


class DestinationRefusal(ValueError):
    """Fail closed on ambiguous, missing or inconsistent visual evidence."""


def locate_destination(ocr: str, tsv: str, width: int, height: int) -> dict:
    if type(width) is not int or type(height) is not int or (width, height) != (WIDTH, HEIGHT):
        raise DestinationRefusal("Unexpected installer framebuffer size")
    if len(ocr.encode("utf-8")) > 32768 or len(tsv.encode("utf-8")) > 1024 * 1024:
        raise DestinationRefusal("Unbounded OCR input")
    normalized = re.sub(r"\s+", " ", ocr).lower()
    for required in (
        "installation summary",
        "bazzite 42 installation",
        "installation destination",
        "no disks selected",
        "no network devices available",
        "begin installation",
    ):
        if required not in normalized:
            raise DestinationRefusal(f"Missing diskless installation evidence: {required}")
    words = _get_words(tsv)
    matches = []
    for first in words:
        if first["text"].lower() != "installation" or first["confidence"] < 85:
            continue
        x1 = first["left"]
        y1 = first["top"] + first["height"] // 2
        if not (660 <= x1 <= 700 and 310 <= y1 <= 350):
            continue
        second = [
            word
            for word in words
            if word["text"].lower() == "destination"
            and word["confidence"] >= 85
            and 0 <= word["left"] - (first["left"] + first["width"]) <= 15
            and abs(word["top"] + word["height"] // 2 - y1) <= 6
        ]
        if len(second) == 1:
            last = second[0]
            matches.append(
                {
                    "x": (x1 + last["left"] + last["width"]) // 2,
                    "y": y1,
                }
            )
    if len(matches) != 1:
        raise DestinationRefusal("No unique native Installation Destination target")
    center = matches[0]
    if not (705 <= center["x"] <= 780 and 310 <= center["y"] <= 350):
        raise DestinationRefusal("Target outside verified Installation Destination tile")
    return {
        "distributionId": "bazzite",
        "advertisedVersion": "42",
        "screen": "installation-summary-diskless",
        "noDisksSelectedTextVerified": True,
        "noNetworkDevicesTextVerified": True,
        "destinationTargetUniquelyObserved": True,
        "coordinate": center,
        "labOnly": True,
        "guestHardDiskAttached": False,
        "installerBinaryIdentityVerified": False,
        "blivetGuiVerified": False,
        "isoProvenanceSignatureVerified": False,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--png", required=True, type=Path)
    parser.add_argument("--ocr", required=True, type=Path)
    parser.add_argument("--tsv", required=True, type=Path)
    parser.add_argument("--coords", required=True, type=Path)
    args = parser.parse_args()
    try:
        from PIL import Image

        if any(x.is_symlink() for x in (args.png, args.ocr, args.tsv, args.coords)):
            raise DestinationRefusal("Symlink evidence path refused")
        if not (0 < args.png.stat().st_size <= 5 * 1024 * 1024):
            raise DestinationRefusal("Invalid screenshot size")
        with Image.open(args.png) as im:
            im.verify()
        with Image.open(args.png) as im:
            size = im.size
        result = locate_destination(
            args.ocr.read_text(encoding="utf-8"),
            args.tsv.read_text(encoding="utf-8"),
            size[0],
            size[1],
        )
        point = result["coordinate"]
        args.coords.write_text(f"{point['x']} {point['y']}\n", encoding="ascii")
    except (OSError, ValueError, UnicodeError) as exc:
        parser.exit(2, f"REFUSED: {exc}\n")
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
