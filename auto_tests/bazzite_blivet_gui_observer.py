#!/usr/bin/env python3
"""Fail-closed OCR observer for opening, but not operating, Bazzite Blivet-GUI.

OCR text and TSV are re-extracted from the supplied screenshot and must match
the sidecars byte-for-byte before any UI decision is made.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import subprocess
from pathlib import Path

from PIL import Image

WIDTH, HEIGHT = 1280, 800


class BlivetObserverRefusal(ValueError):
    """Refuse unexpected, ambiguous, or unbounded installer evidence."""


def _read(png: Path, ocr_path: Path, tsv_path: Path, require_storage_page: bool = True):
    paths = (png, ocr_path, tsv_path)
    if any(path.is_symlink() for path in paths):
        raise BlivetObserverRefusal("Symlink evidence refused")
    if not (0 < png.stat().st_size <= 5 * 1024 * 1024):
        raise BlivetObserverRefusal("Invalid screenshot size")
    ocr = ocr_path.read_text(encoding="utf-8")
    tsv = tsv_path.read_text(encoding="utf-8")
    if len(ocr.encode()) > 32768 or len(tsv.encode()) > 1024 * 1024:
        raise BlivetObserverRefusal("Unbounded OCR evidence")
    with Image.open(png) as image:
        image.verify()
    with Image.open(png) as image:
        if image.size != (WIDTH, HEIGHT):
            raise BlivetObserverRefusal("Unexpected framebuffer geometry")
    try:
        extracted_text = subprocess.run(
            ["tesseract", str(png), "stdout"],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        ).stdout
        extracted_tsv = subprocess.run(
            ["tesseract", str(png), "stdout", "tsv"],
            check=True, capture_output=True, text=True, timeout=20,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise BlivetObserverRefusal("Screenshot OCR extraction failed") from exc
    if extracted_text != ocr or extracted_tsv != tsv:
        raise BlivetObserverRefusal("OCR/TSV sidecars do not match screenshot extraction")
    normalized = re.sub(r"\s+", " ", extracted_text).lower()
    if require_storage_page:
        for marker in (
            "bazzite 42 installation",
            "installation destination",
            "advanced custom",
            "blivet-gui",
        ):
            if marker not in normalized:
                raise BlivetObserverRefusal(f"Missing storage-page marker: {marker}")
    rows = list(csv.DictReader(io.StringIO(extracted_tsv), delimiter="\t"))
    words = []
    for row in rows:
        try:
            item = {
                "text": row["text"].strip().lower().strip("()"),
                "left": int(row["left"]),
                "top": int(row["top"]),
                "width": int(row["width"]),
                "height": int(row["height"]),
                "confidence": float(row["conf"]),
            }
        except (KeyError, TypeError, ValueError):
            continue
        if item["text"]:
            words.append(item)
    return normalized, words


def locate_launch_control(png: Path, ocr_path: Path, tsv_path: Path) -> dict:
    _, words = _read(png, ocr_path, tsv_path)
    candidates = []
    for first in words:
        if first["text"] != "advanced" or first["confidence"] < 60:
            continue
        line = [
            item
            for item in words
            if abs(item["top"] - first["top"]) <= 8
            and abs(
                (item["top"] + item["height"] // 2)
                - (first["top"] + first["height"] // 2)
            ) <= 8
        ]
        line.sort(key=lambda item: item["left"])
        for index, item in enumerate(line):
            if item is not first:
                continue
            phrase = line[index:index + 3]
            labels = [x["text"] for x in phrase]
            if len(phrase) != 3 or labels != ["advanced", "custom", "blivet-gui"]:
                continue
            if any(x["confidence"] < 60 for x in phrase):
                continue
            if phrase[1]["left"] - (phrase[0]["left"] + phrase[0]["width"]) > 35:
                continue
            if phrase[2]["left"] - (phrase[1]["left"] + phrase[1]["width"]) > 45:
                continue
            left = phrase[0]["left"]
            right = phrase[2]["left"] + phrase[2]["width"]
            top = min(x["top"] for x in phrase)
            bottom = max(x["top"] + x["height"] for x in phrase)
            point = {"x": (left + right) // 2, "y": (top + bottom) // 2}
            if 0 <= point["x"] < WIDTH and 0 <= point["y"] < HEIGHT:
                candidates.append(point)
    if len(candidates) != 1:
        raise BlivetObserverRefusal("Advanced Custom (Blivet-GUI) control is not unique")
    return {
        "phase": "launch-control",
        "coordinate": candidates[0],
        "exactControlUniquelyObserved": True,
        "onlyBlivetGuiLaunchClickPermitted": True,
        "partitionControlClicked": False,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
    }


def verify_editor(png: Path, ocr_path: Path, tsv_path: Path) -> dict:
    text, words = _read(png, ocr_path, tsv_path, require_storage_page=False)
    tokens = set(re.findall(r"[a-z0-9][a-z0-9._-]*", text))
    if "blivet-gui" not in tokens or "partition" not in tokens:
        raise BlivetObserverRefusal("Blivet-GUI partition editor identity not observed")
    if "glxbazro001" not in tokens:
        raise BlivetObserverRefusal("Expected disposable guest disk serial not observed")
    return {
        "phase": "editor-observed",
        "blivetGuiIdentityTextObserved": True,
        "partitionEditorContextObserved": True,
        "guestDiskSerialObserved": "GLXBAZRO001",
        "ocrWordCount": len(words),
        "partitionControlClicked": False,
        "partitionMutationAttempted": False,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "windowsDualBootVerified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("before", "after"), required=True)
    parser.add_argument("--png", required=True, type=Path)
    parser.add_argument("--ocr", required=True, type=Path)
    parser.add_argument("--tsv", required=True, type=Path)
    parser.add_argument("--coords", type=Path)
    args = parser.parse_args()
    try:
        result = (
            locate_launch_control(args.png, args.ocr, args.tsv)
            if args.phase == "before"
            else verify_editor(args.png, args.ocr, args.tsv)
        )
        if args.phase == "before":
            if args.coords is None or args.coords.is_symlink():
                raise BlivetObserverRefusal("Safe coordinate output path required")
            point = result["coordinate"]
            args.coords.write_text(f"{point['x']} {point['y']}\n", encoding="ascii")
    except (OSError, ValueError, UnicodeError) as exc:
        parser.exit(2, f"REFUSED: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
