#!/usr/bin/env python3
"""Fail-closed visual gate for selecting Custom in the disposable Bazzite GUI.

Only the Custom radio control may be clicked. The gate never authorizes Done,
Begin Installation, partition edits, disk writes, or Windows media access.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
from pathlib import Path

from PIL import Image

WIDTH = 1280
HEIGHT = 800
BLUE = lambda r, g, b: 40 <= r <= 120 and 120 <= g <= 180 and 200 <= b <= 255


class CustomSelectionRefusal(ValueError):
    """Refuse ambiguous or unexpected installer UI state."""


def _load(png: Path, ocr_path: Path, tsv_path: Path):
    paths = (png, ocr_path, tsv_path)
    if any(p.is_symlink() for p in paths):
        raise CustomSelectionRefusal("Symlink evidence path refused")
    if not (0 < png.stat().st_size <= 5 * 1024 * 1024):
        raise CustomSelectionRefusal("Invalid screenshot size")
    ocr = ocr_path.read_text(encoding="utf-8")
    tsv = tsv_path.read_text(encoding="utf-8")
    if len(ocr.encode("utf-8")) > 32768 or len(tsv.encode("utf-8")) > 1024 * 1024:
        raise CustomSelectionRefusal("Unbounded OCR evidence")
    image = Image.open(png).convert("RGB")
    if image.size != (WIDTH, HEIGHT):
        raise CustomSelectionRefusal("Unexpected installer framebuffer size")
    normalized = re.sub(r"\\s+", " ", ocr).lower()
    for marker in (
        "bazzite 42 installation",
        "installation destination",
        "storage configuration",
        "automatic",
        "custom",
        "advanced custom",
        "blivet-gui",
        "70 gib",
        "vda",
    ):
        if marker not in normalized:
            raise CustomSelectionRefusal(f"Missing storage UI marker: {marker}")
    rows = list(csv.DictReader(io.StringIO(tsv), delimiter="\\t"))
    words = []
    for row in rows:
        try:
            words.append({
                "text": row["text"].strip().lower(),
                "left": int(row["left"]),
                "top": int(row["top"]),
                "width": int(row["width"]),
                "height": int(row["height"]),
                "confidence": float(row["conf"]),
            })
        except (KeyError, TypeError, ValueError):
            continue
    return image, words


def _blue_pixels(image: Image.Image, cx: int, cy: int) -> int:
    return sum(
        1
        for y in range(cy - 5, cy + 6)
        for x in range(cx - 5, cx + 6)
        if BLUE(*image.getpixel((x, y)))
    )


def inspect_custom_before(png: Path, ocr_path: Path, tsv_path: Path) -> dict:
    image, words = _load(png, ocr_path, tsv_path)
    labels = [
        w for w in words
        if w["text"] == "custom" and w["confidence"] >= 75
        and 245 <= w["left"] <= 305 and 470 <= w["top"] <= 490
    ]
    if len(labels) != 1:
        raise CustomSelectionRefusal("Custom radio label is not unique")
    automatic = [
        w for w in words
        if w["text"] == "automatic" and w["confidence"] >= 75
        and 35 <= w["left"] <= 115 and 470 <= w["top"] <= 490
    ]
    if len(automatic) != 1:
        raise CustomSelectionRefusal("Automatic radio label is not unique")
    label = labels[0]
    cy = label["top"] + label["height"] // 2
    point = {"x": label["left"] - 13, "y": cy}
    if not (220 <= point["x"] <= 245 and 475 <= point["y"] <= 490):
        raise CustomSelectionRefusal("Custom radio geometry outside verified bounds")
    custom_blue = _blue_pixels(image, point["x"], point["y"])
    automatic_blue = _blue_pixels(image, 29, cy)
    if custom_blue > 2 or automatic_blue < 8:
        raise CustomSelectionRefusal("Expected Automatic selected and Custom unselected")
    return {
        "phase": "before-custom-click",
        "coordinate": point,
        "automaticSelectedObserved": True,
        "customUnselectedObserved": True,
        "onlyCustomRadioClickPermitted": True,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
    }


def verify_custom_after(png: Path, ocr_path: Path, tsv_path: Path) -> dict:
    image, words = _load(png, ocr_path, tsv_path)
    labels = [
        w for w in words
        if w["text"] == "custom" and w["confidence"] >= 75
        and 245 <= w["left"] <= 305 and 470 <= w["top"] <= 490
    ]
    if len(labels) != 1:
        raise CustomSelectionRefusal("Custom radio label is not unique after click")
    label = labels[0]
    cy = label["top"] + label["height"] // 2
    custom_blue = _blue_pixels(image, label["left"] - 13, cy)
    automatic_blue = _blue_pixels(image, 29, cy)
    if custom_blue < 8 or automatic_blue > 2:
        raise CustomSelectionRefusal("Custom selection was not visually confirmed")
    return {
        "phase": "after-custom-click",
        "customSelectedObserved": True,
        "automaticUnselectedObserved": True,
        "beginInstallationButtonClicked": False,
        "partitionEditorEntered": False,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
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
            inspect_custom_before(args.png, args.ocr, args.tsv)
            if args.phase == "before"
            else verify_custom_after(args.png, args.ocr, args.tsv)
        )
        if args.phase == "before":
            if args.coords is None or args.coords.is_symlink():
                raise CustomSelectionRefusal("A safe coordinate output path is required")
            point = result["coordinate"]
            args.coords.write_text(f'{point["x"]} {point["y"]}\\n', encoding="ascii")
    except (OSError, ValueError, UnicodeError) as exc:
        parser.exit(2, f"REFUSED: {exc}\\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
