#!/usr/bin/env python3
"""Conservative run-local OCR coordinates for Bazzite 42 diskless VM only.

Never returns a disk install authorization; clicks are guarded independently by
the GitHub Actions guest's no-network/no-disk QEMU command line.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from bazzite_legacy_language_gate import BANNER, WELCOME, _get_words

WIDTH = 1280
HEIGHT = 800


class NavigationRefusal(ValueError):
    """Unknown installer screen or ambiguous control location."""


def _check_screen(ocr: str, tsv: str, width: int, height: int) -> list[dict]:
    if type(width) is not int or type(height) is not int or (width, height) != (WIDTH, HEIGHT):
        raise NavigationRefusal("Unknown diskless legacy GUI geometry")
    if not BANNER.search(ocr) or not WELCOME.search(ocr):
        raise NavigationRefusal("Bazzite 42 installer welcome screen not positively recognized")
    if len(ocr.encode()) > 32768 or len(tsv.encode()) > 1024 * 1024:
        raise NavigationRefusal("Unbounded OCR or TSV content")
    return _get_words(tsv)


def locate_english_uk(ocr: str, tsv: str, width: int, height: int) -> dict:
    words = _check_screen(ocr, tsv, width, height)
    matches = []
    for word in words:
        if word["text"].lower() != "english" or word["left"] < width * 0.52:
            continue
        if word["confidence"] < 50:
            continue
        y = word["top"] + word["height"] // 2
        row = [
            peer
            for peer in words
            if abs(peer["top"] + peer["height"] // 2 - y) <= 10
            and word["left"] <= peer["left"] <= word["left"] + 250
        ]
        joined = re.sub(r"[^a-z]", "", " ".join(p["text"] for p in row).lower())
        if "englishunitedkingdom" in joined:
            matches.append({"x": word["left"] + word["width"] // 2, "y": y})
    if len(matches) != 1:
        raise NavigationRefusal("No unique English (United Kingdom) locale row")
    target = matches[0]
    inside_locale_list = (
        width * 0.55 < target["x"] < width * 0.85
        and height * 0.15 < target["y"] < height * 0.55
    )
    if not inside_locale_list:
        raise NavigationRefusal("Locale target outside expected safe list")
    return {
        "phase": "locale-choice",
        "coordinate": target,
        "targetUniquelyObserved": True,
        "labOnly": True,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
    }


def locate_continue(ocr: str, tsv: str, width: int, height: int) -> dict:
    words = _check_screen(ocr, tsv, width, height)
    matches = []
    for word in words:
        normalized = re.sub(r"[^a-z]", "", word["text"].lower())
        if normalized != "continue" or word["confidence"] < 50:
            continue
        x = word["left"] + word["width"] // 2
        y = word["top"] + word["height"] // 2
        if x > width * 0.60 and y > height * 0.65 and x < width and y < height:
            matches.append({"x": x, "y": y})
    if len(matches) > 1:
        raise NavigationRefusal("Multiple Continue controls")
    return {
        "phase": "continue-control",
        "coordinate": matches[0] if len(matches) == 1 else None,
        "targetUniquelyObserved": len(matches) == 1,
        "labOnly": True,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True, choices=["locale", "continue"])
    parser.add_argument("--png", required=True, type=Path)
    parser.add_argument("--ocr", required=True, type=Path)
    parser.add_argument("--tsv", required=True, type=Path)
    parser.add_argument("--coords", required=True, type=Path)
    args = parser.parse_args()
    try:
        from PIL import Image

        if any(p.is_symlink() for p in (args.png, args.ocr, args.tsv, args.coords)):
            raise NavigationRefusal("Symlink evidence path")
        with Image.open(args.png) as im:
            if im.size != (WIDTH, HEIGHT):
                raise NavigationRefusal("Unexpected guest framebuffer")
            if len(im.convert("RGB").getcolors(maxcolors=1000000) or []) <= 2:
                raise NavigationRefusal("Blank screenshot")
            im.verify()
        ocr = args.ocr.read_text(encoding="utf-8")
        tsv = args.tsv.read_text(encoding="utf-8")
        locator = locate_english_uk if args.phase == "locale" else locate_continue
        result = locator(ocr, tsv, WIDTH, HEIGHT)
    except (OSError, ValueError, UnicodeError) as exc:
        parser.exit(2, f"REFUSED: {exc}\n")
    if result["coordinate"] is not None:
        args.coords.write_text(
            f'{result["coordinate"]["x"]} {result["coordinate"]["y"]}\n',
            encoding="ascii",
        )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
