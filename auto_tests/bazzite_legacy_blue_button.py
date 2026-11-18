#!/usr/bin/env python3
"""Read-only, color-validated Continue button locator for Bazzite 42 diskless UI.

Only a 1280x800 PNG with the specific Bazzite 42 language screen and a single
blue GTK Continue rectangle is eligible. Output is a guest UI point, never an
authorization to install or write any disk.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import subprocess
from collections.abc import Callable
from pathlib import Path

from bazzite_legacy_language_gate import BANNER, WELCOME

WIDTH = 1280
HEIGHT = 800
BLUE_REGION = (1150, 735, 1279, 798)


class ButtonRefusal(ValueError):
    """Unknown screenshot, ambiguous button or failed independent OCR."""


def _blue(r: int, g: int, b: int) -> bool:
    return 15 <= r <= 100 and 95 <= g <= 175 and b >= 190 and b - r > 100


def _ocr_threshold_png(data: bytes) -> str:
    proc = subprocess.run(
        ["tesseract", "stdin", "stdout", "--psm", "7"],
        input=data,
        capture_output=True,
        timeout=15,
        check=False,
    )
    if proc.returncode != 0:
        raise ButtonRefusal("Independent contrast-enhanced OCR failed")
    return proc.stdout.decode("utf-8", errors="strict")


def locate_continue(
    png: bytes, full_screen_ocr: str, ocr_engine: Callable[[bytes], str] = _ocr_threshold_png
) -> dict:
    if not isinstance(png, bytes) or not 0 < len(png) <= 5 * 1024 * 1024:
        raise ButtonRefusal("Bounded PNG screenshot required")
    if not BANNER.search(full_screen_ocr) or not WELCOME.search(full_screen_ocr):
        raise ButtonRefusal("Not the verified Bazzite 42 language screen")
    if len(full_screen_ocr.encode("utf-8")) > 32768:
        raise ButtonRefusal("Unbounded OCR")
    try:
        from PIL import Image

        with Image.open(io.BytesIO(png)) as image:
            image.verify()
        with Image.open(io.BytesIO(png)) as image:
            if image.size != (WIDTH, HEIGHT):
                raise ButtonRefusal("Unexpected guest framebuffer dimensions")
            image = image.convert("RGB")
            pixels = image.load()
            blue = [
                (x, y)
                for y in range(BLUE_REGION[1], BLUE_REGION[3])
                for x in range(BLUE_REGION[0], BLUE_REGION[2])
                if _blue(*pixels[x, y])
            ]
            if len(blue) < 2000:
                raise ButtonRefusal("No blue Continue button geometry")
            x0, x1 = min(x for x, _ in blue), max(x for x, _ in blue)
            y0, y1 = min(y for _, y in blue), max(y for _, y in blue)
            if not (
                1174 <= x0 <= 1181
                and 1269 <= x1 <= 1277
                and 752 <= y0 <= 759
                and 784 <= y1 <= 791
            ):
                raise ButtonRefusal("Unexpected blue control boundary")
            area = (x1 - x0 + 1) * (y1 - y0 + 1)
            if len(blue) / area < 0.80:
                raise ButtonRefusal("Ambiguous blue control fill")
            crop = image.crop((x0 + 3, y0 + 3, x1 - 2, y1 - 2))
            threshold = Image.new("L", crop.size, 255)
            for y in range(crop.height):
                for x in range(crop.width):
                    r, g, b = crop.getpixel((x, y))
                    if r > 100 and g > 130 and b > 160:
                        threshold.putpixel((x, y), 0)
            threshold = threshold.resize((crop.width * 5, crop.height * 5))
            output = io.BytesIO()
            threshold.save(output, format="PNG")
    except (OSError, RuntimeError, ValueError) as exc:
        raise ButtonRefusal("Invalid blue control image") from exc
    try:
        label = re.sub(r"[^a-z]", "", ocr_engine(output.getvalue()).lower())
    except (subprocess.TimeoutExpired, UnicodeError) as exc:
        raise ButtonRefusal("OCR timeout or encoding failure") from exc
    if label != "continue":
        raise ButtonRefusal("Contrast-enhanced button label was not Continue")
    return {
        "distributionId": "bazzite",
        "labOnly": True,
        "observedVersionBanner": "42",
        "blueContinueTextVerified": True,
        "blueContinueGeometryVerified": True,
        "coordinate": {"x": (x0 + x1) // 2, "y": (y0 + y1) // 2},
        "guestHardDiskRequired": False,
        "actualAnacondaBinaryVerified": False,
        "blivetGuiVerified": False,
        "isoProvenanceSignatureVerified": False,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "secureBootEnrollmentAuthorized": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--png", required=True, type=Path)
    parser.add_argument("--ocr", required=True, type=Path)
    parser.add_argument("--coords", required=True, type=Path)
    args = parser.parse_args()
    try:
        if any(path.is_symlink() for path in (args.png, args.ocr, args.coords)):
            raise ButtonRefusal("Symlink evidence path")
        result = locate_continue(
            args.png.read_bytes(), args.ocr.read_text(encoding="utf-8")
        )
        point = result["coordinate"]
        args.coords.write_text(f"{point['x']} {point['y']}\n", encoding="ascii")
    except (OSError, ButtonRefusal, UnicodeError) as exc:
        parser.exit(2, f"REFUSED: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
