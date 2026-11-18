#!/usr/bin/env python3
"""Read-only language-screen navigation target scout from prior diskless OVMF PNG.

A proposed coordinate is evidence ONLY and never authorizes installer input
or disk/ESP writes. The actual image and OCR must be checked in each new VM.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
from pathlib import Path

EXPECTED_SCREEN_SHA = "a1df7a3b73c2422ca6a7549ff1ad71bbeac46961d01d133bf0307e4b2cd372a8"
BANNER = re.compile(r"\bBAZZITE\s+42\s+INSTALLATION\b", re.I)
WELCOME = re.compile(r"\bWELCOME\s+TO\s+BAZZITE\s+42\b", re.I)
MAX_TSV_BYTES = 1024 * 1024
MAX_OCR_BYTES = 32768


class ScreenRefusal(ValueError):
    """Fail closed on ambiguous, missing or mismatched visual evidence."""


def _get_words(tsv_text: str) -> list[dict]:
    try:
        rows = csv.DictReader(io.StringIO(tsv_text), delimiter="\t")
        required_fields = {"text", "conf", "left", "top", "width", "height", "level"}
        if not rows.fieldnames or not required_fields <= set(rows.fieldnames):
            raise ScreenRefusal("Missing Tesseract TSV fields")
        words = []
        for row in rows:
            if row["level"] != "5" or not row["text"].strip():
                continue
            try:
                left, top, width, height = [int(row[k]) for k in ("left", "top", "width", "height")]
                confidence = float(row["conf"])
            except (ValueError, TypeError) as exc:
                raise ScreenRefusal("Invalid Tesseract numeric geometry") from exc
            if width <= 0 or height <= 0 or left < 0 or top < 0:
                raise ScreenRefusal("Invalid word rectangle")
            words.append(
                {
                    "text": row["text"].strip(),
                    "left": left,
                    "top": top,
                    "width": width,
                    "height": height,
                    "confidence": confidence,
                }
            )
        return words
    except (csv.Error, UnicodeError) as exc:
        raise ScreenRefusal("Unsafe or invalid OCR metadata") from exc


def inspect(*, width: int, height: int, png_sha: str, ocr: str, tsv: str) -> dict:
    allowed_shape = 1024 <= width <= 1920 and 600 <= height <= 1200
    if type(width) is not int or type(height) is not int or not allowed_shape:
        raise ScreenRefusal("Unexpected installer screenshot dimensions")
    if png_sha != EXPECTED_SCREEN_SHA:
        raise ScreenRefusal("Screenshot SHA differs from independently audited diskless Actions")
    if not BANNER.search(ocr) or not WELCOME.search(ocr):
        raise ScreenRefusal("Bazzite legacy 42 installer welcome identity not confirmed")
    if len(ocr.encode()) > MAX_OCR_BYTES or len(tsv.encode()) > MAX_TSV_BYTES:
        raise ScreenRefusal("Unbounded OCR input")
    words = _get_words(tsv)
    candidates = []
    for word in words:
        if re.sub(r"[^a-z]", "", word["text"].lower()) != "continue":
            continue
        if word["confidence"] < 40:
            continue
        cx = word["left"] + word["width"] // 2
        cy = word["top"] + word["height"] // 2
        if cx >= width or cy >= height:
            raise ScreenRefusal("Target outside guest framebuffer")
        candidates.append({"x": cx, "y": cy, "confidence": round(word["confidence"], 1)})
    # Position is *candidate* only. No click until independent run-local validation,
    # diskless VM ownership, live screenshot and a manual review of the artifact.
    bottom_right = [c for c in candidates if c["x"] >= width * 0.60 and c["y"] >= height * 0.65]
    unique = len(candidates) == 1 and len(bottom_right) == 1
    return {
        "distributionId": "bazzite",
        "observedVersionBanner": "42",
        "sourceKind": "exact-prior-diskless-actions-screenshot",
        "sourceScreenshotSha256": png_sha,
        "targetWordCount": len(candidates),
        "bottomRightCandidateCount": len(bottom_right),
        "unambiguousContinueLabelCandidate": unique,
        "candidateCenter": bottom_right[0] if unique else None,
        "ocrExcerptTail": ocr[-1400:],
        "lowerRightDetectedWords": [
            {
                "word": word["text"][:50],
                "x": word["left"] + word["width"] // 2,
                "y": word["top"] + word["height"] // 2,
                "confidence": round(word["confidence"], 1),
            }
            for word in words
            if word["left"] + word["width"] // 2 >= width * 0.52
            and word["top"] + word["height"] // 2 >= height * 0.60
        ][:50],
        "candidateIsUiPositionOnly": True,
        "runLocalScreenshotRevalidationRequired": True,
        "actualInstallerBinaryVerified": False,
        "blivetGuiVerified": False,
        "installerInputAuthorized": False,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "secureBootEnrollmentAuthorized": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ocr", type=Path, required=True)
    parser.add_argument("--tsv", type=Path, required=True)
    parser.add_argument("--png", type=Path, required=True)
    args = parser.parse_args()
    try:
        from PIL import Image

        if any(p.is_symlink() for p in (args.ocr, args.tsv, args.png)):
            raise ScreenRefusal("Symlink input refused")
        if args.png.stat().st_size > 5 * 1024 * 1024:
            raise ScreenRefusal("Oversized screenshot")
        with Image.open(args.png) as im:
            width, height = im.size
            im.verify()
        sha = hashlib.sha256(args.png.read_bytes()).hexdigest()
        ocr = args.ocr.read_text(encoding="utf-8")
        tsv = args.tsv.read_text(encoding="utf-8")
        result = inspect(width=width, height=height, png_sha=sha, ocr=ocr, tsv=tsv)
    except (OSError, ValueError, UnicodeError, ScreenRefusal) as exc:
        parser.exit(2, f"REFUSED: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
