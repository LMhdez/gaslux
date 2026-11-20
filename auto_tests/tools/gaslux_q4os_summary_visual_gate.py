#!/usr/bin/env python3
"""Strict read-only Q4OS 6.10 Calamares Users-to-Summary VNC screenshot gates.

Original Users ROI hashes come from two verified 1280x800 VMs, Actions
#44641233701; Summary ROI hashes match both independent original Summary
PNGs retained in failed-closed #44646209124 (no install was clicked). This file never
sends input or writes an installation/partition. Unknown screens fail closed.
"""

from __future__ import annotations

import hashlib
import re
import stat
import subprocess
import sys
from pathlib import Path

from PIL import Image

SCREEN = (1280, 800)
# Summary switches Calamares to a taller window whose top edge is at y=35
# rather than y=118 on Users. Never reuse Users' window-position ROI as proof.
SUMMARY_TOP_BAR = (
    (128, 35, 1152, 62),
    "a646832591ac4dcf3a5422faf34ef33ba88b2f6d3fe3747cbfa6e2300983d09d",
)
SUMMARY_SELECTED_SIDEBAR = (
    (128, 395, 318, 437),
    "e8e215c58f151ea1835a61f89c7ca2cf9eb4b2a69f71e343332931b80764ba2a",
)
SUMMARY_PARTITION_PLAN_HEADER = (
    (320, 323, 1152, 405),
    "edf5ff0bece1e7dde7677d298fe7f110b5841e1046cc561f3ccb3abed8949cd6",
)
TITLE = ((128, 118, 1152, 180), "b565add1ff9d5061918278f5cd8871a26b136dfdb04df78e6bcf74c8341b41e5")
USERS_SIDEBAR = (
    (128, 436, 318, 478),
    "afabb9afa668803a507dac9a4458cc51b54dbda969162f5f248034142c773693",
)
DISABLED_NEXT = (
    (957, 622, 1051, 663),
    "0416af48c325376e056f6ef8707b2ebdaedca7f935f2ddf8fc37bc93684d9512",
)
FIELDS = (
    (324, 182, 524, 215),  # Full name, original Q4OS Users screenshot
    (324, 250, 524, 282),  # Login
    (324, 318, 524, 350),  # Computer name
    (324, 386, 524, 418),  # Password
    (530, 386, 730, 418),  # Confirm password
)


class ScreenRefusal(ValueError):
    """Prevent a click unless all visual/identity gates passed."""


def load(path: Path) -> Image.Image:
    if not path.is_absolute() or path.is_symlink():
        raise ScreenRefusal("Screenshot path not absolute or symlinked")
    try:
        meta = path.lstat()
        if not stat.S_ISREG(meta.st_mode) or not 1024 <= meta.st_size <= 2 * 1024 * 1024:
            raise ScreenRefusal("Screenshot file type/size invalid")
        with Image.open(path) as file:
            if file.size != SCREEN or file.format != "PNG":
                raise ScreenRefusal("Unexpected Q4OS screenshot size/type")
            return file.convert("RGB")
    except (OSError, ValueError) as exc:
        raise ScreenRefusal("Unreadable original screenshot") from exc


def crop_sha(image: Image.Image, bbox: tuple[int, ...]) -> str:
    return hashlib.sha256(image.crop(bbox).tobytes()).hexdigest()


def ocr(path: Path) -> str:
    try:
        result = subprocess.run(
            ["tesseract", str(path), "stdout"],
            capture_output=True,
            text=True,
            timeout=40,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScreenRefusal("OCR did not complete") from exc
    return re.sub(r"\s+", " ", result.stdout).lower()


def users_original(path: Path) -> None:
    image = load(path)
    for bbox, expected in (TITLE, USERS_SIDEBAR, DISABLED_NEXT):
        if crop_sha(image, bbox) != expected:
            raise ScreenRefusal("Original pinned Users screenshot ROI identity mismatch")
    text = ocr(path)
    if any(t not in text for t in ("what is your name", "repeat password", "summary")):
        raise ScreenRefusal("Original Calamares Users fields not identified")


def users_with_dummy_data(before: Path, after: Path) -> None:
    users_original(before)
    baseline = load(before)
    filled = load(after)
    for bbox, expected in (TITLE, USERS_SIDEBAR):
        if crop_sha(filled, bbox) != expected:
            raise ScreenRefusal("Calamares changed identity before Next")
    for bbox in FIELDS:
        if crop_sha(baseline, bbox) == crop_sha(filled, bbox):
            raise ScreenRefusal("One of five dummy-only input fields did not visibly change")
    if crop_sha(filled, DISABLED_NEXT[0]) == DISABLED_NEXT[1]:
        raise ScreenRefusal("Calamares Next still disabled")
    text = ocr(after)
    if "gaslux lab" not in text or "gasluxlab" not in text:
        raise ScreenRefusal("Synthetic guest-only identity not visibly confirmed")
    if any(t in text for t in ("too short", "do not match", "invalid password")):
        raise ScreenRefusal("Calamares account validation warning persisted")


def summary_only(before: Path, after: Path) -> None:
    users = load(before)
    summary = load(after)
    for bbox, expected in (
        SUMMARY_TOP_BAR,
        SUMMARY_SELECTED_SIDEBAR,
        SUMMARY_PARTITION_PLAN_HEADER,
    ):
        if crop_sha(summary, bbox) != expected:
            raise ScreenRefusal("Unknown official Calamares Summary ROI")
    if crop_sha(summary, TITLE[0]) == TITLE[1]:
        raise ScreenRefusal("Users page title did not advance to Summary")
    if crop_sha(summary, USERS_SIDEBAR[0]) == crop_sha(users, USERS_SIDEBAR[0]):
        raise ScreenRefusal("Still on Users: sidebar did not change")
    region = (128, 150, 1152, 610)
    if crop_sha(summary, region) == crop_sha(users, region):
        raise ScreenRefusal("No central content transition after Users Next")
    text = ocr(after)
    # Real Tesseract on both source PNGs misses the highlighted Summary word.
    # Enforce exact independently matching Summary sidebar ROI above instead.
    required_text = ("this is an overview", "partitions", "erase disk")
    if any(token not in text for token in required_text) or "what is your name?" in text:
        raise ScreenRefusal("Native Calamares Summary/partition preview text absent")
    if any(t in text for t in ("installing...", "installation in progress", "copying files")):
        raise ScreenRefusal("Installer execution appears to have begun")


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit("usage: q4os_summary_visual_gate.py MODE BEFORE [AFTER]")
    op = sys.argv[1]
    paths = [Path(x) for x in sys.argv[2:]]
    try:
        if op == "pre" and len(paths) == 1:
            users_original(paths[0])
        elif op == "filled" and len(paths) == 2:
            users_with_dummy_data(paths[0], paths[1])
        elif op == "summary" and len(paths) == 2:
            summary_only(paths[0], paths[1])
        else:
            raise ScreenRefusal("Unknown gate operation/argument count")
    except ScreenRefusal as exc:
        print("GASLUX_Q4OS_SUMMARY_GATE_REFUSED=" + str(exc), file=sys.stderr)
        return 1
    print("GASLUX_Q4OS_SUMMARY_GATE_" + op.upper() + "=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
