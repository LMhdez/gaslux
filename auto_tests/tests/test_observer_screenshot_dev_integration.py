"""Offline, non-operational tests for historic Observer screenshot primitives.

These static synthetic PNG fixtures do not attest a VM framebuffer or allow input.
"""

from __future__ import annotations

import ast
import io
from pathlib import Path

import pytest
from PIL import Image

from auto_tests.installer_observer.evidence import Refusal, digest
from auto_tests.installer_observer.screenshot import (
    IEND,
    MAX_PNG,
    Screenshot,
    valid_box,
)

ROOT = Path(__file__).resolve().parents[2]


def image_bytes(size=(16, 12), color=(10, 20, 30)):
    output = io.BytesIO()
    Image.new("RGB", size, color).save(output, format="PNG")
    return output.getvalue()


def test_synthetic_png_decoded_with_exact_size_hash_and_roi():
    png = image_bytes()
    observed = Screenshot.decode(png, (16, 12), digest(png))
    assert observed.sha256 == digest(png)
    assert observed.png == png
    assert observed.image.size == (16, 12)
    assert observed.roi((2, 3, 7, 9)) == digest(observed.image.crop((2, 3, 7, 9)).tobytes())


@pytest.mark.parametrize(
    "invalid",
    (
        b"",
        b"not-a-png",
        b"not-a-png" + IEND,
        image_bytes()[:-5],
        image_bytes() + b"trailing",
        b"\x89PNG\r\n\x1a\n" + IEND,
        b"x" * (MAX_PNG + 1),
    ),
)
def test_png_corrupt_truncated_trailing_or_unbounded_is_refused(invalid):
    with pytest.raises(Refusal):
        Screenshot.decode(invalid, (16, 12))


def test_frame_identity_and_size_must_match_reviewed_expectations():
    png = image_bytes()
    for wrong_size, wrong_digest in (
        ((17, 12), digest(png)),
        ((16, 13), digest(png)),
        ((16, 12), "0" * 64),
    ):
        with pytest.raises(Refusal):
            Screenshot.decode(png, wrong_size, wrong_digest)


@pytest.mark.parametrize(
    "box",
    (
        (0, 0, 17, 12),
        (0, 0, 16, 13),
        (-1, 0, 3, 3),
        (3, 3, 3, 4),
        (3, 3, 4, 3),
        (1, 2, True, 6),
        (0, 0, 4, False),
    ),
)
def test_out_of_bounds_or_noncanonical_roi_is_refused(box):
    screenshot = Screenshot.decode(image_bytes(), (16, 12))
    assert valid_box(box, (16, 12)) is False
    with pytest.raises(Refusal, match="Region outside"):
        screenshot.roi(box)


def test_no_process_network_writer_or_guest_control_in_png_decoder():
    path = ROOT / "auto_tests" / "installer_observer" / "screenshot.py"
    source = path.read_text(encoding="utf-8")
    module = ast.parse(source)
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            assert all(
                item.name.split(".")[0] not in {"subprocess", "socket", "paramiko", "vncdotool"}
                for item in node.names
            )
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in {
                "subprocess",
                "socket",
                "paramiko",
                "vncdotool",
            }
    assert set(dir(Screenshot)).isdisjoint(
        {"click", "type", "execute", "send", "send_key", "install", "authorize"}
    )
    assert "Qmp(" not in source
