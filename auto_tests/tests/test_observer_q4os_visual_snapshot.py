"""N-01 regressions: one authenticated byte snapshot per Q4OS screen.

Original pinned images stay immutable; path attacks use temporary copies.
No QEMU, network transport, guest click, or disk mutation is invoked.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from PIL import Image

from auto_tests.installer_observer import q4os
from auto_tests.installer_observer.evidence import read as evidence_read
from auto_tests.tools import gaslux_q4os_summary_visual_gate as gate


@pytest.fixture
def screenshots(tmp_path):
    source = q4os.ORIGINALS / "14590616864"
    paths = {}
    for name in ("vnc-users-page.png", "vnc-users-dummy-filled.png", "vnc-summary-page.png"):
        paths[name] = tmp_path / name
        shutil.copyfile(source / name, paths[name])
    return paths


def _mock_ocr(monkeypatch, output: str):
    calls = []

    def runner(command, *, input, capture_output, timeout, check):
        assert command == ["tesseract", "stdin", "stdout"]
        assert isinstance(input, bytes)
        assert capture_output is True
        assert check is True
        assert timeout == 40
        calls.append(input)
        return SimpleNamespace(stdout=output.encode("utf-8"))

    monkeypatch.setattr(gate.subprocess, "run", runner)
    return calls


def test_absolute_path_and_bytes_produce_same_decoded_image(screenshots):
    path = screenshots["vnc-users-page.png"]
    data = evidence_read(path, gate.MAX_SCREENSHOT)
    assert gate.load(path).tobytes() == gate.load(data).tobytes()


def test_relative_path_refused():
    with pytest.raises(gate.ScreenRefusal):
        gate.load(Path("relative.png"))


def test_leaf_symlink_refused(tmp_path, screenshots):
    link = tmp_path / "linked.png"
    link.symlink_to(screenshots["vnc-users-page.png"])
    with pytest.raises(gate.ScreenRefusal):
        gate.load(link)


def test_parent_symlink_refused(tmp_path, screenshots):
    parent = tmp_path / "redirected"
    parent.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(gate.ScreenRefusal):
        gate.load(parent / "vnc-users-page.png")


def test_hardlink_refused(tmp_path, screenshots):
    alias = tmp_path / "hardlinked.png"
    os.link(screenshots["vnc-users-page.png"], alias)
    with pytest.raises(gate.ScreenRefusal):
        gate.load(alias)


def test_directory_and_fifo_refused(tmp_path):
    with pytest.raises(gate.ScreenRefusal):
        gate.load(tmp_path)
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "screen.pipe"
        os.mkfifo(fifo)
        with pytest.raises(gate.ScreenRefusal):
            gate.load(fifo)


def test_truncated_png_refused(tmp_path, screenshots):
    corrupted = tmp_path / "truncated.png"
    corrupted.write_bytes(evidence_read(screenshots["vnc-users-page.png"])[:4000])
    with pytest.raises(gate.ScreenRefusal):
        gate.load(corrupted)


def test_oversized_png_refused(tmp_path):
    oversized = tmp_path / "oversized.png"
    oversized.write_bytes(b"X" * (gate.MAX_SCREENSHOT + 1))
    with pytest.raises(gate.ScreenRefusal):
        gate.load(oversized)


def test_wrong_resolution_refused(tmp_path, screenshots):
    wrong = tmp_path / "wrong-resolution.png"
    with Image.open(screenshots["vnc-users-page.png"]) as original:
        original.crop((0, 0, 1279, 800)).save(wrong, format="PNG")
    with pytest.raises(gate.ScreenRefusal, match="size/type"):
        gate.load(wrong)


def test_invalid_bytes_and_invalid_type_refused(screenshots):
    with pytest.raises(gate.ScreenRefusal):
        gate.load(b"not a png" * 200)
    with pytest.raises(gate.ScreenRefusal):
        gate.load(str(screenshots["vnc-users-page.png"]))


def test_ocr_receives_snapshot_via_stdin_not_original_filename(monkeypatch, screenshots):
    source = screenshots["vnc-users-page.png"]
    original = evidence_read(source, gate.MAX_SCREENSHOT)
    calls = _mock_ocr(monkeypatch, "what is your name repeat password summary")
    gate.users_original(source)
    assert calls == [original]


def test_replaced_file_after_capture_cannot_change_ocr(monkeypatch, screenshots):
    path = screenshots["vnc-users-page.png"]
    original = evidence_read(path, gate.MAX_SCREENSHOT)
    actual_read = gate.read
    reads = []

    def replace_after_read(source, limit):
        captured = actual_read(source, limit)
        reads.append(captured)
        path.write_bytes(b"malicious replacement after snapshot")
        return captured

    monkeypatch.setattr(gate, "read", replace_after_read)
    ocr_inputs = _mock_ocr(monkeypatch, "what is your name repeat password summary")
    gate.users_original(path)
    assert reads == [original]
    assert ocr_inputs == [original]
    assert path.read_bytes() != original


def test_path_replaced_before_ocr_does_not_trigger_new_open(monkeypatch, screenshots):
    path = screenshots["vnc-users-page.png"]
    captured = evidence_read(path, gate.MAX_SCREENSHOT)
    ocr_inputs = []

    def replace_in_ocr(command, *, input, capture_output, timeout, check):
        assert command == ["tesseract", "stdin", "stdout"]
        path.unlink()
        path.write_bytes(b"replacement before OCR")
        ocr_inputs.append(input)
        return SimpleNamespace(stdout=b"what is your name repeat password summary")

    monkeypatch.setattr(gate.subprocess, "run", replace_in_ocr)
    gate.users_original(path)
    assert ocr_inputs == [captured]


def test_tesseract_failure_and_timeout_fail_closed(monkeypatch, screenshots):
    path = screenshots["vnc-users-page.png"]

    def fails(*_args, **_kwargs):
        raise subprocess.CalledProcessError(1, "tesseract")

    monkeypatch.setattr(gate.subprocess, "run", fails)
    with pytest.raises(gate.ScreenRefusal, match="OCR did not complete"):
        gate.users_original(path)

    def times_out(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("tesseract", 40)

    monkeypatch.setattr(gate.subprocess, "run", times_out)
    with pytest.raises(gate.ScreenRefusal, match="OCR did not complete"):
        gate.users_original(path)


def test_users_with_dummy_data_reads_before_and_after_once(monkeypatch, screenshots):
    before = screenshots["vnc-users-page.png"]
    after = screenshots["vnc-users-dummy-filled.png"]
    source_read = gate.read
    seen = []

    def counted(path, limit):
        seen.append(path)
        return source_read(path, limit)

    monkeypatch.setattr(gate, "read", counted)
    ocr_inputs = _mock_ocr(
        monkeypatch, "what is your name repeat password summary gaslux lab gasluxlab"
    )
    gate.users_with_dummy_data(before, after)
    assert seen == [before, after]
    assert ocr_inputs == [
        evidence_read(before, gate.MAX_SCREENSHOT),
        evidence_read(after, gate.MAX_SCREENSHOT),
    ]


def test_summary_only_reads_both_screenshots_once(monkeypatch, screenshots):
    before = screenshots["vnc-users-dummy-filled.png"]
    after = screenshots["vnc-summary-page.png"]
    source_read = gate.read
    seen = []

    def counted(path, limit):
        seen.append(path)
        return source_read(path, limit)

    monkeypatch.setattr(gate, "read", counted)
    ocr_inputs = _mock_ocr(monkeypatch, "this is an overview partitions erase disk")
    gate.summary_only(before, after)
    assert seen == [before, after]
    assert ocr_inputs == [evidence_read(after, gate.MAX_SCREENSHOT)]


def test_user_path_is_not_reopened_between_nested_pixel_and_ocr(monkeypatch, screenshots):
    before = screenshots["vnc-users-page.png"]
    after = screenshots["vnc-users-dummy-filled.png"]
    old_read = gate.read
    counter = {before: 0, after: 0}

    def guarded(path, limit):
        counter[path] += 1
        if counter[path] > 1:
            pytest.fail("Same screenshot path reopened after acquisition")
        return old_read(path, limit)

    monkeypatch.setattr(gate, "read", guarded)
    _mock_ocr(monkeypatch, "what is your name repeat password summary gaslux lab gasluxlab")
    gate.users_with_dummy_data(before, after)
    assert counter == {before: 1, after: 1}


def test_ocr_bytes_and_path_are_equivalent(monkeypatch, screenshots):
    path = screenshots["vnc-users-page.png"]
    data = evidence_read(path, gate.MAX_SCREENSHOT)
    inputs = _mock_ocr(monkeypatch, "what is your name repeat password summary")
    assert gate.ocr(path) == gate.ocr(data)
    assert inputs == [data, data]


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        (
            b"This is an\noverview\tpartitions\r\nerase disk",
            "this is an overview partitions erase disk",
        ),
        (
            b"This    is   an overview   partitions   erase disk",
            "this is an overview partitions erase disk",
        ),
        (
            b"This\tis\tan\toverview\tpartitions\terase disk",
            "this is an overview partitions erase disk",
        ),
        (
            b"This is an\r\noverview\r\npartitions\r\nerase disk",
            "this is an overview partitions erase disk",
        ),
        (
            b"This is an\noverview\npartitions\nerase disk",
            "this is an overview partitions erase disk",
        ),
        (
            "This\u00a0is\u2003an overview\u2028partitions erase disk".encode("utf-8"),
            "this is an overview partitions erase disk",
        ),
    ],
)
def test_ocr_snapshot_normalizes_real_whitespace(monkeypatch, stdout, expected):
    snapshot = b"original-image-snapshot"
    captured = []

    def tesseract(command, *, input, capture_output, timeout, check):
        assert command == ["tesseract", "stdin", "stdout"]
        assert capture_output is True
        assert timeout == 40
        assert check is True
        captured.append(input)
        return SimpleNamespace(stdout=stdout)

    monkeypatch.setattr(gate.subprocess, "run", tesseract)
    assert gate._ocr_snapshot(snapshot) == expected
    assert captured == [snapshot]


@pytest.mark.parametrize(
    "error",
    [subprocess.CalledProcessError(1, "tesseract"), subprocess.TimeoutExpired("tesseract", 40)],
)
def test_ocr_snapshot_subprocess_failures_remain_terminal(monkeypatch, error):
    def tesseract(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(gate.subprocess, "run", tesseract)
    with pytest.raises(gate.ScreenRefusal, match="OCR did not complete"):
        gate._ocr_snapshot(b"original-image-snapshot")
