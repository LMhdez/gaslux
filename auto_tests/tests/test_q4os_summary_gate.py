"""Negative contracts for guarded, read-only Q4OS Users -> Summary experiment."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "auto_tests/tools"


def import_file(name: str):
    path = TOOLS / name
    spec = importlib.util.spec_from_file_location(name.replace(".", "_"), path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_random_image_cannot_be_q4os_users(tmp_path: Path) -> None:
    gate = import_file("gaslux_q4os_summary_visual_gate.py")
    image = tmp_path / "untrusted.png"
    Image.new("RGB", (1280, 800), "white").save(image)
    with pytest.raises(gate.ScreenRefusal):
        gate.users_original(image)


def test_wrong_resolution_refused_before_any_vnc(tmp_path: Path) -> None:
    gate = import_file("gaslux_q4os_summary_visual_gate.py")
    image = tmp_path / "small.png"
    Image.new("RGB", (640, 480), "white").save(image)
    with pytest.raises(gate.ScreenRefusal):
        gate.load(image)


def test_symlinked_original_rejected(tmp_path: Path) -> None:
    gate = import_file("gaslux_q4os_summary_visual_gate.py")
    image = tmp_path / "original.png"
    Image.new("RGB", (1280, 800), "white").save(image)
    alias = tmp_path / "alias.png"
    alias.symlink_to(image)
    with pytest.raises(gate.ScreenRefusal):
        gate.load(alias)


def test_patch_requires_exact_once_original_anchor(tmp_path: Path) -> None:
    mod = import_file("gaslux_q4os_patch_summary_lab.py")
    path = tmp_path / "source.sh"
    path.write_text("calamares_users_view_verified=1\n" + mod.OLD + "\n")
    import sys

    old_argv = sys.argv
    try:
        sys.argv = ["patch", str(path.resolve())]
        mod.main()
        updated = path.read_text()
        assert "GASLUX_Q4OS_SUMMARY_READONLY_HOOK" in updated
        assert "calamares_users_view_verified=1" in updated
        with pytest.raises(SystemExit):
            mod.main()
    finally:
        sys.argv = old_argv


def test_only_one_summary_next_click_in_guarded_hook() -> None:
    hook = (TOOLS / "gaslux_q4os_summary_readonly_hook.sh").read_text()
    workflow = (ROOT / ".github/workflows/q4os-summary-repro-2vm.yml").read_text()
    assert hook.count("move 1002 644 click 1") == 1
    assert hook.count('python3 "$readonly_gate" filled') == 1
    assert hook.count('python3 "$readonly_gate" summary') == 1
    assert "GASLUX_Q4OS_NATIVE_COW_VIEW_ONLY" in hook
    assert "GASLUX_Q4OS_SUMMARY_READONLY: '1'" in workflow
    assert "GASLUX_Q4OS_GRAPHICS_LAB_ONLY: '1'" in workflow
    assert "partitionWriterAuthorized" in hook
    assert "calamaresInstallClicked" in hook
    assert "retention-days: 14" in workflow
    subprocess.run(["bash", "-n", str(TOOLS / "gaslux_q4os_summary_readonly_hook.sh")], check=True)
