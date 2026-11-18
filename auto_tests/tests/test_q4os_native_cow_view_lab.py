"""Q4OS native Calamares synthetic-COW preview: fail-closed no-write contracts."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets" / "live"))
sys.path.insert(0, str(ROOT / "auto_tests" / "tools"))

from gaslux_q4os_native_cow_view_guard import (  # noqa: E402
    AUDIT,
    OVERLAY,
    SERIAL_FILE,
    CalamaresCowViewRefusal,
    _inputs,
    prepare,
    verify,
)


def _paths(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    workspace = tmp_path / "gaslux-q4os-graphics-ABCDEFG"
    workspace.mkdir(mode=0o700)
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    return (
        workspace,
        tmp_path / "q4os-cow-plan-12345",
        tmp_path / "q4os-cow-snapshot-12345",
        evidence,
    )


@pytest.mark.parametrize("mode", ["", "no", "1", "true", "YES", "yes "])
def test_native_cow_view_requires_separate_explicit_optin(monkeypatch, tmp_path, mode):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "1234567890")
    monkeypatch.setenv("GASLUX_Q4OS_NATIVE_COW_VIEW_ONLY", mode)
    with pytest.raises(CalamaresCowViewRefusal, match="opt-in"):
        _inputs(*_paths(tmp_path))


def test_native_cow_view_refuses_non_actions_context(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    monkeypatch.setenv("GASLUX_Q4OS_NATIVE_COW_VIEW_ONLY", "yes")
    with pytest.raises(CalamaresCowViewRefusal, match="opt-in"):
        _inputs(*_paths(tmp_path))


def test_native_cow_view_rejects_empty_or_forged_run_id(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GASLUX_Q4OS_NATIVE_COW_VIEW_ONLY", "yes")
    monkeypatch.setenv("GITHUB_RUN_ID", "../forged")
    with pytest.raises(CalamaresCowViewRefusal, match="run ID"):
        _inputs(*_paths(tmp_path))


def test_native_cow_view_rejects_workspace_outside_q4os_lab(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GASLUX_Q4OS_NATIVE_COW_VIEW_ONLY", "yes")
    monkeypatch.setenv("GITHUB_RUN_ID", "1234567890")
    workspace, plan, snapshot, evidence = _paths(tmp_path)
    foreign = tmp_path / "foreign-workspace"
    foreign.mkdir(mode=0o700)
    with pytest.raises(CalamaresCowViewRefusal, match="fresh"):
        _inputs(foreign, plan, snapshot, evidence)
    with pytest.raises(CalamaresCowViewRefusal, match="synthetic base GPT"):
        _inputs(workspace, plan, snapshot, evidence)


def test_native_cow_plan_never_conflates_calamares_preview_with_install(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    monkeypatch.setenv("GASLUX_Q4OS_NATIVE_COW_VIEW_ONLY", "yes")
    with pytest.raises(CalamaresCowViewRefusal):
        prepare(*_paths(tmp_path))
    with pytest.raises(CalamaresCowViewRefusal):
        verify(*_paths(tmp_path))


def test_native_cow_guard_never_uses_user_disk_or_writes_gpt():
    guard = (ROOT / "auto_tests/tools/gaslux_q4os_native_cow_view_guard.py").read_text()
    assert 'OVERLAY = "q4os-native-calamares-view-only.qcow2"' in guard
    assert "qemu-img" in guard
    assert "compare" in guard
    assert "snapshot_lab" in guard
    assert "signed_plan_lab" in guard
    assert 'installationAuthorized": False' in guard
    assert 'calamaresJobsExecuted": False' in guard
    assert 'windowsDiskAttached": False' in guard
    assert "sgdisk --zap-all" not in guard
    assert "mkfs." not in guard
    assert "calamares -d" not in guard
    assert "os.pwrite" not in guard
    assert OVERLAY.startswith("q4os-")
    assert SERIAL_FILE.endswith(".txt")
    assert AUDIT.endswith(".json")


def test_gui_script_proves_radio_select_only_with_signed_snapshot():
    src = (ROOT / "auto_tests/tools/gaslux_q4os_calamares_gui_laboratory.sh").read_text()
    assert 'GASLUX_Q4OS_NATIVE_COW_VIEW_ONLY' in src
    assert "gaslux_q4os_native_cow_view_guard.py" in src
    assert "calamares-synthetic-cow-partitions" in src
    assert "q4os-native-calamares-view-only.qcow2" in src
    assert "GASLUX_Q4OS_CALAMARES_INSTALL_CLICKED=NO" in src
    assert "python3 \"$guard_script\" prepare" in src
    assert "python3 \"$guard_script\" verify" in src
    assert src.index('python3 "$guard_script" prepare') < src.index("qemu-system-x86_64")
    assert "move 334 280 click 1" in src
    assert "move 1002 644 click 1" in src  # existing non-destructive wizard navigation
    assert "GASLUX_Q4OS_CALAMARES_SYNTHETIC_RADIO_SELECTED=PASS" in src


def test_native_cow_guard_source_never_installs_a_real_distro():
    source = (ROOT / "auto_tests/tools/gaslux_q4os_native_cow_view_guard.py").read_text()
    assert 'calamaresJobsExecuted": False' in source
    assert 'linuxRootPartitionCreated": False' in source
    assert 'guestVisibleSerialVerifiedInLive": False' in source
    assert 'guestDiskWritesAuthorized": False' in source
    assert "guestCOWUnchanged" in source
    assert "overlay.unlink()" in source
    assert "recoverySnapshotStillMatchesBase" in source


def test_screenshot_gate_is_exact_official_q4os_native_partitions():
    gate = (ROOT / "auto_tests/tools/gaslux_q4os_vnc_visual_gate.py").read_text()
    assert "verified_synthetic_calamares_partitions_view" in gate
    assert "6975d6f85bebbb4dcd444c9bcdaa6f776880d8a9b5ff361e34b0829684cfb762" in gate
    assert "c62608a7994f551be49ac138c245ab4c11d78c148671b827c2ceda2ac274219e" in gate
    assert "0416af48c325376e056f6ef8707b2ebdaedca7f935f2ddf8fc37bc93684d9512" in gate
