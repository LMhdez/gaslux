"""Fail-closed contracts for QEMU SIGKILL recovery, not Windows/Calamares."""

from __future__ import annotations

import signal
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets" / "live"))
sys.path.insert(0, str(ROOT / "auto_tests" / "tools"))

from gaslux_q4os_bounded_cow_write_lab import (  # noqa: E402
    POWER_CUT_MODE,
    POWER_CUT_READY,
    BoundVmWriteRefusal,
    _authenticate_guest_write,
    run_lab,
)


def test_power_cut_messages_are_distinct_from_production_protocol():
    assert POWER_CUT_MODE == "SIMULATE-POWER-CUT"
    assert POWER_CUT_READY == b"GQ4OS-WRITE-SYNCED-BLOCKED-V1"


@pytest.mark.parametrize("bad_mode", [None, 0, 1, "true", [], {}])
def test_guest_write_laboratory_refuses_nonboolean_cut_mode(bad_mode):
    with pytest.raises(BoundVmWriteRefusal, match="boolean"):
        run_lab(
            *(Path(f"/tmp/nonexistent-q4os-powercut-{i}") for i in range(6)),
            simulate_power_cut=bad_mode,
        )


@pytest.mark.parametrize("setting", [None, "", "false", "1", "YES", "yes "])
def test_power_cut_requires_separate_explicit_opt_in(monkeypatch, tmp_path, setting):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GASLUX_Q4OS_SYNTHETIC_WRITE_LAB_ONLY", "yes")
    if setting is None:
        monkeypatch.delenv("GASLUX_Q4OS_POWER_CUT_LAB_ONLY", raising=False)
    else:
        monkeypatch.setenv("GASLUX_Q4OS_POWER_CUT_LAB_ONLY", setting)
    with pytest.raises(BoundVmWriteRefusal, match="power-cut-only"):
        run_lab(
            *(tmp_path / f"not-present-{i}" for i in range(6)),
            simulate_power_cut=True,
        )


def test_regular_signed_write_gate_keeps_powercut_mode_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    monkeypatch.delenv("GASLUX_Q4OS_POWER_CUT_LAB_ONLY", raising=False)
    with pytest.raises(BoundVmWriteRefusal, match="synthetic QEMU-only write lab"):
        run_lab(*(tmp_path / f"not-present-{i}" for i in range(6)))


def test_cut_barrier_only_reachable_after_guest_fsync_and_gpt_verification():
    src = (ROOT / "auto_tests/tools/q4os_guest_bound_write_agent.py").read_text(encoding="utf-8")
    assert src.index("os.fsync(handle)") < src.index("gpt_after = inspect_gpt_fd(")
    assert src.index("gpt_after = inspect_gpt_fd(") < src.index("_report(fd, RESULT")
    assert src.index("_report(fd, RESULT") < src.index("_write_all(fd, POWER_CUT_READY")
    assert "if power_cut:" in src
    assert "_read_line(fd, 64)" in src
    assert "SIMULATE-POWER-CUT" in src


def test_sigkill_uses_authenticated_report_instead_of_buffered_serial_log():
    src = (ROOT / "auto_tests/tools/gaslux_q4os_bounded_cow_write_lab.py").read_text(
        encoding="utf-8"
    )
    assert "if not simulate_power_cut:" in src
    assert "Missing guest serial evidence of the bounded write" in src
    assert "guest power-cut barrier" in src
    assert "Unauthenticated guest write report" in src
    assert "process.returncode == -signal.SIGKILL" in src


def test_host_kills_live_qemu_process_not_agent_or_graceful_guest():
    src = (ROOT / "auto_tests/tools/gaslux_q4os_bounded_cow_write_lab.py").read_text(
        encoding="utf-8"
    )
    assert src.index("process.kill()") < src.index("process.wait(timeout=30)")
    assert "process.returncode == -signal.SIGKILL" in src
    assert "Guest shut down before injected power cut" in src
    assert "Guest failed to remain active after durable write" in src
    assert "qemuKilledBySigkill" in src
    assert signal.SIGKILL == 9


def test_powercut_checkpoint_is_durable_and_revalidated_before_discarding():
    src = (ROOT / "auto_tests/tools/gaslux_q4os_bounded_cow_write_lab.py").read_text(
        encoding="utf-8"
    )
    assert src.index('checkpoint_state["powerCutObserved"] = True') < src.index(
        'checkpoint_state["guestWriteObserved"] = True'
    )
    assert src.index('checkpoint_state["guestWriteObserved"] = True') < src.index(
        "overlay.unlink()"
    )
    assert src.index("_restore_verified_snapshot(") < src.index("overlay.unlink()")
    assert 'checkpoint_state["postPowerCutRecoveryVerified"] = simulate_power_cut' in src
    assert '"rollbackVerified": False' in src
    assert '"installationAuthorized": False' in src


def test_host_cut_mode_requires_explicit_boolean():
    with pytest.raises(BoundVmWriteRefusal, match="boolean"):
        _authenticate_guest_write(
            workspace=Path("/tmp"),
            overlay=Path("/tmp/not-an-overlay"),
            kernel=Path("/tmp/not-a-kernel"),
            initramfs=Path("/tmp/not-an-initramfs"),
            plan={},
            evidence=Path("/tmp"),
            simulate_power_cut="yes",
        )


def test_powercut_workflow_still_forbids_windows_calamares_and_physical_disks():
    yml = (ROOT / ".github/workflows/gaslux-q4os-powercut-recovery.yml").read_text(encoding="utf-8")
    assert "GASLUX_Q4OS_POWER_CUT_LAB_ONLY: 'yes'" in yml
    assert "GASLUX_Q4OS_SYNTHETIC_WRITE_LAB_ONLY: 'yes'" in yml
    assert "GASLUX_Q4OS_KERNEL" in yml
    assert "SIGKILL" in yml
    assert "--power-cut" in yml
    assert "q4os-bounded-write-recovery-checkpoint.json" in yml
    assert "q4os-qemu-guest-identity.json" in yml
    assert 'assert result["rollbackVerified"] is False' in yml
    assert 'assert result["calamaresExecuted"] is False' in yml
    assert "qemu-system-x86_64" in (
        ROOT / "auto_tests/tools/gaslux_q4os_bounded_cow_write_lab.py"
    ).read_text(encoding="utf-8")


def test_ci_runs_only_disposable_file_guest_and_never_windows_disk(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    monkeypatch.setenv("GASLUX_Q4OS_POWER_CUT_LAB_ONLY", "yes")
    monkeypatch.setenv("GASLUX_Q4OS_SYNTHETIC_WRITE_LAB_ONLY", "yes")
    with pytest.raises(BoundVmWriteRefusal, match="synthetic QEMU-only"):
        run_lab(
            *(tmp_path / f"cannot-write-{i}" for i in range(6)),
            simulate_power_cut=True,
        )


def test_powercut_does_not_inherit_environment_write_permission(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GASLUX_Q4OS_POWER_CUT_LAB_ONLY", "yes")
    monkeypatch.delenv("GASLUX_Q4OS_SYNTHETIC_WRITE_LAB_ONLY", raising=False)
    with pytest.raises(BoundVmWriteRefusal, match="synthetic QEMU-only"):
        run_lab(
            *(tmp_path / f"cannot-write-{i}" for i in range(6)),
            simulate_power_cut=True,
        )
