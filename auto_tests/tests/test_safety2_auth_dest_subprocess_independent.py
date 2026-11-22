"""Independent Safety-2 subprocess adversarial tests against #346 real module.

The module under audit and its original oracles are NEVER patched on disk.
Only the subprocess launcher is monkeypatched to use real disposable Python
subprocesses, so _bounded_info owns selector/read/deadline/cleanup behavior.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from auto_tests.installer_observer import large_sparse_destination as actual

PARENT_SHA = "9306d0fff8cc89794b83fe002ae133c110e641ae"


@pytest.fixture
def source_fd(tmp_path: Path):
    image = tmp_path / "owned-regular-file.bin"
    image.write_bytes(b"readonly")
    with image.open("rb") as source:
        yield source.fileno()


@pytest.fixture
def budget():
    return actual.LargeReadOnlyBudget(known_quota_bytes=64 * 1024**2)


def _fake_popen(monkeypatch, program: str, *args: str):
    """Replace qemu-img Popen only; run a real program with identical pipes."""
    real_popen = subprocess.Popen
    started = []

    def invoke(_argv, **kwargs):
        child = real_popen(
            [sys.executable, "-c", program, *args],
            stdin=kwargs["stdin"],
            stdout=kwargs["stdout"],
            stderr=kwargs["stderr"],
            pass_fds=kwargs.get("pass_fds", ()),
            start_new_session=kwargs.get("start_new_session", False),
        )
        started.append(child)
        return child

    monkeypatch.setattr(actual.subprocess, "Popen", invoke)
    return started


def test_invalid_qemu_img_json_is_refused(source_fd, budget, monkeypatch):
    _fake_popen(monkeypatch, "import sys; sys.stdout.write('broken json')")
    with pytest.raises(actual.LargeDestinationRefused, match="QEMU_INFO_INVALID_JSON"):
        actual._bounded_info(source_fd, budget, time.monotonic() + 3)


def test_output_limit_kills_real_subprocess(source_fd, budget, monkeypatch):
    processes = _fake_popen(
        monkeypatch, "import sys, time; sys.stdout.write('Z'*70000); sys.stdout.flush(); time.sleep(10)"
    )
    with pytest.raises(actual.LargeDestinationRefused, match="QEMU_INFO_OUTPUT_LIMIT"):
        actual._bounded_info(source_fd, budget, time.monotonic() + 3)
    assert len(processes) == 1
    assert processes[0].poll() is not None, "direct output-producing process not reaped"


def test_timeout_kills_direct_real_subprocess(source_fd, budget, monkeypatch):
    processes = _fake_popen(monkeypatch, "import time; time.sleep(10)")
    with pytest.raises(actual.LargeDestinationRefused):
        actual._bounded_info(source_fd, budget, time.monotonic() + 0.5)
    assert len(processes) == 1
    assert processes[0].poll() is not None, "direct timed-out process not reaped"


def test_red_timeout_must_reap_descendant_inherited_pipe(
    source_fd, budget, monkeypatch, tmp_path: Path
):
    """RED: a completed parent leaves an orphan holding qemu-img stdout open.

    On the unmodified #346 module, proc.poll() != None bypasses kill().
    The call fails closed but leaks the descendant, violating cleanup isolation.
    """
    pidfile = tmp_path / "descendant.pid"
    launcher = textwrap.dedent(
        """
        import pathlib, subprocess, sys
        descendant = subprocess.Popen(
            [sys.executable, '-c', 'import time; time.sleep(20)'],
            stdin=subprocess.DEVNULL,
            stdout=sys.stdout,
            stderr=subprocess.DEVNULL,
        )
        pathlib.Path(sys.argv[1]).write_text(str(descendant.pid))
        """
    )
    processes = _fake_popen(monkeypatch, launcher, str(pidfile))
    descendant_pid = None
    try:
        with pytest.raises(actual.LargeDestinationRefused):
            actual._bounded_info(source_fd, budget, time.monotonic() + 1.0)
        assert processes and processes[0].poll() is not None
        for _ in range(20):
            if pidfile.exists():
                break
            time.sleep(0.02)
        assert pidfile.exists(), "test launcher did not start a real descendant"
        descendant_pid = int(pidfile.read_text())
        try:
            os.kill(descendant_pid, 0)
        except ProcessLookupError:
            pass
        else:
            pytest.fail(
                "SAFETY2-346-01 RED: descendant is still alive after "
                "_bounded_info() refused the timed-out pipe"
            )
    finally:
        if descendant_pid is None and pidfile.exists():
            descendant_pid = int(pidfile.read_text())
        if descendant_pid is not None:
            try:
                os.kill(descendant_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.mark.parametrize(
    "field, excessive",
    [
        ("max_virtual_bytes", 128 * 1024**3 + 1),
        ("max_qcow2_apparent_bytes", 64 * 1024**2 + 1),
        ("max_qcow2_allocated_bytes", 32 * 1024**2 + 1),
        ("max_raw_allocated_bytes", 32 * 1024**2 + 1),
        ("max_total_allocated_bytes", 64 * 1024**2 + 1),
        ("max_checkpoint_bytes", 64 * 1024 + 1),
        ("max_qemu_info_bytes", 64 * 1024 + 1),
        ("max_seconds", 31),
    ],
)
def test_budget_caps_reject_all_excess_values(field, excessive):
    with pytest.raises(actual.LargeDestinationRefused, match="INVALID_RESOURCE_LIMIT"):
        actual.LargeReadOnlyBudget(known_quota_bytes=64 * 1024**2, **{field: excessive})


def test_unknown_quota_is_explicitly_unproven():
    # Budget metadata may carry None; the assessment is responsible for refusal.
    value = actual.LargeReadOnlyBudget(known_quota_bytes=None)
    assert value.known_quota_bytes is None


@pytest.mark.parametrize("failure,expected", [("short", "SPARSE_SHORT_READ"), ("eio", "SPARSE_READ_IO_FAILED")])
def test_real_sparse_module_exact_read_fail_closed(source_fd, monkeypatch, failure, expected):
    """Call the actual bounded pread helper, not a replacement oracle."""
    original = actual.os.pread

    def injected(fd, count, offset):
        if fd == source_fd:
            if failure == "eio":
                raise OSError(5, "injected EIO")
            return original(fd, max(0, count - 1), offset)
        return original(fd, count, offset)

    monkeypatch.setattr(actual.os, "pread", injected)
    with pytest.raises(actual.LargeDestinationRefused, match=expected):
        actual._read_exact(source_fd, 0, 8, time.monotonic() + 2)
