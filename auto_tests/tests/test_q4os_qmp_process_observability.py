"""Offline QEMU/QMP diagnostic adversarial tests: Popen is ALWAYS simulated."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "auto_tests/tools"))

import q4os_win10_qmp_supervisor as witness  # noqa: E402
from q4os_win10_qmp_boot import BootRefusal  # noqa: E402


@pytest.fixture
def lab(tmp_path):
    work = tmp_path / "private"
    work.mkdir(mode=0o700)
    work.chmod(0o700)
    files = []
    for name in ("vars.fd", "disk.qcow2", "win.iso", "answer.iso"):
        path = work / name
        path.write_bytes(b"owned-synthetic-only")
        files.append(path)
    code = tmp_path / "code.fd"
    code.write_bytes(b"synthetic-firmware")
    return work, code, *files


def drive(monkeypatch, lab, *, mode="success", stderr=b"", seconds=0.04):
    work, code, vars_path, image, iso, answer = lab
    holder = {}

    class Process:
        pid = os.getpid()

        def __init__(self, args, **kwargs):
            assert args[0] == witness.QEMU
            assert kwargs["start_new_session"] is True
            assert kwargs["stdin"] == subprocess.DEVNULL
            assert kwargs["cwd"] == work
            assert "-net" in args and args[args.index("-net") + 1] == "none"
            assert "send-key" not in args
            kwargs["stdout"].write(stderr)
            kwargs["stdout"].flush()
            self.returncode = 19 if mode in ("early", "exit_after_socket") else None
            holder["process"] = self

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            if mode == "cleanup_fail":
                raise subprocess.TimeoutExpired(cmd="synthetic", timeout=timeout)
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

    class FakeChannel:
        def close(self):
            pass

    def fake_qmp(_path):
        if mode == "refused":
            raise ConnectionRefusedError()
        if mode in ("greeting", "version", "capabilities", "not_running"):
            raise BootRefusal(
                {
                    "greeting": "invalid_qmp_greeting",
                    "version": "invalid_qmp_version",
                    "capabilities": "qmp_command_refused_qmp_capabilities",
                    "not_running": "qemu_is_not_running",
                }[mode]
            )
        if mode == "exit_after_socket":
            holder["process"].returncode = 12
            raise BootRefusal("invalid_qmp_greeting")
        return FakeChannel()

    call_count = 0

    def socket_identity(_path, _work):
        nonlocal call_count
        call_count += 1
        if mode == "invalid" and call_count > 1:
            raise witness.StartupRefusal("QEMU_QMP_SOCKET_INVALID")
        if mode == "absent":
            return None
        if mode == "late" and call_count <= 3:
            return None
        if mode == "swapped":
            if call_count <= 2:
                return None if call_count == 1 else (1, 2)
            return (1, 3)
        return None if call_count == 1 else (1, 2)

    def guard_process(proc, _pidfd):
        if proc.poll() is not None:
            raise witness.StartupRefusal("QEMU_EARLY_EXIT")

    def guard_peer(_channel, _proc):
        if mode == "foreign":
            raise witness.StartupRefusal("QEMU_QMP_SOCKET_INVALID")

    def fake_supervise(*_args, **kwargs):
        assert kwargs["qmp_channel"] is not None
        assert callable(kwargs["process_guard"])
        kwargs["process_guard"]()
        return {"qmpSendKeyAcknowledged": True}

    birth_calls = 0

    def fake_birth_identity(_pid):
        nonlocal birth_calls
        birth_calls += 1
        if mode == "birth_drift" and birth_calls > 1:
            return os.getpid(), 101
        return os.getpid(), 100

    monkeypatch.setattr(witness, "_birth_identity", fake_birth_identity)
    monkeypatch.setattr(witness, "_witness", guard_process)
    monkeypatch.setattr(witness, "_peer", guard_peer)
    monkeypatch.setattr(witness, "_socket_identity", socket_identity)
    monkeypatch.setattr(witness, "Qmp", fake_qmp)
    monkeypatch.setattr(witness, "supervise", fake_supervise)
    if mode == "spawn":

        def spawn_fails(*_args, **_kwargs):
            raise OSError("private path must not appear in report")

        factory = spawn_fails
    else:
        factory = Process
    if mode == "cleanup_fail":

        def signal_fails(*_args, **_kwargs):
            raise OSError("refuse unsafe termination")

        monkeypatch.setattr(witness.signal, "pidfd_send_signal", signal_fails)
    else:

        def fake_pidfd_signal(_fd, sig):
            # No real process is signalled: only the simulated child exits.
            holder["process"].returncode = -sig

        monkeypatch.setattr(witness.signal, "pidfd_send_signal", fake_pidfd_signal)

    report = witness.run_lab(
        work,
        code,
        vars_path,
        image,
        iso,
        answer,
        "kvm",
        popen_factory=factory,
        pidfd_factory=lambda _pid: os.open(os.devnull, os.O_RDONLY),
        connect_seconds=0.2 if mode == "late" else seconds,
        prompt_seconds=0.02,
        progress_seconds=0.02,
        wait_seconds=0.02,
    )
    assert report["installationAuthorized"] is False
    assert report["diskWritesAuthorized"] is False
    assert report["rollbackVerified"] is False
    assert report["windowsSetupVerified"] is False
    assert "private" not in repr(report)
    return report


@pytest.mark.parametrize(
    ("scenario", "reason"),
    [
        ("spawn", "QEMU_SPAWN_FAILED"),
        ("early", "QEMU_EARLY_EXIT"),
        ("absent", "QEMU_QMP_SOCKET_TIMEOUT"),
        ("invalid", "QEMU_QMP_SOCKET_INVALID"),
        ("refused", "QEMU_QMP_CONNECTION_REFUSED"),
        ("greeting", "QEMU_QMP_HANDSHAKE_FAILED"),
        ("version", "QEMU_QMP_HANDSHAKE_FAILED"),
        ("capabilities", "QEMU_QMP_HANDSHAKE_FAILED"),
        ("not_running", "QEMU_QMP_NOT_RUNNING"),
        ("exit_after_socket", "QEMU_EARLY_EXIT"),
        ("swapped", "QEMU_QMP_SOCKET_INVALID"),
        ("foreign", "QEMU_QMP_SOCKET_INVALID"),
        ("cleanup_fail", "QEMU_PROCESS_CLEANUP_FAILED"),
        ("birth_drift", "QEMU_PROCESS_CLEANUP_FAILED"),
    ],
)
def test_bounded_failure_codes(monkeypatch, lab, scenario, reason):
    report = drive(monkeypatch, lab, mode=scenario)
    assert report["decision"] == "refuse"
    assert report["reasonCode"] == reason
    if scenario in ("cleanup_fail", "birth_drift"):
        assert report["cleanupVerified"] is False
    else:
        assert report["cleanupVerified"] is True


@pytest.mark.parametrize(
    ("private_log", "detail"),
    [
        (b"qemu: failed to initialize kvm", "QEMU_KVM_INITIALIZATION_FAILED"),
        (b"qemu: cannot allocate memory", "QEMU_HOST_MEMORY_UNAVAILABLE"),
        (b"qemu: Bus 'sata.0' not found", "QEMU_SATA_BUS_NOT_FOUND"),
        (b"qemu: Property 'pflash.foo' not found", "QEMU_DEVICE_OPTION_UNSUPPORTED"),
        (b"qemu: Could not open /tmp/private: permission denied", "QEMU_FILE_ACCESS_DENIED"),
        (b"secret=/tmp/unknown and token=ab", "QEMU_EARLY_EXIT_UNCLASSIFIED"),
    ],
)
def test_early_exit_has_only_allowlisted_details(monkeypatch, lab, private_log, detail):
    result = drive(monkeypatch, lab, mode="early", stderr=private_log)
    assert result["reasonCode"] == "QEMU_EARLY_EXIT"
    assert result["errorDetailCode"] == detail
    assert "/tmp/" not in repr(result) and "token=" not in repr(result)


@pytest.mark.parametrize("scenario", ["late", "success"])
def test_late_socket_and_connected_process(monkeypatch, lab, scenario):
    result = drive(monkeypatch, lab, mode=scenario)
    assert result["decision"] == "dvd_key_sent_once"
    assert result["reasonCode"] is None
    assert result["qmpHandshakeVerified"] is True
    assert result["cleanupVerified"] is True


def test_socket_symlink_and_non_socket_rejected_before_any_qmp(tmp_path):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    target = root / "target"
    target.write_bytes(b"not-socket")
    path = root / "qmp.sock"
    path.symlink_to(target)
    with pytest.raises(witness.StartupRefusal, match="QEMU_QMP_SOCKET_INVALID"):
        witness._socket_identity(path, root)
    path.unlink()
    path.write_bytes(b"still-not-socket")
    with pytest.raises(witness.StartupRefusal, match="QEMU_QMP_SOCKET_INVALID"):
        witness._socket_identity(path, root)


def test_pid_mismatch_in_connected_socket_is_refused():
    class Socket:
        def getsockopt(self, *_args):
            import struct

            return struct.pack("3i", os.getpid(), os.getuid(), os.getgid())

    class Channel:
        socket = Socket()

    class Foreign:
        pid = os.getpid() + 101

    with pytest.raises(witness.StartupRefusal, match="QEMU_QMP_SOCKET_INVALID"):
        witness._peer(Channel(), Foreign())


def test_workflow_never_triggers_windows_on_push():
    root = Path(__file__).resolve().parents[2]
    target = root / ".github/workflows/gaslux-q4os-windows10-qcow2.yml"
    text = target.read_text(encoding="utf-8")
    assert "\n  workflow_dispatch:\n" in text
    assert "\n  push:\n" not in text
    assert "q4os_win10_qmp_supervisor.py" in text
    assert "timeout --signal=TERM --kill-after=60s" not in text
    assert "qemu_pid=$!" not in text


def test_kvm_and_tcg_machine_graph_and_wait_budgets(lab):
    work, code, vars_path, image, iso, answer = lab
    kvm = witness._qemu_args(work, code, vars_path, image, iso, answer, "kvm")
    tcg = witness._qemu_args(work, code, vars_path, image, iso, answer, "tcg")
    assert kvm[kvm.index("-accel") + 1] == "kvm"
    assert kvm[kvm.index("-cpu") + 1] == "host"
    assert tcg[tcg.index("-accel") + 1] == "tcg,thread=multi"
    assert tcg[tcg.index("-cpu") + 1] == "max"
    assert kvm[kvm.index("-m") + 1] == tcg[tcg.index("-m") + 1] == "6144"
    source = (
        Path(__file__).resolve().parents[2] / "auto_tests/tools/q4os_win10_qmp_supervisor.py"
    ).read_text()
    assert 'wait_seconds=14400 if args.accel == "tcg" else 7200' in source
