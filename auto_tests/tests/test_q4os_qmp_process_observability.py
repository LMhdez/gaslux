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
        def negotiate_protocol(self):
            pass

        def close(self):
            pass

    def fake_qmp(_path, *, negotiate=False):
        assert negotiate is False
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
        if mode == "poisoned_reason":
            raise BootRefusal("QEMU_SECRET_key=/tmp/should-not-appear")
        if mode == "suffix_reason":
            raise BootRefusal("QEMU_EARLY_EXIT SECRET=/tmp/private")
        if mode == "valid_reason":
            raise BootRefusal("QEMU_QMP_SOCKET_INVALID")
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
    assert "SECRET" not in repr(report)
    assert "key=" not in repr(report)
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
        ("poisoned_reason", "QEMU_STARTUP_UNCLASSIFIED"),
        ("suffix_reason", "QEMU_STARTUP_UNCLASSIFIED"),
        ("valid_reason", "QEMU_QMP_SOCKET_INVALID"),
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


def test_real_foreign_same_uid_qmp_peer_receives_zero_commands(tmp_path, monkeypatch):
    """Real Unix socket and two real Python PIDs, no QEMU/installer."""
    import time

    work = tmp_path / "private"
    work.mkdir(mode=0o700)
    sock = work / "qmp.sock"
    transcript = work / "received.bin"
    server_script = """
import socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.bind(sys.argv[1]);s.listen(1)
c,_=s.accept();c.settimeout(2)
c.sendall(b'{"QMP":{"version":{}}}\\r\\n')
try:
    result=c.recv(512)
except (OSError, TimeoutError):
    result=b''
open(sys.argv[2],'wb').write(result)
c.close();s.close()
"""
    monitor = subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(15)"],
        start_new_session=True,
    )
    server = subprocess.Popen(
        [sys.executable, "-u", "-c", server_script, str(sock), str(transcript)],
        start_new_session=True,
    )
    fd = None
    try:
        deadline = time.monotonic() + 3
        while not sock.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert sock.exists()
        fd = os.pidfd_open(monitor.pid)
        monkeypatch.setattr(
            witness,
            "_witness",
            lambda proc, _fd: (
                None if proc.poll() is None else (_ for _ in ()).throw(
                    witness.StartupRefusal("QEMU_EARLY_EXIT")
                )
            ),
        )
        report = {"qmpSocketState": "ABSENT", "qmpHandshakeVerified": False}
        with pytest.raises(witness.StartupRefusal, match="QEMU_QMP_SOCKET_INVALID"):
            witness._await_qmp(
                monitor, fd, sock, work, report, seconds=0.5, interval=0.01,
            )
        assert server.wait(timeout=5) == 0
        assert transcript.read_bytes() == b"", "peer must receive ZERO QMP commands"
        assert report["qmpHandshakeVerified"] is False
    finally:
        if fd is not None:
            os.close(fd)
        for child in (monitor, server):
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)


@pytest.mark.parametrize("fault,errno_value", [("flush", 28), ("close", 5)])
def test_real_python_child_reaped_despite_report_io_fault(
    monkeypatch, lab, fault, errno_value
):
    """ENOSPC/EIO on supervisor-owned logfile may not bypass wait/reap."""

    holder = {}
    native_open = Path.open

    class FaultyOutput:
        def __init__(self, stream):
            self.stream = stream

        def fileno(self):
            return self.stream.fileno()

        def flush(self):
            if fault == "flush":
                raise OSError(errno_value, "synthetic logfile failure")
            return self.stream.flush()

        def close(self):
            self.stream.close()
            if fault == "close":
                raise OSError(errno_value, "synthetic logfile close failure")

    def fault_open(path, mode="r", *args, **kwargs):
        result = native_open(path, mode, *args, **kwargs)
        if path.name == "windows10-qemu-process.log" and mode == "xb":
            return FaultyOutput(result)
        return result

    def start_python(_qemu_args, **kwargs):
        assert all(x != "/usr/bin/qemu-system-x86_64" for x in [
            sys.executable,
        ])
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time;time.sleep(30)"],
            **kwargs,
        )
        holder["child"] = proc
        return proc

    monkeypatch.setattr(Path, "open", fault_open)
    monkeypatch.setattr(witness, "_witness", lambda *_args: None)
    work, code, vars_path, image, iso, answer = lab
    report = witness.run_lab(
        work, code, vars_path, image, iso, answer, "kvm",
        popen_factory=start_python, connect_seconds=0.03,
    )
    child = holder["child"]
    assert report["reportIoFailed"] is True
    assert report["decision"] == "refuse"
    assert report["cleanupVerified"] is True
    assert report["descendantsCleanupVerified"] is False
    assert report["reasonCode"] == "QEMU_QMP_SOCKET_TIMEOUT"
    assert child.poll() is not None
    assert child.wait(timeout=1) == child.returncode


def test_symlink_swap_after_initial_validation_refused_before_spawn(
    monkeypatch, lab, tmp_path
):
    """O_NOFOLLOW + fstat detects TOCTOU, without opening foreign media."""
    work, code, vars_path, image, iso, answer = lab
    foreign = tmp_path / "foreign-synthetic"
    foreign.write_bytes(b"FOREIGN-DATA")
    original = witness._pin_file
    seen = {"spawn": False, "swap": False}

    def pin_then_swap(path, expected, **kwargs):
        if path == image and not seen["swap"]:
            image.unlink()
            image.symlink_to(foreign)
            seen["swap"] = True
        return original(path, expected, **kwargs)

    def forbidden_spawn(*_args, **_kwargs):
        seen["spawn"] = True
        raise AssertionError("no spawn after inode/symlink mismatch")

    monkeypatch.setattr(witness, "_pin_file", pin_then_swap)
    report = witness.run_lab(
        work, code, vars_path, image, iso, answer, "kvm",
        popen_factory=forbidden_spawn,
    )
    assert report["decision"] == "refuse"
    assert seen == {"spawn": False, "swap": True}
    assert foreign.read_bytes() == b"FOREIGN-DATA"
    assert report["diskWritesAuthorized"] is False


def test_pinned_fd_remains_on_original_inode_after_path_swap(monkeypatch, lab, tmp_path):
    """The old synthetic file is pinned even when its path is replaced."""
    work, code, vars_path, image, iso, answer = lab
    foreign = tmp_path / "foreign-synthetic"
    foreign.write_bytes(b"PROTECTED-CONTENT")
    original = image.read_bytes()
    called = {"spawn": False}

    class FakeProcess:
        pid = os.getpid()

        def __init__(self, args, **kwargs):
            called["spawn"] = True
            media = args[args.index("-drive") + 1]
            assert "/proc/self/fd/" in media
            assert "disk.qcow2" not in " ".join(args)
            assert len(kwargs["pass_fds"]) == 5
            image.rename(work / "original-owned-image")
            image.symlink_to(foreign)
            pinned_fd = next(
                fd for fd in kwargs["pass_fds"]
                if os.fstat(fd).st_ino == (work / "original-owned-image").stat().st_ino
            )
            os.lseek(pinned_fd, 0, os.SEEK_SET)
            os.write(pinned_fd, b"OWNED-FD")
            self.returncode = None

        def poll(self):
            return self.returncode

        def wait(self, _timeout):
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

    def fake_signal(_fd, sig):
        assert sig == 15
        # The fake child is not an OS process; signalling remains mocked.
        fake.returncode = -sig

    fake = None

    def spawn(args, **kwargs):
        nonlocal fake
        fake = FakeProcess(args, **kwargs)
        return fake

    monkeypatch.setattr(witness, "_birth_identity", lambda *_args: (1, 2))
    monkeypatch.setattr(witness, "_witness", lambda *_args: None)
    monkeypatch.setattr(witness.signal, "pidfd_send_signal", fake_signal)
    report = witness.run_lab(
        work, code, vars_path, image, iso, answer, "kvm",
        popen_factory=spawn,
        pidfd_factory=lambda _pid: os.open(os.devnull, os.O_RDONLY),
        connect_seconds=0.02,
    )
    assert called["spawn"]
    assert foreign.read_bytes() == b"PROTECTED-CONTENT"
    assert (work / "original-owned-image").read_bytes().startswith(b"OWNED-FD")
    assert original != (work / "original-owned-image").read_bytes()
    assert report["decision"] == "refuse"


def test_unproven_qemu_backing_contract_blocks_real_spawn(monkeypatch, lab):
    """When real QEMU FD compatibility is not established, no Popen may occur."""
    work, code, vars_path, image, iso, answer = lab
    assert witness.QEMU_FD_BACKING_VERIFIED is False

    def never_popen(*_args, **_kwargs):
        raise AssertionError("QEMU spawn must be disabled")

    monkeypatch.setattr(witness.subprocess, "Popen", never_popen)
    result = witness.run_lab(work, code, vars_path, image, iso, answer, "kvm")
    assert result["reasonCode"] == "QEMU_STARTUP_UNCLASSIFIED"
    assert result["qemuSpawned"] is False


@pytest.mark.parametrize(
    "malicious", [
        "QEMU_",
        "QEMU_QMP_SOCKET_INVALID_token=/tmp/private",
        "QEMU_SECRET=confidential",
        "QEMU_EARLY_EXIT;password=fake",
    ],
)
def test_strict_reason_code_allowlist_never_exposes_tokens(malicious):
    reason = witness.StartupRefusal(malicious)
    assert reason.code == "QEMU_STARTUP_UNCLASSIFIED"
    assert "private" not in str(reason)
    assert "confidential" not in str(reason)
    assert "password" not in str(reason)
