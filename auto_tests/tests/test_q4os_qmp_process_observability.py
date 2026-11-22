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

        def __init__(self):
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
        def bind_verified_session(self, session):
            self.session = session

        def negotiate_protocol(self):
            self.session.verify()

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
        assert type(kwargs["qmp_session"]) is witness._BoundQmpSession
        kwargs["qmp_session"].verify()
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
    # This is a protocol simulation, not an issued operational QMP authority.
    monkeypatch.setattr(witness, "_verify_session_authority", lambda _session: None)
    monkeypatch.setattr(witness, "_peer", guard_peer)
    monkeypatch.setattr(witness, "_socket_identity", socket_identity)
    monkeypatch.setattr(witness, "Qmp", fake_qmp)
    monkeypatch.setattr(witness, "supervise", fake_supervise)
    child = None if mode == "spawn" else Process()
    if mode == "cleanup_fail":

        def signal_fails(*_args, **_kwargs):
            raise OSError("refuse unsafe termination")

        monkeypatch.setattr(witness.signal, "pidfd_send_signal", signal_fails)
    else:

        def fake_pidfd_signal(_fd, sig):
            # No real process is signalled: only the simulated child exits.
            holder["process"].returncode = -sig

        monkeypatch.setattr(witness.signal, "pidfd_send_signal", fake_pidfd_signal)

    report = witness._run_lab_synthetic(
        work,
        code,
        vars_path,
        image,
        iso,
        answer,
        "kvm",
        synthetic_child=child,
        synthetic_spawn_failure=mode == "spawn",
        synthetic_log_data=stderr,
        # Simulated signal delivery is mocked above. Use a genuine live pidfd
        # matching the simulated process PID; never a foreign /dev/null FD.
        pidfd_factory=(None if mode == "spawn" else lambda _pid: os.pidfd_open(os.getpid())),
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
        ("absent", "QEMU_STARTUP_UNCLASSIFIED"),
        ("invalid", "QEMU_STARTUP_UNCLASSIFIED"),
        ("refused", "QEMU_STARTUP_UNCLASSIFIED"),
        ("greeting", "QEMU_STARTUP_UNCLASSIFIED"),
        ("version", "QEMU_STARTUP_UNCLASSIFIED"),
        ("capabilities", "QEMU_STARTUP_UNCLASSIFIED"),
        ("not_running", "QEMU_STARTUP_UNCLASSIFIED"),
        ("exit_after_socket", "QEMU_EARLY_EXIT"),
        ("swapped", "QEMU_STARTUP_UNCLASSIFIED"),
        ("foreign", "QEMU_STARTUP_UNCLASSIFIED"),
        ("cleanup_fail", "QEMU_PROCESS_CLEANUP_FAILED"),
        ("birth_drift", "QEMU_PROCESS_CLEANUP_FAILED"),
        ("poisoned_reason", "QEMU_STARTUP_UNCLASSIFIED"),
        ("suffix_reason", "QEMU_STARTUP_UNCLASSIFIED"),
        ("valid_reason", "QEMU_STARTUP_UNCLASSIFIED"),
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
def test_synthetic_qmp_never_reports_operational_success(monkeypatch, lab, scenario):
    result = drive(monkeypatch, lab, mode=scenario)
    assert result["decision"] == "refuse"
    assert result["reasonCode"] == "QEMU_STARTUP_UNCLASSIFIED"
    assert result["qemuSpawned"] is False
    assert result["qemuPidRecorded"] is False
    assert result["qmpSocketState"] == "ABSENT"
    assert result["qmpHandshakeVerified"] is False
    assert result["qmpSendKeyAcknowledged"] is False
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
    fd_owners = {"code": 50, "vars": 51, "image": 52, "iso": 53, "answer": 54}
    kvm = witness._qemu_args(work, code, vars_path, image, iso, answer, "kvm", fd_owners)
    tcg = witness._qemu_args(work, code, vars_path, image, iso, answer, "tcg", fd_owners)
    assert "/proc/self/fd/52" in " ".join(kvm)
    assert "disk.qcow2" not in " ".join(kvm)
    assert "win.iso" not in " ".join(kvm)
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
# Deliberately send no greeting: the supervisor must reject by SO_PEERCRED
# without requiring a protocol response or transmitting QMP commands.
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
        # This separate test exercises SO_PEERCRED with a simulated
        # supervisor. It must not manufacture operational QMP authority.
        monkeypatch.setattr(witness, "_verify_session_authority", lambda _session: None)
        monkeypatch.setattr(
            witness,
            "_witness",
            lambda proc, _fd: (
                None
                if proc.poll() is None
                else (_ for _ in ()).throw(witness.StartupRefusal("QEMU_EARLY_EXIT"))
            ),
        )
        from q4os_win10_qmp_boot import Qmp

        channel = Qmp(sock, negotiate=False)
        try:
            with pytest.raises(witness.StartupRefusal, match="QEMU_QMP_SOCKET_INVALID"):
                witness._peer(channel, monitor)
        finally:
            channel.close()
        assert server.wait(timeout=5) == 0
        assert transcript.read_bytes() == b"", "peer must receive ZERO QMP commands"
    finally:
        if fd is not None:
            os.close(fd)
        for child in (monitor, server):
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)


@pytest.mark.parametrize("fault,errno_value", [("flush", 28), ("close", 5)])
def test_real_python_child_reaped_despite_report_io_fault(monkeypatch, lab, fault, errno_value):
    """ENOSPC/EIO on supervisor-owned logfile may not bypass wait/reap."""

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

    monkeypatch.setattr(Path, "open", fault_open)
    monkeypatch.setattr(witness, "_witness", lambda *_args: None)
    work, code, vars_path, image, iso, answer = lab
    # The test itself creates a real, disposable Python child. Gaslux core
    # never receives or invokes an executable/factory, only an existing PID.
    child = subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(30)"],
        cwd=work,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        report = witness._run_lab_synthetic(
            work,
            code,
            vars_path,
            image,
            iso,
            answer,
            "kvm",
            synthetic_child=child,
            connect_seconds=0.03,
        )
    finally:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=5)
    assert report["reportIoFailed"] is True
    assert report["decision"] == "refuse"
    assert report["cleanupVerified"] is True
    assert report["descendantsCleanupVerified"] is False
    # A synthetic child must be denied before opening QMP, even when the
    # report flush or close fails; cleanup still reaps the real test child.
    assert report["reasonCode"] == "QEMU_STARTUP_UNCLASSIFIED"
    assert child.poll() is not None
    assert child.wait(timeout=1) == child.returncode


def test_symlink_swap_after_initial_validation_refused_before_spawn(monkeypatch, lab, tmp_path):
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

    monkeypatch.setattr(witness, "_pin_file", pin_then_swap)
    report = witness._run_lab_synthetic(
        work,
        code,
        vars_path,
        image,
        iso,
        answer,
        "kvm",
        synthetic_child=object(),
    )
    assert report["decision"] == "refuse"
    assert seen["swap"] is True
    assert report["qemuSpawned"] is False
    assert foreign.read_bytes() == b"FOREIGN-DATA"
    assert report["diskWritesAuthorized"] is False


def test_pinned_fd_remains_on_original_inode_after_path_swap(monkeypatch, lab, tmp_path):
    """Pinned inode write never follows an attacker-swapped synthetic path."""
    work, _code, _vars_path, image, _iso, _answer = lab
    foreign = tmp_path / "foreign-synthetic"
    foreign.write_bytes(b"PROTECTED-CONTENT")
    old_bytes = image.read_bytes()
    fd = witness._pin_file(image, image.lstat(), writable=True)
    try:
        image.rename(work / "original-owned-image")
        image.symlink_to(foreign)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, b"OWNED-FD")
        assert foreign.read_bytes() == b"PROTECTED-CONTENT"
        assert (work / "original-owned-image").read_bytes().startswith(b"OWNED-FD")
        assert old_bytes != (work / "original-owned-image").read_bytes()
    finally:
        os.close(fd)


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
    "malicious",
    [
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


# R-01 / R-02 / R-03: committed as RED regressions before implementation.
def test_r01_autonomous_boot_rejected_before_opening_qmp(monkeypatch, tmp_path):
    import q4os_win10_qmp_boot as boot

    work = tmp_path / "owned"
    work.mkdir(mode=0o700)
    disk = work / "synthetic.qcow2"
    disk.write_bytes(b"synthetic")
    serial = work / "serial.log"
    serial.write_bytes(b"Press any key to boot from CD or DVD")
    events = []

    def forbidden_qmp(*_args, **_kwargs):
        events.append("qmp-open")
        raise AssertionError("autonomous connection forbidden")

    monkeypatch.setattr(boot, "Qmp", forbidden_qmp)
    with pytest.raises(boot.BootRefusal):
        boot.supervise(work / "qmp.sock", serial, disk, connect_seconds=0.02)
    assert events == []


def test_r01_foreign_injected_channel_and_no_guard_rejected(monkeypatch, tmp_path):
    import q4os_win10_qmp_boot as boot

    work = tmp_path / "owned"
    work.mkdir(mode=0o700)
    disk = work / "synthetic.qcow2"
    disk.write_bytes(b"synthetic")
    serial = work / "serial.log"
    serial.write_bytes(b"Press any key to boot from CD or DVD")
    events = []

    class ForeignQmp:
        def send_key_once(self):
            events.append("send-key")

        def close(self):
            pass

    with pytest.raises(boot.BootRefusal):
        boot.supervise(
            work / "qmp.sock",
            serial,
            disk,
            qmp_channel=ForeignQmp(),
            process_guard=lambda: None,
            prompt_seconds=0.02,
        )
    assert events == []


def test_r02_arbitrary_factory_never_runs_under_closed_gate(lab):
    work, code, vars_path, image, iso, answer = lab
    effects = []

    def malicious_factory(*_args, **_kwargs):
        effects.append("SPAWNED")
        raise OSError("secret=/tmp/private")

    assert witness.QEMU_FD_BACKING_VERIFIED is False
    result = witness.run_lab(
        work,
        code,
        vars_path,
        image,
        iso,
        answer,
        "kvm",
        popen_factory=malicious_factory,
        connect_seconds=0.02,
    )
    assert effects == []
    assert result["qemuSpawned"] is False
    assert result["reasonCode"] == "QEMU_STARTUP_UNCLASSIFIED"


@pytest.mark.parametrize(
    "secret",
    [
        "QEMU_TOKEN=SECRET_SENTINEL",
        "QEMU_EARLY_EXIT SECRET_SENTINEL",
        "QEMU_",
        "",
        "日本語🚫SECRET_SENTINEL",
    ],
)
def test_r03_legacy_cli_never_leaks_arbitrary_boot_reason(monkeypatch, tmp_path, capsys, secret):
    import q4os_win10_qmp_boot as boot

    root = tmp_path / "owned"
    root.mkdir(mode=0o700)
    report_path = root / "report.json"
    monkeypatch.setattr(
        boot,
        "supervise",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(boot.BootRefusal(secret)),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "q4os_win10_qmp_boot.py",
            "--qmp",
            str(root / "qmp.sock"),
            "--serial",
            str(root / "serial"),
            "--disk",
            str(root / "disk"),
            "--report",
            str(report_path),
        ],
    )
    assert boot.main() == 1
    result = report_path.read_text()
    output = capsys.readouterr().out
    assert "SECRET_SENTINEL" not in result + output
    assert "reason" in result
    assert "QEMU_TOKEN" not in result


def test_r01_lowlevel_qmp_has_no_unbound_command_path(tmp_path):
    """Real AF_UNIX socket, zero bytes before and after a forged guard."""
    import socket

    from q4os_win10_qmp_boot import Qmp

    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    sockpath = root / "qmp.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sockpath))
    server.listen(1)
    qmp = Qmp(sockpath, negotiate=False)
    accepted, _ = server.accept()

    class Forged:
        channel = qmp

        def verify(self):
            return None

    try:
        for operation in (
            lambda: qmp.command("qmp_capabilities", "untrusted"),
            qmp.negotiate_protocol,
            qmp.send_key_once,
        ):
            with pytest.raises(BootRefusal, match="qmp_supervisor_required"):
                operation()
        qmp._bound_session = Forged()  # adversarial direct attribute mutation
        with pytest.raises(BootRefusal, match="qmp_supervisor_required"):
            qmp.send_key_once()
        accepted.settimeout(0.1)
        with pytest.raises(socket.timeout):
            accepted.recv(1)
    finally:
        qmp.close()
        accepted.close()
        server.close()


@pytest.mark.parametrize("factory", [subprocess.Popen, lambda *_a, **_k: object()])
def test_r02_public_factory_is_not_spawn_authority(lab, factory):
    work, code, vars_path, image, iso, answer = lab
    before = set(work.iterdir())
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
    )
    assert report["decision"] == "refuse"
    assert report["qemuSpawned"] is False
    assert before == set(work.iterdir())


def test_r02_direct_internal_core_without_child_has_no_spawn(monkeypatch, lab):
    work, code, vars_path, image, iso, answer = lab
    events = []

    def forbidden(*_args, **_kwargs):
        events.append("spawn")
        raise AssertionError("never start process when contract is unverified")

    monkeypatch.setattr(witness.subprocess, "Popen", forbidden)
    report = witness._run_lab_impl(
        work,
        code,
        vars_path,
        image,
        iso,
        answer,
        "kvm",
    )
    assert report["qemuSpawned"] is False
    assert report["decision"] == "refuse"
    assert events == []


def test_r02_public_cli_refuses_without_spawn_even_with_host_claims(monkeypatch, tmp_path):
    import json

    run_id = "987654"
    work = tmp_path / ("gaslux-win10-" + run_id)
    work.mkdir(mode=0o700)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    monkeypatch.setenv("GITHUB_REPOSITORY", "LMhdez/gaslux")
    monkeypatch.setenv("RUNNER_OS", "Linux")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_RUN_ID", run_id)
    events = []

    def forbidden(*_args, **_kwargs):
        events.append("spawn")
        raise AssertionError("CLI cannot launch any process")

    monkeypatch.setattr(witness.subprocess, "Popen", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "q4os_win10_qmp_supervisor.py",
            "--work",
            str(work),
            "--code",
            str(tmp_path / "synthetic-code"),
            "--vars",
            str(work / "vars.fd"),
            "--image",
            str(work / "disk.qcow2"),
            "--iso",
            str(work / "synthetic.iso"),
            "--answer",
            str(work / "answer.iso"),
            "--accel",
            "tcg",
        ],
    )
    assert witness.main() == 1
    report = json.loads((work / "q4os-win10-uefi-dvd-boot.json").read_text())
    assert report["reasonCode"] == "QEMU_STARTUP_UNCLASSIFIED"
    assert report["qemuSpawned"] is False
    assert events == []


def test_r03_unexpected_exception_stays_redacted_in_legacy_cli(monkeypatch, tmp_path, capsys):
    import q4os_win10_qmp_boot as boot

    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    report = root / "report.json"

    def unexpected(*_args, **_kwargs):
        raise RuntimeError("SECRET_SENTINEL /tmp/private password")

    monkeypatch.setattr(boot, "supervise", unexpected)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "q4os_win10_qmp_boot.py",
            "--qmp",
            str(root / "qmp.sock"),
            "--serial",
            str(root / "serial.log"),
            "--disk",
            str(root / "synthetic.qcow2"),
            "--report",
            str(report),
        ],
    )
    assert boot.main() == 1
    assert '"QEMU_STARTUP_UNCLASSIFIED"' in report.read_text()
    assert "SECRET_SENTINEL" not in report.read_text() + capsys.readouterr().out


# R-01 residual: execute actual supervisor and Qmp modules with genuine
# kernel pidfds and same-UID UNIX peers. No QEMU or Windows is started.
@pytest.mark.parametrize(
    "scenario",
    [
        "regular_fd",
        "other_child_pidfd",
        "fabricated_process",
        "direct_session",
        "send_key_foreign",
    ],
)
def test_r01_pidfd_provenance_and_unsupervised_session_denied(monkeypatch, tmp_path, scenario):
    import time

    from q4os_win10_qmp_boot import Qmp

    work = tmp_path / "private"
    work.mkdir(mode=0o700)
    sock = work / "qmp.sock"
    record = work / "received.bin"
    server_code = """
import socket,sys
from pathlib import Path
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1]);s.listen(1)
c,_=s.accept();c.settimeout(0.6)
try:
    data=c.recv(4096)
except (TimeoutError, OSError):
    data=b''
Path(sys.argv[2]).write_bytes(data)
c.close();s.close()
"""
    server = subprocess.Popen(
        [sys.executable, "-u", "-c", server_code, str(sock), str(record)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    other = subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(8)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    fd = None
    qmp = None
    monkeypatch.setattr(witness, "QEMU", sys.executable)
    try:
        deadline = time.monotonic() + 3
        while not sock.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert sock.exists()
        if scenario == "regular_fd":
            fd = os.open(os.devnull, os.O_RDONLY)
        elif scenario == "other_child_pidfd":
            fd = os.pidfd_open(other.pid)
        else:
            fd = os.pidfd_open(server.pid)

        class Fabricated:
            pid = server.pid

            def poll(self):
                return None

        process = Fabricated() if scenario in ("fabricated_process", "send_key_foreign") else server
        qmp = Qmp(sock, negotiate=False)
        session = witness._BoundQmpSession(
            qmp, process, fd, sock, work, witness._socket_identity(sock, work)
        )
        if scenario == "send_key_foreign":
            try:
                qmp.bind_verified_session(session)
                qmp.send_key_once()
            except (witness.StartupRefusal, BootRefusal, OSError, ValueError):
                pass
        else:
            with pytest.raises(
                (witness.StartupRefusal, BootRefusal),
                match="QEMU_STARTUP_UNCLASSIFIED|qmp_supervisor_required",
            ):
                session.verify()
    finally:
        if qmp is not None:
            qmp.close()
        if fd is not None:
            os.close(fd)
        # The server must finish its read and write a transcript before
        # asserting that no command arrived; an absent transcript is NOT proof.
        try:
            server.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server.terminate()
            server.wait(timeout=5)
        if other.poll() is None:
            other.terminate()
        other.wait(timeout=5)
    assert record.exists(), "must independently observe the UNIX peer transcript"
    assert record.read_bytes() == b"", "unauthorized peer received QMP bytes"


def test_r01_kernel_pidfd_binding_and_fd_substitution_real_children():
    """Actual Linux fdinfo, pidfd readiness, no QEMU, no mocked verifier."""
    first = subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(15)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    second = subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(15)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    first_fd = os.pidfd_open(first.pid)
    other_fd = os.pidfd_open(second.pid)
    regular_fd = os.open(os.devnull, os.O_RDONLY)
    try:
        assert witness.QEMU_FD_BACKING_VERIFIED is False
        assert witness._pidfd_target(first_fd, first.pid) is None
        with pytest.raises(witness.StartupRefusal, match="QEMU_STARTUP_UNCLASSIFIED"):
            witness._pidfd_target(regular_fd, first.pid)
        with pytest.raises(witness.StartupRefusal, match="QEMU_STARTUP_UNCLASSIFIED"):
            witness._pidfd_target(other_fd, first.pid)
        # Simulate fd-number reuse after the validated pidfd was closed.
        reused_fd = os.dup(regular_fd)
        os.dup2(reused_fd, first_fd)
        os.close(reused_fd)
        with pytest.raises(witness.StartupRefusal, match="QEMU_STARTUP_UNCLASSIFIED"):
            witness._pidfd_target(first_fd, first.pid)
        # Even an original genuine pidfd is no longer proof of a *live*
        # process after the corresponding child has exited.
        second.terminate()
        second.wait(timeout=5)
        with pytest.raises(witness.StartupRefusal):
            witness._pidfd_target(other_fd, second.pid)
        with pytest.raises(witness.StartupRefusal):
            witness._birth_identity(second.pid)
    finally:
        for fd in (first_fd, other_fd, regular_fd):
            os.close(fd)
        for child in (first, second):
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)


def test_r01_post_authentication_socket_swap_denies_send_key(monkeypatch, tmp_path):
    """OS socket peer and inode are rechecked after initially verified connect."""
    import socket

    from q4os_win10_qmp_boot import Qmp

    work = tmp_path / "private"
    work.mkdir(mode=0o700)
    sock = work / "qmp.sock"
    other = work / "foreign.sock"
    owned = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    foreign = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    owned.bind(str(sock))
    owned.listen(1)
    foreign.bind(str(other))
    foreign.listen(1)

    class SyntheticOwner:
        pid = os.getpid()

        def poll(self):
            return None

    qmp = None
    peer = None
    # Protocol-only instrumentation: test the real inode/SO_PEERCRED guards,
    # not authority issuance; no production gate is changed.
    monkeypatch.setattr(witness, "_verify_session_authority", lambda _session: None)
    monkeypatch.setattr(witness, "_witness", lambda *_args: None)
    try:
        original_inode = witness._socket_identity(sock, work)
        qmp = Qmp(sock, negotiate=False)
        peer, _ = owned.accept()
        session = witness._BoundQmpSession(qmp, SyntheticOwner(), -1, sock, work, original_inode)
        qmp.bind_verified_session(session)
        session.verify()
        sock.unlink()
        sock.symlink_to(other)
        with pytest.raises(witness.StartupRefusal, match="QEMU_QMP_SOCKET_INVALID"):
            qmp.send_key_once()
        peer.settimeout(0.1)
        with pytest.raises(socket.timeout):
            peer.recv(1)
    finally:
        if qmp is not None:
            qmp.close()
        if peer is not None:
            peer.close()
        owned.close()
        foreign.close()


def test_r02_fabricated_synthetic_child_never_claims_qemu_spawn(lab):
    work, code, vars_path, image, iso, answer = lab

    class Invented:
        pid = os.getpid()

        def poll(self):
            return 5

        def wait(self, timeout):
            return 5

    for runner in (witness._run_lab_synthetic, witness._run_lab_impl):
        # Fresh paths prevent synthetic log collisions between calls.
        for name in ("windows10-qemu-process.log",):
            (work / name).unlink(missing_ok=True)
        result = runner(
            work,
            code,
            vars_path,
            image,
            iso,
            answer,
            "kvm",
            synthetic_child=Invented(),
            connect_seconds=0.03,
        )
        assert result["qemuSpawned"] is False
        assert result["qemuPidRecorded"] is False
        assert result["qmpHandshakeVerified"] is False
        assert result["qmpSendKeyAcknowledged"] is False
        assert result["decision"] == "refuse"


@pytest.mark.parametrize("runner_name", ["_run_lab_impl", "_run_lab_synthetic"])
def test_r02_preexisting_python_child_cannot_reach_qmp(monkeypatch, lab, runner_name):
    work, code, vars_path, image, iso, answer = lab
    calls = []
    native = witness._await_qmp

    def forbidden_qmp(*args, **kwargs):
        calls.append("QMP_ATTEMPT")
        raise witness.StartupRefusal("QEMU_STARTUP_UNCLASSIFIED")

    monkeypatch.setattr(witness, "_await_qmp", forbidden_qmp)
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(20)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        report = getattr(witness, runner_name)(
            work,
            code,
            vars_path,
            image,
            iso,
            answer,
            "kvm",
            synthetic_child=child,
            connect_seconds=0.03,
        )
    finally:
        monkeypatch.setattr(witness, "_await_qmp", native)
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=5)
    assert witness.QEMU_FD_BACKING_VERIFIED is False
    assert calls == [], "synthetic child must not enter QMP transport"
    assert report["qemuSpawned"] is False
    assert report["qemuPidRecorded"] is False
    assert report["qmpHandshakeVerified"] is False
    assert report["qmpSendKeyAcknowledged"] is False
    assert report["installationAuthorized"] is False
    assert report["diskWritesAuthorized"] is False
    assert child.poll() is not None


def test_r03_dangling_symlink_report_is_bounded_refusal(monkeypatch, tmp_path, capsys):
    import q4os_win10_qmp_boot as boot

    work = tmp_path / "SECRET_SENTINEL_PRIVATE"
    work.mkdir(mode=0o700)
    report = work / "report.json"
    target = work / "missing-secret"
    report.symlink_to(target)
    monkeypatch.setattr(
        boot,
        "supervise",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            boot.BootRefusal("dvd_prompt_not_detected")
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "q4os_win10_qmp_boot.py",
            "--qmp",
            str(work / "qmp.sock"),
            "--serial",
            str(work / "serial.log"),
            "--disk",
            str(work / "disk.qcow2"),
            "--report",
            str(report),
        ],
    )
    assert boot.main() == 1
    output = capsys.readouterr()
    assert output.err == ""
    assert "SECRET_SENTINEL" not in output.out
    assert report.is_symlink()
    assert not target.exists()


@pytest.mark.parametrize("runner_name", ["_run_lab_impl", "_run_lab_synthetic"])
def test_r02_real_unix_socket_never_receives_synthetic_qmp(monkeypatch, lab, runner_name):
    """Existing Python child plus same-UID UNIX QMP server; zero commands."""
    import time

    work, code, vars_path, image, iso, answer = lab
    sock = work / "q4os-win10-qmp.sock"
    transcript = work / "qmp-bytes.bin"
    server_script = """
import socket,sys
from pathlib import Path
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.bind(sys.argv[1]);s.listen(1);s.settimeout(0.7)
data=b''
try:
    client,_=s.accept()
    client.settimeout(0.5)
    try:
        data=client.recv(4096)
    except (socket.timeout,OSError):
        pass
    client.close()
except socket.timeout:
    pass
Path(sys.argv[2]).write_bytes(data)
s.close()
"""
    sleeper = subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(15)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    owner = {}
    original_args = witness._qemu_args

    def args_after_preflight(*args, **kwargs):
        # The core's initial qmp-socket-absent check has completed.
        result = original_args(*args, **kwargs)
        owner["server"] = subprocess.Popen(
            [sys.executable, "-u", "-c", server_script, str(sock), str(transcript)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.monotonic() + 3
        while not sock.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert sock.exists()
        return result

    monkeypatch.setattr(witness, "_qemu_args", args_after_preflight)
    try:
        report = getattr(witness, runner_name)(
            work,
            code,
            vars_path,
            image,
            iso,
            answer,
            "kvm",
            synthetic_child=sleeper,
            connect_seconds=0.1,
        )
    finally:
        if sleeper.poll() is None:
            sleeper.terminate()
        sleeper.wait(timeout=5)
        if "server" in owner:
            child = owner["server"]
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.terminate()
                child.wait(timeout=5)
    assert witness.QEMU_FD_BACKING_VERIFIED is False
    assert transcript.exists(), "the synthetic peer must publish its observation"
    received = transcript.read_bytes()
    for command in (b"qmp_capabilities", b"query-status", b"send-key"):
        assert command not in received
    assert received == b"", "synthetic helper must not establish a QMP connection"
    assert report["decision"] == "refuse"
    assert report["qemuSpawned"] is False
    assert report["qemuPidRecorded"] is False
    assert report["qmpHandshakeVerified"] is False
    assert report["qmpSendKeyAcknowledged"] is False
    assert report["installationAuthorized"] is False
    assert report["diskWritesAuthorized"] is False
    assert sleeper.poll() is not None


def test_safety_cleanup_foreign_pidfd_never_signals_other_live_child():
    """RED against HEAD 1106085: foreign pidfd must never signal its owner."""
    a = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(1.0)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    b = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(20)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    foreign_fd = None
    try:
        assert a.poll() is None and b.poll() is None
        foreign_fd = os.pidfd_open(b.pid)
        assert witness._cleanup(a, foreign_fd) is False
        assert b.poll() is None, "foreign child B MUST NOT receive SIGTERM/SIGKILL"
    finally:
        if foreign_fd is not None:
            os.close(foreign_fd)
        for owned in (a, b):
            if owned.poll() is None:
                owned.terminate()
            owned.wait(timeout=5)


def test_safety_synthetic_foreign_pidfd_factory_has_zero_foreign_signals(lab):
    """The full synthetic entrypoint may refuse but must never harm B."""
    work, code, vars_path, image, iso, answer = lab
    a = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(1.0)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    b = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(20)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        assert a.poll() is None and b.poll() is None
        report = witness._run_lab_synthetic(
            work,
            code,
            vars_path,
            image,
            iso,
            answer,
            "tcg",
            synthetic_child=a,
            pidfd_factory=lambda _pid: os.pidfd_open(b.pid),
            connect_seconds=0.02,
        )
        assert report["decision"] == "refuse"
        assert report["qemuSpawned"] is False
        assert report["qmpSendKeyAcknowledged"] is False
        assert report["cleanupVerified"] is False
        assert b.poll() is None, "foreign pidfd must never terminate B"
    finally:
        for owned in (a, b):
            if owned.poll() is None:
                owned.terminate()
            owned.wait(timeout=5)


def test_safety_cleanup_matching_real_pidfd_reaps_owned_child():
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(20)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    pidfd = os.pidfd_open(child.pid)
    try:
        assert witness._cleanup(child, pidfd) is True
        assert child.poll() is not None
    finally:
        os.close(pidfd)
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=5)
