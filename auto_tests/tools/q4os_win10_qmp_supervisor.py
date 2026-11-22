#!/usr/bin/env python3
"""Fail-closed QEMU/QMP process witness. No executable installation authority.

The caller owns one direct Popen child and a Linux pidfd. Never signal an
unverified numeric PID. The report is an allowlisted diagnostic, not proof
of a trusted Windows host or permission to run an installation.
"""

from __future__ import annotations

import argparse
import json
import os
import select
import signal
import socket
import stat
import struct
import subprocess
import time
import weakref
from pathlib import Path

from q4os_win10_qemu_ovmf_preflight import classify_qemu_error
from q4os_win10_qmp_boot import BootRefusal, Qmp, supervise

QEMU = "/usr/bin/qemu-system-x86_64"
EARLY_EXIT_DETAIL = "QEMU_EARLY_EXIT_UNCLASSIFIED"
REASON_CODES = frozenset(
    {
        "QEMU_SPAWN_FAILED",
        "QEMU_EARLY_EXIT",
        "QEMU_QMP_SOCKET_TIMEOUT",
        "QEMU_QMP_SOCKET_INVALID",
        "QEMU_QMP_CONNECTION_REFUSED",
        "QEMU_QMP_HANDSHAKE_FAILED",
        "QEMU_QMP_NOT_RUNNING",
        "QEMU_PROCESS_CLEANUP_FAILED",
        "QEMU_STARTUP_UNCLASSIFIED",
    }
)
DETAIL_CODES = frozenset(
    {
        EARLY_EXIT_DETAIL,
        "QEMU_KVM_INITIALIZATION_FAILED",
        "QEMU_HOST_MEMORY_UNAVAILABLE",
        "QEMU_SATA_BUS_NOT_FOUND",
        "QEMU_DEVICE_OPTION_UNSUPPORTED",
        "QEMU_FILE_ACCESS_DENIED",
        "QEMU_MEDIA_OPEN_FAILED",
    }
)
# QEMU /proc/self/fd drive-argument compatibility has not been proven in a
# separately authorized VM test. Consequently the production spawn is blocked.
# The operational API never accepts a spawn factory as authority.
QEMU_FD_BACKING_VERIFIED = False

# Trusted in-process supervisor bookkeeping: neither a caller-provided Popen
# nor a bare pidfd creates a QMP authority. The operational path registers
# ONLY the real child returned by its own subprocess.Popen call.
# Python cannot defend these private objects from malicious code *already*
# executing inside this interpreter. The production gate remains false.
_OWNED_CHILDREN = weakref.WeakKeyDictionary()
_ISSUED_QMP_SESSIONS = weakref.WeakSet()


class StartupRefusal(RuntimeError):
    """One allowlisted diagnostic only."""

    def __init__(self, code: str):
        self.code = code if code in REASON_CODES else "QEMU_STARTUP_UNCLASSIFIED"
        super().__init__(self.code)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise StartupRefusal(code)


def _private_dir(work: Path) -> os.stat_result:
    _require(work.is_absolute() and not work.is_symlink(), "QEMU_STARTUP_UNCLASSIFIED")
    st = work.stat()
    _require(
        stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o077,
        "QEMU_STARTUP_UNCLASSIFIED",
    )
    return st


def _owned_file(path: Path, work: Path) -> os.stat_result:
    _require(path.parent == work and not path.is_symlink(), "QEMU_STARTUP_UNCLASSIFIED")
    st = path.lstat()
    _require(
        stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_nlink == 1,
        "QEMU_STARTUP_UNCLASSIFIED",
    )
    return st


def _pin_file(
    path: Path, expected: os.stat_result, *, dirfd: int | None = None, writable: bool = False
) -> int:
    """Pin the exact initially validated inode, refusing symlinks/hardlinks.

    The child later receives /proc/self/fd/N with pass_fds; no drive media path
    is re-opened by name. Compatibility with real QEMU remains NOT VERIFIED.
    """
    flags = (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path.name if dirfd is not None else path, flags, dir_fd=dirfd)
    except OSError:
        raise StartupRefusal("QEMU_STARTUP_UNCLASSIFIED") from None
    try:
        actual = os.fstat(fd)
        _require(
            stat.S_ISREG(actual.st_mode)
            and actual.st_uid == expected.st_uid
            and actual.st_uid in (0, os.getuid())
            and actual.st_nlink == 1
            and (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino),
            "QEMU_STARTUP_UNCLASSIFIED",
        )
        return fd
    except BaseException:
        os.close(fd)
        raise


def _socket_identity(path: Path, work: Path) -> tuple[int, int] | None:
    _require(path.parent == work, "QEMU_QMP_SOCKET_INVALID")
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None
    _require(
        stat.S_ISSOCK(st.st_mode) and st.st_uid == os.getuid() and st.st_nlink == 1,
        "QEMU_QMP_SOCKET_INVALID",
    )
    return st.st_dev, st.st_ino


def _birth_identity(pid: int) -> tuple[int, int]:
    """Require a live direct child and pin kernel start ticks before pidfd_open."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields = raw[raw.rfind(")") + 2 :].split()
        _require(len(fields) >= 20, "QEMU_STARTUP_UNCLASSIFIED")
        _require(fields[0] != "Z", "QEMU_EARLY_EXIT")
        parent_pid = int(fields[1])
        _require(parent_pid == os.getpid(), "QEMU_STARTUP_UNCLASSIFIED")
        return parent_pid, int(fields[19])
    except (OSError, ValueError, IndexError) as exc:
        raise StartupRefusal("QEMU_STARTUP_UNCLASSIFIED") from exc


def _pidfd_target(pidfd: int, pid: int) -> None:
    """Verify Linux kernel fdinfo and live pidfd, not a numeric FD claim."""
    _require(
        type(pidfd) is int and pidfd >= 0 and type(pid) is int and pid > 0,
        "QEMU_STARTUP_UNCLASSIFIED",
    )
    try:
        # A regular FD (including /dev/null) and a pidfd for another child
        # must fail before a QMP command, even if the fd number is recycled.
        _require(
            os.readlink(f"/proc/self/fd/{pidfd}") == "anon_inode:[pidfd]",
            "QEMU_STARTUP_UNCLASSIFIED",
        )
        info = Path(f"/proc/self/fdinfo/{pidfd}").read_text(encoding="ascii")
        target = [
            line.partition(":")[2].strip() for line in info.splitlines() if line.startswith("Pid:")
        ]
        _require(
            len(target) == 1 and int(target[0]) == pid,
            "QEMU_STARTUP_UNCLASSIFIED",
        )
        poll = select.poll()
        poll.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        _require(not poll.poll(0), "QEMU_EARLY_EXIT")
    except (OSError, ValueError, TypeError):
        raise StartupRefusal("QEMU_STARTUP_UNCLASSIFIED") from None


def _register_owned_child(process: subprocess.Popen, pidfd: int, birth: tuple[int, int]) -> None:
    """Only called after operational Popen and successful birth/pidfd checks."""
    _require(
        QEMU_FD_BACKING_VERIFIED and type(process) is subprocess.Popen,
        "QEMU_STARTUP_UNCLASSIFIED",
    )
    _require(process.poll() is None, "QEMU_EARLY_EXIT")
    _pidfd_target(pidfd, process.pid)
    _require(_birth_identity(process.pid) == birth, "QEMU_STARTUP_UNCLASSIFIED")
    _OWNED_CHILDREN[process] = (process.pid, pidfd, birth)


def _verify_session_authority(session: _BoundQmpSession) -> None:
    """Reject directly fabricated sessions and any detached/changed pidfd."""
    _require(
        QEMU_FD_BACKING_VERIFIED and session in _ISSUED_QMP_SESSIONS,
        "QEMU_STARTUP_UNCLASSIFIED",
    )
    process = session.process
    _require(type(process) is subprocess.Popen, "QEMU_STARTUP_UNCLASSIFIED")
    record = _OWNED_CHILDREN.get(process)
    _require(
        record is not None and record[0] == process.pid and record[1] == session.pidfd,
        "QEMU_STARTUP_UNCLASSIFIED",
    )
    _pidfd_target(session.pidfd, process.pid)
    _require(_birth_identity(process.pid) == record[2], "QEMU_STARTUP_UNCLASSIFIED")


def _witness(process: subprocess.Popen, pidfd: int) -> None:
    _require(type(process) is subprocess.Popen, "QEMU_STARTUP_UNCLASSIFIED")
    _require(process.pid > 0, "QEMU_STARTUP_UNCLASSIFIED")
    _require(process.poll() is None, "QEMU_EARLY_EXIT")
    _pidfd_target(pidfd, process.pid)
    # The birth identity and supervisor's own Popen registration are checked
    # separately, on *each* session command, before inspecting the socket.
    _require(os.path.samefile(f"/proc/{process.pid}/exe", QEMU), "QEMU_STARTUP_UNCLASSIFIED")


def _peer(channel: Qmp, process: subprocess.Popen) -> None:
    if not hasattr(socket, "SO_PEERCRED"):
        raise StartupRefusal("QEMU_QMP_HANDSHAKE_FAILED")
    raw = channel.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    pid, uid, _gid = struct.unpack("3i", raw)
    _require(pid == process.pid and uid == os.getuid(), "QEMU_QMP_SOCKET_INVALID")


class _BoundQmpSession:
    """Kernel-checked peer/process/inode witness; no caller-supplied guard.

    Every protocol action re-verifies the same child, pidfd and socket inode.
    A Python callback or mock QMP object alone is never an authorization.
    """

    def __init__(
        self,
        channel: Qmp,
        process: subprocess.Popen,
        pidfd: int,
        path: Path,
        work: Path,
        identity: tuple[int, int],
    ):
        self.channel = channel
        self.process = process
        self.pidfd = pidfd
        self.path = path
        self.work = work
        self.identity = identity

    def verify(self) -> None:
        _verify_session_authority(self)
        _witness(self.process, self.pidfd)
        _require(
            _socket_identity(self.path, self.work) == self.identity,
            "QEMU_QMP_SOCKET_INVALID",
        )
        _peer(self.channel, self.process)


def _await_qmp(
    process: subprocess.Popen,
    pidfd: int,
    path: Path,
    work: Path,
    report: dict,
    *,
    seconds: float = 15,
    interval: float = 0.05,
) -> _BoundQmpSession:
    # Neither a synthetic child nor a direct helper call can authorize guest
    # protocol input while operational QEMU FD backing remains unverified.
    _require(QEMU_FD_BACKING_VERIFIED, "QEMU_STARTUP_UNCLASSIFIED")
    deadline = time.monotonic() + seconds
    refused = False
    while time.monotonic() < deadline:
        _witness(process, pidfd)
        identity = _socket_identity(path, work)
        if identity is None:
            time.sleep(interval)
            continue
        report["qmpSocketState"] = "PRESENT"
        channel = None
        try:
            # Connect-only. No capabilities/query-status until the peer PID
            # and actual connected socket have been authenticated.
            channel = Qmp(path, negotiate=False)
            # No protocol bytes are allowed until the real kernel peer
            # and owned process have been authenticated.
            session = _BoundQmpSession(channel, process, pidfd, path, work, identity)
            _ISSUED_QMP_SESSIONS.add(session)
            session.verify()
            channel.bind_verified_session(session)
            channel.negotiate_protocol()
            session.verify()
            report["qmpSocketState"] = "CONNECTED"
            report["qmpHandshakeVerified"] = True
            report["qmpRunningVerified"] = True
            return session
        except ConnectionRefusedError:
            refused = True
            report["qmpSocketState"] = "CONNECTION_REFUSED"
        except BootRefusal as exc:
            if process.poll() is not None:
                raise StartupRefusal("QEMU_EARLY_EXIT") from None
            code = (
                "QEMU_QMP_NOT_RUNNING"
                if str(exc) == "qemu_is_not_running"
                else "QEMU_QMP_HANDSHAKE_FAILED"
            )
            raise StartupRefusal(code) from None
        except (OSError, ValueError, json.JSONDecodeError):
            if process.poll() is not None:
                raise StartupRefusal("QEMU_EARLY_EXIT") from None
            raise StartupRefusal("QEMU_QMP_HANDSHAKE_FAILED") from None
        finally:
            if channel is not None and not report["qmpHandshakeVerified"]:
                channel.close()
        time.sleep(interval)
    _witness(process, pidfd)
    if refused:
        raise StartupRefusal("QEMU_QMP_CONNECTION_REFUSED")
    raise StartupRefusal("QEMU_QMP_SOCKET_TIMEOUT")


def _qemu_args(
    work: Path,
    code: Path,
    vars_path: Path,
    image: Path,
    iso: Path,
    answer: Path,
    accelerator: str,
    pinned: dict[str, int],
) -> list[str]:
    _require(accelerator in ("kvm", "tcg"), "QEMU_STARTUP_UNCLASSIFIED")
    accel, cpu = ("kvm", "host") if accelerator == "kvm" else ("tcg,thread=multi", "max")

    def media(name: str) -> str:
        return f"/proc/self/fd/{pinned[name]}"

    return [
        QEMU,
        "-no-user-config",
        "-machine",
        "q35",
        "-accel",
        accel,
        "-cpu",
        cpu,
        "-smp",
        "4",
        "-m",
        "6144",
        "-rtc",
        "base=utc",
        "-display",
        "none",
        "-vga",
        "std",
        "-serial",
        "file:" + str(work / "windows10-qemu-serial.log"),
        "-monitor",
        "none",
        "-net",
        "none",
        "-qmp",
        "unix:" + str(work / "q4os-win10-qmp.sock") + ",server=on,wait=off",
        "-drive",
        "if=pflash,format=raw,unit=0,readonly=on,file=" + media("code"),
        "-drive",
        "if=pflash,format=raw,unit=1,file=" + media("vars"),
        "-device",
        "ich9-ahci,id=sata",
        "-drive",
        "if=none,id=system,file=" + media("image") + ",format=qcow2,cache=writeback",
        "-device",
        "ide-hd,drive=system,bus=sata.0,bootindex=2",
        "-drive",
        "if=none,id=install,file=" + media("iso") + ",format=raw,media=cdrom,readonly=on",
        "-device",
        "ide-cd,drive=install,bus=sata.1,bootindex=1",
        "-drive",
        "if=none,id=answer,file=" + media("answer") + ",format=raw,media=cdrom,readonly=on",
        "-device",
        "ide-cd,drive=answer,bus=sata.2,bootindex=3",
    ]


def _cleanup(process: subprocess.Popen | None, pidfd: int | None) -> bool:
    if process is None:
        return True
    try:
        if process.poll() is None:
            if pidfd is None:
                return False
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            if pidfd is None:
                return False
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            process.wait(timeout=5)
        return process.poll() is not None
    except (OSError, subprocess.TimeoutExpired):
        return False


def _run_lab_impl(
    work: Path,
    code: Path,
    vars_path: Path,
    image: Path,
    iso: Path,
    answer: Path,
    accelerator: str,
    *,
    connect_seconds: float = 15,
    prompt_seconds: float = 90,
    progress_seconds: float = 600,
    wait_seconds: float = 7200,
    synthetic_child=None,
    synthetic_log_data: bytes = b"",
    synthetic_spawn_failure: bool = False,
    pidfd_factory=None,
) -> dict:
    """Shared witness: only accepts an ALREADY-CREATED synthetic child.

    With QEMU backing unverified, even direct imports of this internal helper
    cannot launch any operating-system process, no matter what is supplied.
    No arbitrary factory is ever invoked.
    """
    report = {
        "schemaVersion": 1,
        "decision": "refuse",
        "reasonCode": "QEMU_STARTUP_UNCLASSIFIED",
        "qemuSpawned": False,
        "qemuPidRecorded": False,
        "qemuExitCode": None,
        "qemuSignal": None,
        "qmpSocketState": "ABSENT",
        "qmpHandshakeVerified": False,
        "qmpRunningVerified": False,
        "qmpSendKeyAcknowledged": False,
        "cleanupVerified": False,
        "windowsSetupVerified": False,
        "installationAuthorized": False,
        "diskWritesAuthorized": False,
        "rollbackVerified": False,
        "errorDetailCode": None,
        "cleanupReasonCode": None,
        "reportIoFailed": False,
        "descendantsCleanupVerified": False,
    }
    process = None
    pidfd = None
    session = None
    output = None
    pinned: dict[str, int] = {}
    work_fd = None
    try:
        dir_identity = _private_dir(work)
        _require(
            hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
            "QEMU_STARTUP_UNCLASSIFIED",
        )
        expected = {}
        for name, path in (("vars", vars_path), ("image", image), ("iso", iso), ("answer", answer)):
            expected[name] = _owned_file(path, work)
        _require(code.is_file() and not code.is_symlink(), "QEMU_STARTUP_UNCLASSIFIED")
        code_stat = code.lstat()
        _require(
            stat.S_ISREG(code_stat.st_mode) and code_stat.st_nlink == 1, "QEMU_STARTUP_UNCLASSIFIED"
        )
        work_fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        work_stat = os.fstat(work_fd)
        path_stat = work.stat()
        _require(
            (work_stat.st_dev, work_stat.st_ino)
            == (path_stat.st_dev, path_stat.st_ino)
            == (dir_identity.st_dev, dir_identity.st_ino)
            and work_stat.st_uid == os.getuid()
            and not work_stat.st_mode & 0o077,
            "QEMU_STARTUP_UNCLASSIFIED",
        )
        for name, path in (("vars", vars_path), ("image", image), ("iso", iso), ("answer", answer)):
            pinned[name] = _pin_file(
                path, expected[name], dirfd=work_fd, writable=name in ("vars", "image")
            )
        pinned["code"] = _pin_file(code, code_stat)
        qmp_path = work / "q4os-win10-qmp.sock"
        _require(_socket_identity(qmp_path, work) is None, "QEMU_QMP_SOCKET_INVALID")
        serial = work / "windows10-qemu-serial.log"
        _require(not serial.exists() and not serial.is_symlink(), "QEMU_STARTUP_UNCLASSIFIED")
        args = _qemu_args(work, code, vars_path, image, iso, answer, accelerator, pinned)
        # A synthetic process is supplied *already constructed*. The seam
        # has no factory, shell command or callable spawn hook.
        # If no child is provided, the real process gate is mandatory even
        # when someone imports this private function directly.
        _require(
            synthetic_child is not None or synthetic_spawn_failure or QEMU_FD_BACKING_VERIFIED,
            "QEMU_STARTUP_UNCLASSIFIED",
        )
        _require(
            not synthetic_log_data or synthetic_child is not None,
            "QEMU_STARTUP_UNCLASSIFIED",
        )
        # Operational callers cannot supply their own pidfd factory, even
        # if the FD-compatibility gate is eventually validated independently.
        _require(
            pidfd_factory is None or synthetic_child is not None,
            "QEMU_STARTUP_UNCLASSIFIED",
        )
        log = work / "windows10-qemu-process.log"
        output = log.open("xb")
        if synthetic_spawn_failure:
            raise StartupRefusal("QEMU_SPAWN_FAILED")
        if synthetic_child is None:
            try:
                process = subprocess.Popen(
                    args,
                    cwd=work,
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    pass_fds=tuple(pinned.values()),
                )
            except OSError:
                raise StartupRefusal("QEMU_SPAWN_FAILED") from None
        else:
            process = synthetic_child
            if synthetic_log_data:
                output.write(synthetic_log_data)
                output.flush()
        # Synthetic processes, including genuine pre-existing Python children,
        # have NOT been spawned by the operational QEMU supervisor.
        report["qemuSpawned"] = synthetic_child is None
        report["qemuPidRecorded"] = synthetic_child is None
        if process.poll() is not None:
            raise StartupRefusal("QEMU_EARLY_EXIT")
        birth = _birth_identity(process.pid)
        fd_factory = pidfd_factory or os.pidfd_open
        try:
            pidfd = fd_factory(process.pid)
        except OSError:
            if process.poll() is not None:
                raise StartupRefusal("QEMU_EARLY_EXIT") from None
            raise StartupRefusal("QEMU_STARTUP_UNCLASSIFIED") from None
        # Fail without signalling if a PID was recycled between spawn and pidfd.
        if process.poll() is not None or _birth_identity(process.pid) != birth:
            os.close(pidfd)
            pidfd = None
            raise StartupRefusal("QEMU_STARTUP_UNCLASSIFIED")
        # Synthetic fixtures must never register a child as operational.
        if synthetic_child is None:
            _register_owned_child(process, pidfd, birth)
        # The synthetic path is diagnostic-only. Never open QMP or input a
        # guest key, including when imported and called directly.
        _require(
            synthetic_child is None and QEMU_FD_BACKING_VERIFIED,
            "QEMU_STARTUP_UNCLASSIFIED",
        )
        session = _await_qmp(
            process,
            pidfd,
            qmp_path,
            work,
            report,
            seconds=connect_seconds,
        )

        try:
            result = supervise(
                qmp_path,
                serial,
                image,
                prompt_seconds=prompt_seconds,
                progress_seconds=progress_seconds,
                qmp_session=session,
            )
            report["qmpSendKeyAcknowledged"] = result["qmpSendKeyAcknowledged"]
        except BootRefusal as exc:
            code = str(exc)
            raise StartupRefusal(
                code if code in REASON_CODES else "QEMU_STARTUP_UNCLASSIFIED"
            ) from None
        try:
            exit_code = process.wait(timeout=wait_seconds)
        except subprocess.TimeoutExpired:
            raise StartupRefusal("QEMU_STARTUP_UNCLASSIFIED") from None
        if exit_code != 0:
            raise StartupRefusal("QEMU_STARTUP_UNCLASSIFIED")
        report["decision"] = "dvd_key_sent_once"
        report["reasonCode"] = None
    except StartupRefusal as exc:
        report["reasonCode"] = exc.code
    except (OSError, ValueError, RuntimeError):
        report["reasonCode"] = "QEMU_STARTUP_UNCLASSIFIED"
    finally:
        # Every operation before or after cleanup may fail (ENOSPC/EIO,
        # unexpected filesystem state, broken file.close, etc.). None may
        # bypass child termination and reaping.
        try:
            try:
                if process is not None:
                    exit_code = process.poll()
                    if exit_code is not None:
                        report["qemuExitCode"] = exit_code
                        report["qemuSignal"] = -exit_code if exit_code < 0 else None
                if output is not None:
                    output.flush()
                    if process is not None and report["reasonCode"] == "QEMU_EARLY_EXIT":
                        # Read through the supervisor's already-open file
                        # descriptor, not an attacker-replaceable pathname.
                        size = os.fstat(output.fileno()).st_size
                        # The log was opened O_WRONLY; dup() cannot make it
                        # readable. Re-open the pinned procfs FD, never log path.
                        with open(f"/proc/self/fd/{output.fileno()}", "rb") as source:
                            base = os.fstat(output.fileno())
                            observed = os.fstat(source.fileno())
                            _require(
                                (observed.st_dev, observed.st_ino) == (base.st_dev, base.st_ino),
                                "QEMU_STARTUP_UNCLASSIFIED",
                            )
                            detail = classify_qemu_error(source.read(min(size, 32768)))
                        report["errorDetailCode"] = (
                            detail if detail in DETAIL_CODES else EARLY_EXIT_DETAIL
                        )
            except Exception:
                report["reportIoFailed"] = True
                if report["reasonCode"] in (None, "QEMU_STARTUP_UNCLASSIFIED"):
                    report["reasonCode"] = "QEMU_STARTUP_UNCLASSIFIED"
                report["decision"] = "refuse"
        finally:
            try:
                cleaned = _cleanup(process, pidfd)
            except Exception:
                cleaned = False
            report["cleanupVerified"] = cleaned
            if not cleaned:
                report["decision"] = "refuse"
                report["cleanupReasonCode"] = "QEMU_PROCESS_CLEANUP_FAILED"
                if report["reasonCode"] in (None, "QEMU_STARTUP_UNCLASSIFIED"):
                    report["reasonCode"] = "QEMU_PROCESS_CLEANUP_FAILED"
            try:
                if process is not None:
                    code_now = process.poll()
                    if code_now is not None:
                        report["qemuExitCode"] = code_now
                        report["qemuSignal"] = -code_now if code_now < 0 else None
            except Exception:
                report["reportIoFailed"] = True
                report["decision"] = "refuse"
            # Revoke before releasing descriptors; no retained QMP object
            # can claim authority after its child has been reaped.
            if session is not None:
                _ISSUED_QMP_SESSIONS.discard(session)
            if process is not None:
                _OWNED_CHILDREN.pop(process, None)
            for fd in (pidfd, *pinned.values(), work_fd):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        report["reportIoFailed"] = True
                        report["decision"] = "refuse"
            if output is not None:
                try:
                    output.close()
                except Exception:
                    report["reportIoFailed"] = True
                    report["decision"] = "refuse"
            if report["decision"] == "refuse" and report["reasonCode"] is None:
                report["reasonCode"] = "QEMU_STARTUP_UNCLASSIFIED"
    return report


def _refused_report() -> dict:
    """Stable no-spawn diagnostic without accessing any caller-controlled path."""
    return {
        "schemaVersion": 1,
        "decision": "refuse",
        "reasonCode": "QEMU_STARTUP_UNCLASSIFIED",
        "qemuSpawned": False,
        "qemuPidRecorded": False,
        "qemuExitCode": None,
        "qemuSignal": None,
        "qmpSocketState": "ABSENT",
        "qmpHandshakeVerified": False,
        "qmpRunningVerified": False,
        "qmpSendKeyAcknowledged": False,
        "cleanupVerified": False,
        "windowsSetupVerified": False,
        "installationAuthorized": False,
        "diskWritesAuthorized": False,
        "rollbackVerified": False,
        "errorDetailCode": None,
        "cleanupReasonCode": None,
        "reportIoFailed": False,
        "descendantsCleanupVerified": False,
    }


def _run_lab_synthetic(
    work: Path,
    code: Path,
    vars_path: Path,
    image: Path,
    iso: Path,
    answer: Path,
    accelerator: str,
    *,
    synthetic_child=None,
    synthetic_log_data: bytes = b"",
    synthetic_spawn_failure: bool = False,
    pidfd_factory=None,
    connect_seconds: float = 0.04,
    prompt_seconds: float = 0.02,
    progress_seconds: float = 0.02,
    wait_seconds: float = 0.02,
) -> dict:
    """Internal DENY-ONLY fixture seam, never manufactures a process.

    Tests may provide a child they created independently. This function
    cannot run an injected executable or factory; every disk remains owned
    by the disposable test fixture. Never use as operational authority.
    """
    return _run_lab_impl(
        work,
        code,
        vars_path,
        image,
        iso,
        answer,
        accelerator,
        synthetic_child=synthetic_child,
        synthetic_log_data=synthetic_log_data,
        synthetic_spawn_failure=synthetic_spawn_failure,
        pidfd_factory=pidfd_factory,
        connect_seconds=connect_seconds,
        prompt_seconds=prompt_seconds,
        progress_seconds=progress_seconds,
        wait_seconds=wait_seconds,
    )


def run_lab(
    work: Path,
    code: Path,
    vars_path: Path,
    image: Path,
    iso: Path,
    answer: Path,
    accelerator: str,
    *,
    connect_seconds: float = 15,
    prompt_seconds: float = 90,
    progress_seconds: float = 600,
    wait_seconds: float = 7200,
    popen_factory=None,
    pidfd_factory=None,
) -> dict:
    """Public/CLI entry: synthetic factories cannot grant spawn authority."""
    # In particular, reject factories BEFORE evaluating them, checking
    # paths, pinning files, opening outputs, or calling subprocess.Popen.
    if popen_factory is not None or pidfd_factory is not None:
        return _refused_report()
    if not QEMU_FD_BACKING_VERIFIED:
        return _refused_report()
    return _run_lab_impl(
        work,
        code,
        vars_path,
        image,
        iso,
        answer,
        accelerator,
        connect_seconds=connect_seconds,
        prompt_seconds=prompt_seconds,
        progress_seconds=progress_seconds,
        wait_seconds=wait_seconds,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("work", "code", "vars", "image", "iso", "answer"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--accel", choices=("kvm", "tcg"), required=True)
    args = parser.parse_args()
    work = args.work
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or os.environ.get("GITHUB_REPOSITORY") != "LMhdez/gaslux"
        or os.environ.get("RUNNER_OS") != "Linux"
        or work
        != Path(os.environ.get("RUNNER_TEMP", "/nonexistent"))
        / ("gaslux-win10-" + os.environ.get("GITHUB_RUN_ID", "missing"))
    ):
        print("GASLUX_Q4OS_DVD_BOOT_DECISION=refuse")
        return 1
    report = run_lab(
        work,
        args.code,
        args.vars,
        args.image,
        args.iso,
        args.answer,
        args.accel,
        wait_seconds=14400 if args.accel == "tcg" else 7200,
    )
    _private_dir(work)
    report_path = work / "q4os-win10-uefi-dvd-boot.json"
    with report_path.open("x", encoding="utf-8") as output:
        json.dump(report, output, sort_keys=True, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    print("GASLUX_Q4OS_DVD_BOOT_DECISION=" + report["decision"])
    return 0 if report["decision"] == "dvd_key_sent_once" else 1


if __name__ == "__main__":
    raise SystemExit(main())
