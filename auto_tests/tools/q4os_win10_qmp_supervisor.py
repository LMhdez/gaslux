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
import signal
import socket
import stat
import struct
import subprocess
import time
from pathlib import Path

from q4os_win10_qemu_ovmf_preflight import classify_qemu_error
from q4os_win10_qmp_boot import BootRefusal, Qmp, supervise

QEMU = "/usr/bin/qemu-system-x86_64"
EARLY_EXIT_DETAIL = "QEMU_EARLY_EXIT_UNCLASSIFIED"


class StartupRefusal(RuntimeError):
    """One allowlisted diagnostic only."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise StartupRefusal(code)


def _private_dir(work: Path) -> None:
    _require(work.is_absolute() and not work.is_symlink(), "QEMU_STARTUP_UNCLASSIFIED")
    st = work.stat()
    _require(
        stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o077,
        "QEMU_STARTUP_UNCLASSIFIED",
    )


def _owned_file(path: Path, work: Path) -> None:
    _require(path.parent == work and not path.is_symlink(), "QEMU_STARTUP_UNCLASSIFIED")
    st = path.lstat()
    _require(
        stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_nlink == 1,
        "QEMU_STARTUP_UNCLASSIFIED",
    )


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


def _witness(process: subprocess.Popen, pidfd: int) -> None:
    _require(pidfd >= 0 and process.pid > 0, "QEMU_STARTUP_UNCLASSIFIED")
    _require(process.poll() is None, "QEMU_EARLY_EXIT")
    # pidfd signals are pinned to the kernel process object, unlike kill(pid).
    _require(os.path.samefile(f"/proc/{process.pid}/exe", QEMU), "QEMU_STARTUP_UNCLASSIFIED")


def _peer(channel: Qmp, process: subprocess.Popen) -> None:
    if not hasattr(socket, "SO_PEERCRED"):
        raise StartupRefusal("QEMU_QMP_HANDSHAKE_FAILED")
    raw = channel.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    pid, uid, _gid = struct.unpack("3i", raw)
    _require(pid == process.pid and uid == os.getuid(), "QEMU_QMP_SOCKET_INVALID")


def _await_qmp(
    process: subprocess.Popen,
    pidfd: int,
    path: Path,
    work: Path,
    report: dict,
    *,
    seconds: float = 15,
    interval: float = 0.05,
) -> tuple[Qmp, tuple[int, int]]:
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
            channel = Qmp(path)
            _peer(channel, process)
            _require(_socket_identity(path, work) == identity, "QEMU_QMP_SOCKET_INVALID")
            _witness(process, pidfd)
            report["qmpSocketState"] = "CONNECTED"
            report["qmpHandshakeVerified"] = True
            report["qmpRunningVerified"] = True
            return channel, identity
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
    work: Path, code: Path, vars_path: Path, image: Path, iso: Path, answer: Path, accelerator: str
) -> list[str]:
    _require(accelerator in ("kvm", "tcg"), "QEMU_STARTUP_UNCLASSIFIED")
    accel, cpu = ("kvm", "host") if accelerator == "kvm" else ("tcg,thread=multi", "max")
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
        "if=pflash,format=raw,unit=0,readonly=on,file=" + str(code),
        "-drive",
        "if=pflash,format=raw,unit=1,file=" + str(vars_path),
        "-device",
        "ich9-ahci,id=sata",
        "-drive",
        "if=none,id=system,file=" + str(image) + ",format=qcow2,cache=writeback",
        "-device",
        "ide-hd,drive=system,bus=sata.0,bootindex=2",
        "-drive",
        "if=none,id=install,file=" + str(iso) + ",format=raw,media=cdrom,readonly=on",
        "-device",
        "ide-cd,drive=install,bus=sata.1,bootindex=1",
        "-drive",
        "if=none,id=answer,file=" + str(answer) + ",format=raw,media=cdrom,readonly=on",
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
    """Observe a direct child and clean up only through its kernel pidfd."""
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
    }
    process = None
    pidfd = None
    output = None
    try:
        _private_dir(work)
        for path in (vars_path, image, iso, answer):
            _owned_file(path, work)
        _require(code.is_file() and not code.is_symlink(), "QEMU_STARTUP_UNCLASSIFIED")
        _require(
            hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
            "QEMU_STARTUP_UNCLASSIFIED",
        )
        qmp_path = work / "q4os-win10-qmp.sock"
        _require(_socket_identity(qmp_path, work) is None, "QEMU_QMP_SOCKET_INVALID")
        serial = work / "windows10-qemu-serial.log"
        _require(not serial.exists() and not serial.is_symlink(), "QEMU_STARTUP_UNCLASSIFIED")
        args = _qemu_args(work, code, vars_path, image, iso, answer, accelerator)
        log = work / "windows10-qemu-process.log"
        output = log.open("xb")
        try:
            factory = popen_factory or subprocess.Popen
            process = factory(
                args,
                cwd=work,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError:
            raise StartupRefusal("QEMU_SPAWN_FAILED") from None
        report["qemuSpawned"] = True
        report["qemuPidRecorded"] = True
        fd_factory = pidfd_factory or os.pidfd_open
        try:
            pidfd = fd_factory(process.pid)
        except OSError:
            if process.poll() is not None:
                raise StartupRefusal("QEMU_EARLY_EXIT") from None
            raise StartupRefusal("QEMU_STARTUP_UNCLASSIFIED") from None
        channel, identity = _await_qmp(
            process,
            pidfd,
            qmp_path,
            work,
            report,
            seconds=connect_seconds,
        )

        def guard() -> None:
            _witness(process, pidfd)
            _require(_socket_identity(qmp_path, work) == identity, "QEMU_QMP_SOCKET_INVALID")
            _peer(channel, process)

        try:
            result = supervise(
                qmp_path,
                serial,
                image,
                prompt_seconds=prompt_seconds,
                progress_seconds=progress_seconds,
                qmp_channel=channel,
                process_guard=guard,
            )
            report["qmpSendKeyAcknowledged"] = result["qmpSendKeyAcknowledged"]
        except BootRefusal as exc:
            if str(exc).startswith("QEMU_"):
                raise StartupRefusal(str(exc)) from None
            raise StartupRefusal("QEMU_STARTUP_UNCLASSIFIED") from None
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
        if process is not None:
            code = process.poll()
            if code is not None:
                report["qemuExitCode"] = code
                report["qemuSignal"] = -code if code < 0 else None
        if output is not None:
            output.flush()
            if (
                process is not None
                and report["reasonCode"] == "QEMU_EARLY_EXIT"
                and (work / "windows10-qemu-process.log").is_file()
            ):
                with (work / "windows10-qemu-process.log").open("rb") as source:
                    report["errorDetailCode"] = classify_qemu_error(source.read(32768))
        cleaned = _cleanup(process, pidfd)
        if pidfd is not None:
            os.close(pidfd)
        if output is not None:
            output.close()
        report["cleanupVerified"] = cleaned
        if not cleaned:
            report["decision"] = "refuse"
            report["reasonCode"] = "QEMU_PROCESS_CLEANUP_FAILED"
        if process is not None:
            code = process.poll()
            if code is not None:
                report["qemuExitCode"] = code
                report["qemuSignal"] = -code if code < 0 else None
    return report


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
    report = run_lab(work, args.code, args.vars, args.image, args.iso, args.answer, args.accel)
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
