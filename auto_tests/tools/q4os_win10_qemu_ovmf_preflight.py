#!/usr/bin/env python3
"""Real QEMU/OVMF startup smoke test on SYNTHETIC private media only.

Run on an explicitly authorized Ubuntu 24.04 hosted runner after the
Q4OS libguestfs synthetic gate, BEFORE downloading any Windows ISO.
No Windows, Calamares, GPT write, bootloader or physical disk is used.
The same QEMU CPU, memory, KVM, pflash and SATA graph as the Windows
lab must expose a working read-only QMP control connection.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from q4os_win10_qmp_boot import Qmp

EXPECTED_REPOSITORY = "LMhdez/gaslux"
OVMF_CODE = Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
OVMF_VARS = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
SIZE = 48 * 1024**3


class QemuStartupDenied(RuntimeError):
    """A fail-closed, bounded reason, never a raw process log."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise QemuStartupDenied(reason)


def classify_qemu_error(private_log: bytes) -> str:
    """Classify known signatures only; NEVER publish QEMU stderr or paths."""
    text = private_log[: 32 * 1024].lower()
    if b"failed to initialize kvm" in text or b"could not access kvm" in text:
        return "QEMU_KVM_INITIALIZATION_FAILED"
    if b"cannot allocate memory" in text or b"memory allocation failed" in text:
        return "QEMU_HOST_MEMORY_UNAVAILABLE"
    if b"bus " in text and b"not found" in text:
        return "QEMU_SATA_BUS_NOT_FOUND"
    if b"property " in text and b"not found" in text:
        return "QEMU_DEVICE_OPTION_UNSUPPORTED"
    if b"permission denied" in text or b"could not open" in text:
        return "QEMU_FILE_ACCESS_DENIED"
    if b"failed to open" in text:
        return "QEMU_MEDIA_OPEN_FAILED"
    return "QEMU_EARLY_EXIT_UNCLASSIFIED"


def require_hosted_scope(env: dict[str, str], temp: Path) -> None:
    require(
        env.get("GITHUB_ACTIONS") == "true"
        and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and env.get("GITHUB_REPOSITORY") == EXPECTED_REPOSITORY
        and env.get("RUNNER_OS") == "Linux",
        "UNAUTHORIZED_QEMU_LAB",
    )
    require(
        temp.is_absolute()
        and temp.is_dir()
        and not temp.is_symlink()
        and temp.stat().st_uid == os.getuid(),
        "UNOWNED_RUNNER_TEMP",
    )
    kvm = Path("/dev/kvm")
    require(
        kvm.exists() and not kvm.is_symlink() and stat.S_ISCHR(kvm.stat().st_mode),
        "KVM_DEVICE_MISSING",
    )
    require(os.access(kvm, os.R_OK | os.W_OK), "KVM_DEVICE_UNREADABLE")
    require(
        shutil.which("qemu-system-x86_64") == "/usr/bin/qemu-system-x86_64"
        and shutil.which("qemu-img") == "/usr/bin/qemu-img",
        "QEMU_BINARY_NOT_PACKAGED",
    )
    require(
        OVMF_CODE.is_file()
        and OVMF_VARS.is_file()
        and not OVMF_CODE.is_symlink()
        and not OVMF_VARS.is_symlink(),
        "OVMF_FIRMWARE_MISSING",
    )


def _run_qemu(scratch: Path) -> dict:
    """Boot the actual Windows-sized machine graph with only blank owned media."""
    vars_path = scratch / "OVMF_VARS.fd"
    shutil.copyfile(OVMF_VARS, vars_path)
    vars_path.chmod(0o600)
    require(vars_path.stat().st_uid == os.getuid(), "OVMF_VARS_NOT_PRIVATE")
    disk = scratch / "synthetic-48g.qcow2"
    result = subprocess.run(
        ["/usr/bin/qemu-img", "create", "-f", "qcow2", "-o", "compat=1.1", str(disk), "48G"],
        capture_output=True,
        check=False,
        timeout=20,
    )
    require(result.returncode == 0 and disk.is_file(), "SYNTHETIC_QCOW2_CREATE_FAILED")
    dvd = scratch / "synthetic-dvd.iso"
    answer = scratch / "synthetic-answer.iso"
    dvd.write_bytes(b"\0" * 8192)
    answer.write_bytes(b"\0" * 8192)
    serial = scratch / "qemu-serial.private"
    log = scratch / "qemu-process.private"
    qmp = scratch / "qemu-qmp.sock"
    args = [
        "/usr/bin/qemu-system-x86_64",
        "-no-user-config",
        "-machine",
        "q35",
        "-accel",
        "kvm",
        "-cpu",
        "host",
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
        "file:" + str(serial),
        "-monitor",
        "none",
        "-net",
        "none",
        "-qmp",
        "unix:" + str(qmp) + ",server=on,wait=off",
        "-drive",
        "if=pflash,format=raw,unit=0,readonly=on,file=" + str(OVMF_CODE),
        "-drive",
        "if=pflash,format=raw,unit=1,file=" + str(vars_path),
        "-device",
        "ich9-ahci,id=sata",
        "-drive",
        "if=none,id=system,file=" + str(disk) + ",format=qcow2,cache=writeback",
        "-device",
        "ide-hd,drive=system,bus=sata.0,bootindex=2",
        "-drive",
        "if=none,id=install,file=" + str(dvd) + ",format=raw,media=cdrom,readonly=on",
        "-device",
        "ide-cd,drive=install,bus=sata.1,bootindex=1",
        "-drive",
        "if=none,id=answer,file=" + str(answer) + ",format=raw,media=cdrom,readonly=on",
        "-device",
        "ide-cd,drive=answer,bus=sata.2,bootindex=3",
    ]
    proc = None
    started_at = time.monotonic()
    failure: Exception | None = None
    verified = False
    with log.open("xb") as output:
        try:
            proc = subprocess.Popen(
                args,
                cwd=scratch,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
            )
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise QemuStartupDenied(classify_qemu_error(log.read_bytes()))
                if qmp.exists():
                    channel = None
                    try:
                        channel = Qmp(qmp)
                        verified = True
                        break
                    except (OSError, ValueError):
                        pass
                    finally:
                        if channel is not None:
                            channel.close()
                time.sleep(0.1)
            require(verified, "QEMU_QMP_STARTUP_TIMEOUT")
        except Exception as exc:
            failure = exc
        finally:
            if proc is not None:
                if proc.poll() is None:
                    proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
    if failure is not None:
        if isinstance(failure, QemuStartupDenied):
            raise failure
        raise QemuStartupDenied("QEMU_STARTUP_OR_CLEANUP_FAILED") from failure
    require(verified, "QEMU_QMP_NOT_VERIFIED")
    return {
        "qemuProcessStarted": True,
        "qmpHandshakeAndRunningVerified": True,
        "qmpKeySent": False,
        "syntheticDriveCount": 1,
        "syntheticQcow2VirtualBytes": SIZE,
        "ovmfPrivateVars": True,
        "hostKvmRequired": True,
        "qemuMachineTopology": "q35-kvm-cpu-host-smp4-m6144-ahci-pflash-two-cdrom",
        "startupElapsedMilliseconds": int((time.monotonic() - started_at) * 1000),
    }


def execute() -> dict:
    temp = Path(os.environ.get("RUNNER_TEMP", "/nonexistent-runner-temp"))
    require_hosted_scope(os.environ, temp)
    evidence = Path(os.environ.get("GASLUX_Q4OS_OVMF_EVIDENCE", "/nonexistent-evidence"))
    require(
        evidence.is_absolute()
        and evidence.parent == temp
        and evidence.is_dir()
        and not evidence.is_symlink()
        and evidence.stat().st_uid == os.getuid()
        and evidence.stat().st_mode & 0o077 == 0,
        "OVMF_EVIDENCE_NOT_PRIVATE",
    )
    with tempfile.TemporaryDirectory(prefix="gaslux-q4os-ovmf-", dir=temp) as path:
        observed = _run_qemu(Path(path))
    return {
        "schemaVersion": 1,
        "decision": "SYNTHETIC_QEMU_OVMF_QMP_PASS_NO_WRITER",
        "source": "GITHUB_HOSTED_BLANK_SYNTHETIC_MEDIA_ONLY",
        "trustBoundary": "NOT_INDEPENDENT",
        "tempMediaRemoved": True,
        "windowsMediaUsed": False,
        "windowsSetupExecuted": False,
        "installationAuthorized": False,
        "diskWritesAuthorized": False,
        "rollbackVerified": False,
        **observed,
    }


def main() -> int:
    evidence = Path(os.environ.get("GASLUX_Q4OS_OVMF_EVIDENCE", "/nonexistent-evidence"))
    try:
        report = execute()
        code = 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        reason = (
            str(exc) if isinstance(exc, QemuStartupDenied) else "OVMF_PREFLIGHT_UNEXPECTED_FAILURE"
        )
        report = {
            "schemaVersion": 1,
            "decision": "BLOCKED_QEMU_OVMF_STARTUP",
            "reasonCode": reason[:96],
            "trustBoundary": "NOT_INDEPENDENT",
            "windowsMediaUsed": False,
            "windowsSetupExecuted": False,
            "installationAuthorized": False,
            "diskWritesAuthorized": False,
            "rollbackVerified": False,
        }
        code = 1
    if evidence.is_dir() and not evidence.is_symlink():
        output = evidence / "q4os-qemu-ovmf-startup.json"
        require(not output.exists(), "OVMF_REPORT_ALREADY_EXISTS")
        output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("GASLUX_Q4OS_QEMU_OVMF_PREFLIGHT=" + report["decision"])
    return code


if __name__ == "__main__":
    sys.exit(main())
