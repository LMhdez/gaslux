#!/usr/bin/env python3
"""Observe the pinned Zorin ISO in QEMU/OVMF without ANY hard disk or installer call.

QMP quit stops only a disposable, diskless VM. It is not a Linux shutdown
witness and a screenshot is not by itself a proof of live boot.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import time
from uuid import uuid4

from windows_zorin_synthetic_cow_root import verify_official_zorin

CONSENT = "I_ACCEPT_ZORIN_PINNED_ISO_DISKLESS_OVMF_OBSERVATION"


class ObservationError(RuntimeError):
    pass


def require(ok: bool, why: str) -> None:
    if not ok:
        raise ObservationError(why)


def sha256_file(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def check_host(iso: Path, evidence: Path) -> Path:
    scratch = Path(os.environ.get("RUNNER_TEMP", "/absent"))
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", "/absent"))
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and str(scratch) == "/home/runner/work/_temp"
        and os.environ.get("GASLUX_ZORIN_LIVE_CONSENT") == CONSENT
        and os.geteuid() != 0
        and iso.is_file() and not iso.is_symlink()
        and iso.resolve().is_relative_to(scratch.resolve())
        and evidence.is_dir() and not evidence.is_symlink()
        and evidence.resolve() == workspace.resolve() / "zorin-native-evidence"
        and os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK),
        "requires opted-in private hosted KVM, readonly ISO and evidence directory",
    )
    return scratch


def qmp(sock: socket.socket, stream, name: str, args: dict | None = None):
    query = {"execute": name, "id": name}
    if args is not None:
        query["arguments"] = args
    sock.sendall((json.dumps(query) + "\n").encode())
    for _ in range(50):
        line = stream.readline()
        require(bool(line), "truncated QMP response")
        message = json.loads(line)
        if message.get("id") == name:
            require("return" in message and "error" not in message,
                    "QMP command not acknowledged: " + name)
            return message["return"]
    raise ObservationError("QMP response missing: " + name)


def capture(iso: Path, evidence: Path, seconds: int = 180) -> dict:
    scratch = check_host(iso, evidence)
    require(60 <= seconds <= 300, "observation duration must be bounded")
    verify_official_zorin(iso)
    executable = shutil.which("qemu-system-x86_64")
    require(executable is not None, "QEMU is missing")
    candidates = (
        ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
        ("/usr/share/OVMF/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_VARS.fd"),
    )
    pair = next(((Path(c), Path(v)) for c, v in candidates
                 if Path(c).is_file() and Path(v).is_file()), None)
    require(pair is not None, "OVMF code/vars pair is missing")
    code, vars_template = pair
    require(not code.is_symlink() and not vars_template.is_symlink(),
            "refusing linked firmware source")
    directory = scratch / ("gaslux-zorin-live-" + uuid4().hex)
    directory.mkdir(mode=0o700)
    require(stat.S_IMODE(directory.stat().st_mode) == 0o700,
            "unsafe private OVMF directory")
    vars_file = directory / "OVMF_VARS.fd"
    shutil.copyfile(vars_template, vars_file)
    starting_vars_sha = sha256_file(vars_file)
    socket_file = directory / "qmp.sock"
    serial_file = directory / "serial.log"
    cmd = [
        executable, "-nodefaults", "-no-user-config", "-machine", "q35,accel=kvm",
        "-cpu", "host", "-smp", "2", "-m", "4096", "-net", "none",
        "-display", "none", "-device", "VGA", "-no-reboot",
        "-drive", "if=pflash,format=raw,readonly=on,file=" + str(code),
        "-drive", "if=pflash,format=raw,file=" + str(vars_file),
        "-device", "ich9-ahci,id=ahci",
        "-drive", "if=none,id=cd,media=cdrom,readonly=on,format=raw,file=" + str(iso),
        "-device", "ide-cd,drive=cd,bus=ahci.0,bootindex=1",
        "-qmp", "unix:" + str(socket_file) + ",server=on,wait=off",
        "-serial", "file:" + str(serial_file),
    ]
    process = subprocess.Popen(
        cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    result = {
        "sessionId": directory.name,
        "qemuPid": process.pid, "qemuCommandSha256":
            hashlib.sha256("\0".join(cmd).encode()).hexdigest(),
        "isoSha256": sha256_file(iso), "ovmfCodeSha256": sha256_file(code),
        "ovmfVariablesInitialSha256": starting_vars_sha,
        "hostGuestIdentityIndependentlyAuthenticated": False,
        "windowsDiskAttached": False, "linuxTargetDiskAttached": False,
        "isoAttachedReadOnly": True, "installerInvokedByObserver": False,
        "nativeInstallationVerified": False, "liveIsoBootVerified": False,
        "guestShutdownVerified": False, "qmpQuitIsCleanupOnly": True,
        "screenshots": [], "authorization": "DENY_NO_WRITER",
    }
    sock = stream = None
    failure = None
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect(str(socket_file))
                break
            except (OSError, ConnectionRefusedError):
                time.sleep(0.3)
        else:
            raise ObservationError("QMP socket unavailable")
        stream = sock.makefile("rb")
        greeting = json.loads(stream.readline())
        require("QMP" in greeting, "QMP greeting absent")
        qmp(sock, stream, "qmp_capabilities")
        blocks = qmp(sock, stream, "query-block")
        require(isinstance(blocks, list), "QMP block identity unavailable")
        # QMP can expose pflash as a writable block device. It is allowed ONLY
        # for this VM's private OVMF variables file, never a target hard disk.
        for block in blocks:
            inserted = block.get("inserted", {})
            filename = str(inserted.get("file", ""))
            require(
                not filename or filename in (str(iso), str(code), str(vars_file)),
                "unexpected QEMU block-device backing",
            )
            require(filename != str(iso) or inserted.get("ro") is True,
                    "optical ISO opened writable")
        result["qmpBlockCount"] = len(blocks)
        result["qmpSocketInode"] = socket_file.stat().st_ino
        result["qmpVerified"] = True
        from PIL import Image
        for index in range(2):
            time.sleep(seconds // 2)
            require(process.poll() is None, "QEMU exited before frame capture")
            state = qmp(sock, stream, "query-status")
            require(state.get("status") == "running", "QEMU is not running")
            frame = directory / ("frame" + str(index) + ".ppm")
            qmp(sock, stream, "screendump", {"filename": str(frame)})
            require(frame.is_file() and frame.stat().st_size < 16 * 1024**2,
                    "missing or oversized guest framebuffer")
            png = evidence / ("zorin-native-live-frame" + str(index) + ".png")
            with Image.open(frame) as image:
                require(image.width <= 1920 and image.height <= 1080,
                        "unexpected virtual framebuffer geometry")
                image.save(png)
            result["screenshots"].append({"file": png.name, "sha256": sha256_file(png)})
        result["serialLogSha256"] = sha256_file(serial_file)
        qmp(sock, stream, "quit")
        process.wait(timeout=30)
        result["qemuExitAfterQmpQuit"] = process.returncode
    except Exception as error:
        failure = str(error)[:350]
    finally:
        if stream is not None:
            stream.close()
        if sock is not None:
            sock.close()
        if process.poll() is None:
            process.terminate()  # cleanup only; never a Linux shutdown witness
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()  # cleanup only; never claim orderly shutdown
                process.wait(timeout=10)
                result["forcedTeardown"] = True
        result["ovmfVariablesFinalSha256"] = sha256_file(vars_file)
        result["failure"] = failure
        (evidence / "zorin-native-live-observation.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8",
        )
        shutil.rmtree(directory)
    require(failure is None, "ISO-only QEMU observation failed: " + str(failure))
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=180)
    args = parser.parse_args()
    data = capture(args.iso, args.evidence, args.seconds)
    print("QMP ISO-only observation complete, no native installation:", data["sessionId"])


if __name__ == "__main__":
    main()
