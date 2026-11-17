#!/usr/bin/env python3
"""VM-only HMP screendump smoke: no guest disk, ISO, network or Windows boot."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from windows_x64_tcg_firstboot import LabError, capture_vm_screen, require


def main() -> int:
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("RUNNER_OS") == "Linux" and
            os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux",
            "VM screen smoke requires hosted GitHub Linux runner")
    require(Path(os.environ["RUNNER_TEMP"]) == Path("/home/runner/work/_temp"),
            "unexpected hosted runner temp root")
    with tempfile.TemporaryDirectory(prefix="gaslux-win-x64-",
                                     dir=os.environ["RUNNER_TEMP"]) as tmp:
        root = Path(tmp)
        monitor = root / "initial-installer-hmp.sock"
        target = root / "windows-dvd-90s.ppm"
        with (root / "qemu-smoke-stderr.log").open("xb") as stderr:
            process = subprocess.Popen([
                "qemu-system-x86_64", "-machine", "q35,accel=tcg",
                "-cpu", "qemu64", "-m", "256", "-smp", "1",
                "-nodefaults", "-net", "none", "-S",
                "-display", "vnc=127.0.0.1:79", "-vga", "std",
                "-monitor", f"unix:{monitor},server,nowait",
            ], stdout=subprocess.DEVNULL, stderr=stderr)
            try:
                for _ in range(100):
                    if monitor.is_socket():
                        break
                    if process.poll() is not None:
                        break
                    time.sleep(.1)
                require(process.poll() is None and monitor.is_socket(),
                        "headless QEMU monitor did not start")
                digest = capture_vm_screen(monitor, target)
                print(f"VM_HMP_SCREENSHOT_SHA256={digest}", flush=True)
                print("PASS: genuine paused diskless QEMU display capture, "
                      "not evidence of Windows or Linux boot.", flush=True)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (LabError, OSError) as error:
        print(f"QEMU_SCREEN_SMOKE_FAILURE: {error}", file=sys.stderr)
        sys.exit(1)
