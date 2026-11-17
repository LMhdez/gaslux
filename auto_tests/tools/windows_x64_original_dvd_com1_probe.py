#!/usr/bin/env python3
"""CI-only short original Microsoft Win10 DVD/COM1 HMP timing experiment.

No HDD, no answer USB, no WinPE/FirstLogon evidence and no host block devices.
A successful probe means only: an acknowledged HMP key was issued on the live
UEFI DVD COM1 prompt and no immediate firmware DVD timeout followed.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time

from windows_x64_qemu_host_gate import load_catalog, OVMF_CODE, OVMF_VARS
from windows_x64_tcg_firstboot import (
    BOOT_FROM_CD_PROMPT, LabError, download_verified_iso,
    first_stage_dvd_key_ready, require, scan_two_stage_dvd_serial,
    send_first_iso_boot_key, validate_environment,
)

TEMP = Path("/home/runner/work/_temp")
PROFILE = "win10_22h2_en_us_x64"


def original_dvd_probe(qemu: list[str], serial: Path, monitor: Path,
                       hold_ms: int, seconds: int = 105) -> bool:
    """Never infer Windows installation from an EFI DVD/monitor observation."""
    require(hold_ms in (300, 6000) and seconds == 105,
            "unapproved original ISO short-probe profile")
    require(serial.parent == monitor.parent and
            serial.parent.parent == TEMP and
            serial.parent.name.startswith("gaslux-win-x64-") and
            not serial.exists() and not monitor.exists(),
            "unsafe or reused DVD experiment paths")
    require("file:" + str(serial) in qemu and
            f"unix:{monitor},server,nowait" in qemu and
            "-net" in qemu and qemu[qemu.index("-net") + 1] == "none",
            "DVD-only QEMU endpoint was changed")
    drive_values = [qemu[i+1] for i, v in enumerate(qemu[:-1])
                    if v == "-drive"]
    require(len(drive_values) == 3 and
            sum("if=pflash" in x for x in drive_values) == 2 and
            sum("id=verified_iso,media=cdrom,readonly=on" in x
                for x in drive_values) == 1 and
            all("if=none,id=only_windows" not in x and
                "id=lab_unattend" not in x for x in drive_values),
            "an unexpected writable disk or answer image was offered")
    started_at = time.monotonic()
    start_seen_at = None
    key_at = None
    count, offset, carry = 0, 0, b""
    with (serial.parent / f"short-probe-{hold_ms}-qemu-stderr.log").open("xb") as stderr:
        proc = subprocess.Popen(qemu, stdout=subprocess.DEVNULL, stderr=stderr)
        try:
            while time.monotonic() - started_at < seconds:
                require(proc.poll() is None,
                        "UEFI DVD short-probe VM exited prematurely")
                if serial.is_file():
                    require(not serial.is_symlink() and
                            serial.stat().st_size <= 256 * 1024,
                            "original DVD firmware COM1 exceeded proof boundary")
                    hits, offset, carry, observed = scan_two_stage_dvd_serial(
                        serial, offset, carry)
                    count += hits
                    require(count <= 1, "original DVD boot restarted or duplicated")
                    if count == 1 and start_seen_at is None:
                        start_seen_at = time.monotonic()
                    require(b"No bootable option or device was found." not in observed
                            and not (b"DVD-ROM" in observed
                                     and b"Time out" in observed),
                            "original Windows DVD reported firmware timeout")
                    if key_at is None and first_stage_dvd_key_ready(
                            observed, start_seen_at, time.monotonic(), True):
                        require(monitor.is_socket() and not monitor.is_symlink(),
                                "private QEMU HMP socket is unavailable")
                        send_first_iso_boot_key(monitor, hold_ms=hold_ms)
                        key_at = time.monotonic()
                        print(f"GASLUX_ORIGINAL_WIN10_COM1_PROMPT_HMP_{hold_ms}MS_ACK=1",
                              flush=True)
                    if key_at is not None and time.monotonic() - key_at >= 20:
                        print(f"GASLUX_ORIGINAL_WIN10_DVD_NO_IMMEDIATE_TIMEOUT_{hold_ms}MS=1",
                              flush=True)
                        print("NOT TESTED: WinPE Setup, Windows installation, firstboot, "
                              "ESP/BCD/WinRE or Windows+CachyOS", flush=True)
                        return True
                time.sleep(0.1 if key_at is None else 0.3)
            raise LabError("official Microsoft DVD short probe timed out; "
                           "no EFI input progress proven")
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=8)
    return False


def main() -> int:
    require(os.environ.get("GASLUX_WINDOWS_ORIGINAL_DVD_PROBE_CONSENT") ==
            "I_ACCEPT_GITHUB_HOSTED_KVM_ORIGINAL_WIN10_DVD_ONLY_NO_DISK" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux",
            "explicit original Microsoft ISO DVD-only hosted consent missing")
    with tempfile.TemporaryDirectory(prefix="gaslux-win-x64-", dir=TEMP) as tmp:
        workspace = Path(tmp)
        require(workspace.stat().st_uid == os.getuid() and
                stat.S_IMODE(workspace.stat().st_mode) == 0o700,
                "original DVD workspace ownership or mode invalid")
        validate_environment(workspace, accelerator="kvm")
        iso = workspace / "official-microsoft-win10.iso"
        sha, size = download_verified_iso(
            load_catalog()["profiles"][PROFILE], iso)
        require(iso.is_file() and not iso.is_symlink() and
                iso.stat().st_uid == os.getuid() and 3 * 1024**3 <= size <= 9 * 1024**3,
                "ISO source or size does not match verified guest media")
        print("GASLUX_ORIGINAL_WIN10_DVD_ISO_SHA256_VERIFIED=1", flush=True)
        code = Path(OVMF_CODE)
        require(code.is_file() and not code.is_symlink(), "OVMF CODE not trusted")
        observed = []
        for hold_ms in (300, 6000):
            variables = workspace / f"ovmf-{hold_ms}.fd"
            shutil.copyfile(OVMF_VARS, variables)
            serial = workspace / f"serial-{hold_ms}.log"
            monitor = workspace / "initial-installer-hmp.sock"
            require(not monitor.exists(), "reused original ISO HMP monitor")
            qemu = [
                "qemu-system-x86_64", "-machine", "q35,accel=kvm,smm=on",
                "-cpu", "host", "-smp", "2", "-m", "4096",
                "-display", "none", "-vga", "std", "-net", "none",
                "-global", "driver=cfi.pflash01,property=secure,value=on",
                "-device", "qemu-xhci,id=lab_usb",
                "-device", "usb-kbd,bus=lab_usb.0",
                "-device", "ich9-ahci,id=lab_sata",
                "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
                "-drive", f"if=pflash,format=raw,file={variables}",
                "-drive", f"if=none,id=verified_iso,media=cdrom,readonly=on,format=raw,file={iso}",
                "-device", "ide-cd,drive=verified_iso,bus=lab_sata.1",
                "-boot", "order=d", "-no-reboot",
                "-serial", "file:" + str(serial),
                "-monitor", f"unix:{monitor},server,nowait",
            ]
            try:
                observed.append(original_dvd_probe(qemu, serial, monitor, hold_ms))
            except LabError:
                observed.append(False)
                print(f"GASLUX_ORIGINAL_WIN10_DVD_PROBE_{hold_ms}MS_FAILED=1",
                      flush=True)
            finally:
                # The QEMU process is always joined in original_dvd_probe().
                if monitor.is_socket() and not monitor.is_symlink():
                    monitor.unlink()
        require(any(observed),
                "neither 300ms nor 6000ms original DVD prompt advanced without "
                "immediate firmware timeout")
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        raise SystemExit(f"DVD-only CI diagnostic rejected: {error}") from None
