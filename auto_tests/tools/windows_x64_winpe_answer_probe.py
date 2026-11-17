#!/usr/bin/env python3
"""Disposable WinPE answer-auto-discovery A/B, with NO installed guest disk.

The tested ISO is an ephemeral UEFI no-prompt derivative from a Microsoft
SHA-256-verified Windows 10 source. Only Windows PE's *own* windowsPE
RunSynchronous command can emit the COM1 marker. A floppy and read-only USB
each have the same XML and script bytes. This is not Windows client firstboot
or proof of a recoverable Windows/Linux dual boot.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

from windows_x64_tcg_firstboot import (
    LabError, OVMF_CODE, OVMF_VARS,
    derive_no_prompt_uefi_lab_iso, download_verified_iso,
    generate_unattend, load_catalog, require, validate_environment,
    witness_powershell,
)

PROFILE = "win10_22h2_en_us_x64"
BUILD = "19045"
MARKER = b"GASLUX_WINPE_AUTOANSWER_ACTUALLY_CONSUMED=1"
NS = "urn:schemas-microsoft-com:unattend"
WCM = "http://schemas.microsoft.com/WMIConfig/2002/State"
MODES = ("fat12_floppy", "fat32_usb")
MAX_SERIAL = 1_000_000
PROBE_SECONDS = 240
CI_CONSENT = "I_ACCEPT_DISPOSABLE_WINPE_NO_TARGET_DISK"


def build_winpe_witness_xml(mode: str) -> bytes:
    """Add exactly one preinstall serial witness to real generated Win10 XML."""
    require(mode in MODES, "unsupported Windows PE answer media")
    root = ET.fromstring(generate_unattend(PROFILE, BUILD,
                                           usb_answer=(mode == "fat32_usb")))
    setup = [x for x in root.findall("./{" + NS + "}settings/{" + NS + "}component")
             if x.attrib.get("name") == "Microsoft-Windows-Setup"]
    require(len(setup) == 1, "missing unique WinPE Setup component")
    # The positive FAT12 control previously failed even though the FAT12
    # answer is known to install Windows on a disposable target disk. This
    # *diskless* WinPE probe was mistakenly supplying the real unattended
    # DiskConfiguration/WillWipeDisk=TRUE and InstallTo DiskID=0 despite NO
    # target disk. Strip ALL installed-OS and Setup-disk instructions before
    # adding the sole Windows PE COM1 discovery witness.
    #
    # This is intentionally NOT the production/installer unattended document.
    for setting in root.findall("{" + NS + "}settings"):
        if setting.attrib.get("pass") != "windowsPE":
            root.remove(setting)
    require(len(root.findall("{" + NS + "}settings")) == 1,
            "ambiguous windowsPE pass in diskless answer probe")
    for existing in list(setup[0]):
        setup[0].remove(existing)
    for banned in ("DiskConfiguration", "ImageInstall", "DiskID",
                   "InstallTo", "WillWipeDisk", "FirstLogonCommands"):
        require(not any(x.tag == "{" + NS + "}" + banned
                        for x in root.iter()),
                "diskless WinPE probe must not contain " + banned)
    node = ET.SubElement(setup[0], "{" + NS + "}RunSynchronous")
    command = ET.SubElement(node, "{" + NS + "}RunSynchronousCommand",
                            {"{" + WCM + "}action": "add"})
    ET.SubElement(command, "{" + NS + "}Order").text = "1"
    ET.SubElement(command, "{" + NS + "}Description").text = (
        "Gaslux read-only Windows PE answer file discovery probe"
    )
    # All commands execute only in the throwaway Windows PE guest.
    # Echoing a marker to guest COM1 does not modify a disk or bootloader.
    ET.SubElement(command, "{" + NS + "}Path").text = (
        "cmd.exe /c echo GASLUX_WINPE_AUTOANSWER_ACTUALLY_CONSUMED=1>COM1"
    )
    ET.SubElement(command, "{" + NS + "}WillReboot").text = "Never"
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def make_readonly_answer_media(work: Path, mode: str) -> Path:
    require(mode in MODES and work.is_dir()
            and work.parent.parent == Path("/home/runner/work/_temp")
            and work.parent.name.startswith("gaslux-win-x64-"),
            "refuse foreign answer-media workspace")
    answer = work / "answer-lab.img"
    require(not answer.exists() and not answer.is_symlink(),
            "refuse reused answer image")
    is_usb = mode == "fat32_usb"
    subprocess.run(["truncate", "-s", "64M" if is_usb else "1440K",
                    str(answer)], check=True)
    subprocess.run(
        ["mkfs.vfat", "-F", "32" if is_usb else "12",
         "-n", "GASLUXCI", str(answer)],
        stdout=subprocess.DEVNULL, check=True,
    )
    xml = work / "Autounattend.xml"
    script = work / "GASLUX.PS1"
    xml.write_bytes(build_winpe_witness_xml(mode))
    script.write_bytes((witness_powershell(PROFILE, BUILD) + "\n").encode("utf-8"))
    for name, source in (("Autounattend.xml", xml), ("GASLUX.PS1", script)):
        subprocess.run(["mcopy", "-i", str(answer), str(source), "::/" + name],
                       check=True)
        actual = subprocess.run(
            ["mtype", "-i", str(answer), "::/" + name],
            check=True, stdout=subprocess.PIPE,
        ).stdout
        require(source.read_bytes() == actual,
                "Windows PE answer-media FAT write/readback mismatch")
    return answer


def build_no_target_qemu_args(
    iso: Path, answer: Path, vars_file: Path, serial: Path, mode: str,
) -> list[str]:
    require(mode in MODES, "unknown WinPE answer medium")
    args = [
        "qemu-system-x86_64", "-machine", "q35,accel=kvm,smm=on",
        "-global", "driver=cfi.pflash01,property=secure,value=on",
        "-cpu", "host", "-smp", "2", "-m", "4096",
        "-display", "none", "-vga", "std",
        "-net", "none", "-no-reboot",
        "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE}",
        "-drive", f"if=pflash,format=raw,file={vars_file}",
        "-device", "qemu-xhci,id=lab_usb",
        "-device", "usb-kbd,bus=lab_usb.0",
        "-device", "ich9-ahci,id=lab_sata",
        "-drive", f"if=none,id=verified_iso,media=cdrom,readonly=on,format=raw,file={iso}",
        "-device", "ide-cd,drive=verified_iso,bus=lab_sata.1",
        "-serial", f"file:{serial}", "-boot", "order=d",
        "-monitor", "none",
    ]
    if mode == "fat12_floppy":
        args += ["-drive", f"if=floppy,format=raw,readonly=on,file={answer}"]
    else:
        args += [
            "-drive", f"if=none,id=lab_unattend,format=raw,readonly=on,file={answer}",
            "-device", "usb-storage,drive=lab_unattend,bus=lab_usb.0",
        ]
    require(
        "-net" in args and args[args.index("-net") + 1] == "none"
        and all("only_windows" not in arg and "ide-hd" not in arg
                and "qcow2" not in arg for arg in args)
        and args.count("-boot") == 1
        and args[args.index("-boot") + 1] == "order=d",
        "WinPE probe must never attach an installable target disk or network",
    )
    return args


def probe_once(derived_iso: Path, root: Path, mode: str) -> bool:
    require(mode in MODES, "unknown WinPE probe mode")
    work = root / mode
    work.mkdir(mode=0o700)
    answer = make_readonly_answer_media(work, mode)
    nvram = work / "owned-ovmf-vars.fd"
    shutil.copyfile(OVMF_VARS, nvram)
    nvram.chmod(0o600)
    serial = work / "guest-serial.log"
    args = build_no_target_qemu_args(derived_iso, answer, nvram, serial, mode)
    error = work / "qemu-stderr.log"
    found = False
    with error.open("xb") as stderr:
        vm = subprocess.Popen(
            args, stdout=subprocess.DEVNULL, stderr=stderr,
        )
        try:
            deadline = time.monotonic() + PROBE_SECONDS
            while time.monotonic() < deadline:
                if serial.is_file() and not serial.is_symlink():
                    size = serial.stat().st_size
                    require(size <= MAX_SERIAL,
                            "bounded COM1 log exceeded or guest spammed serial")
                    with serial.open("rb") as stream:
                        raw = stream.read(MAX_SERIAL + 1)
                    lines = [line.strip() for line in raw.splitlines()]
                    if lines.count(MARKER) > 1:
                        raise LabError("duplicate WinPE answer consumption markers")
                    if MARKER in lines:
                        found = True
                        break
                    if b"No bootable option or device was found." in raw:
                        break
                if vm.poll() is not None:
                    break
                time.sleep(2)
        finally:
            if vm.poll() is None:
                vm.kill()
                vm.wait(timeout=30)
    print("GASLUX_WINPE_" + mode.upper() + "_ANSWER_MARKER=" + str(int(found)),
          flush=True)
    return found


def main() -> int:
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "Linux"
            and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
            and os.environ.get("RUNNER_TEMP") == "/home/runner/work/_temp"
            and os.environ.get("GASLUX_WINDOWS_WINPE_PROBE_CONSENT") == CI_CONSENT,
            "unapproved Windows PE answer-media probe")
    catalog = load_catalog()
    profile = catalog["profiles"][PROFILE]
    with tempfile.TemporaryDirectory(
        prefix="gaslux-win-x64-", dir=os.environ["RUNNER_TEMP"],
    ) as temporary:
        root = Path(temporary)
        validate_environment(root, "kvm")
        original = root / "pinned-official-windows10.iso"
        original_sha, size = download_verified_iso(profile, original)
        print("GASLUX_WINDOWS_WINPE_ORIGINAL_MICROSOFT_SHA256_VERIFIED=1",
              flush=True)
        derived = root / "lab-only-no-prompt-derived.iso"
        derived_sha = derive_no_prompt_uefi_lab_iso(original, derived, root)
        result = {mode: probe_once(derived, root, mode) for mode in MODES}
        print("GASLUX_WINPE_ANSWER_A_B_NUMERIC=" + json.dumps({
            "fat12FloppyReadByWinPE": int(result["fat12_floppy"]),
            "fat32UsbReadByWinPE": int(result["fat32_usb"]),
            "originalIsoSha256Verified": True,
            "labDerivedIsoSha256MatchesOriginal": derived_sha == original_sha,
            "windowsClientBootVerified": False,
            "dualBootVerified": False,
            "storageWritesAuthorized": False,
        }, sort_keys=True), flush=True)
        require(result["fat12_floppy"],
                "WinPE FAT12 control failed; USB result is inconclusive")
        require(result["fat32_usb"],
                "WinPE FAT32 USB answer not observed; no installer proof")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LabError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print("GASLUX_WINDOWS_WINPE_ANSWER_PROBE_FAIL: " + str(error), flush=True)
        raise SystemExit(1)
