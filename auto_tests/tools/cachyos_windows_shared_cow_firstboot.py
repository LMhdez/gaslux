#!/usr/bin/env python3
"""Disposable QEMU-only, read-only poweroff boot of the installed CachyOS root.

This is a *minimal boot smoke*, not a login, dual boot, update or rollback
test. It runs after the signed native pacstrap and before the trial COW is
discarded. Both the Windows-backed QCOW2 and the temporary boot EFI medium
are attached READ-ONLY to the guest. The only guest-writable state is a fresh
ephemeral OVMF variable file. The Windows ESP, BCD and NVRAM are never used.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid

from windows_cachyos_cow_checkpoint import CHECKPOINT_DIR, OVERLAY_NAME
from windows_cachyos_qcow2_gpt_readonly import qcow2_file_identity, VIRTUAL_BYTES
from windows_x64_qemu_host_gate import OVMF_VARS
from cachyos_windows_shared_root_pacstrap_host import (
    _copy_fresh_ovmf_vars, _copy_to_fat, _owned, _run, _sha,
    _write_lab_image,
)

MAX_SERIAL_BYTES = 2 * 1024 * 1024
CONSENT = "I_ACCEPT_READONLY_CACHYOS_INSTALLED_ROOT_POWER_OFF_VM_ONLY"


class InstalledReadOnlyBootError(ValueError):
    """Minimal read-only installed-OS smoke was not proven."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise InstalledReadOnlyBootError(reason)


def canonical_root_uuid(value: str) -> str:
    require(isinstance(value, str) and len(value) == 36,
            "missing canonical installed-root filesystem UUID")
    try:
        canonical = str(uuid.UUID(value))
    except ValueError as error:
        raise InstalledReadOnlyBootError("invalid installed-root filesystem UUID") from error
    require(value == canonical, "noncanonical installed-root filesystem UUID")
    return canonical


def installed_poweroff_grub_config(root_uuid: str) -> str:
    """Never select a disk by hd index, /dev name, or partition order."""
    root_uuid = canonical_root_uuid(root_uuid)
    return (
        "serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1\n"
        "terminal_input serial\nterminal_output serial\n"
        "set timeout=0\n"
        "insmod part_gpt\ninsmod ext2\ninsmod usb\ninsmod usbms\n"
        "search --no-floppy --fs-uuid --set=gaslux_linux_root " + root_uuid + "\n"
        "if [ ! -f ($gaslux_linux_root)/boot/vmlinuz-linux-cachyos-lts ]; then\n"
        " echo 'GASLUX_VM_INSTALLED_ROOT_KERNEL_MISSING'\n halt\nfi\n"
        "if [ ! -f ($gaslux_linux_root)/boot/initramfs-linux-cachyos-lts.img ]; then\n"
        " echo 'GASLUX_VM_INSTALLED_ROOT_INITRD_MISSING'\n halt\nfi\n"
        "echo 'GASLUX_VM_INSTALLED_ROOT_UUID_SELECTED:" + root_uuid + "'\n"
        "linux ($gaslux_linux_root)/boot/vmlinuz-linux-cachyos-lts"
        " root=UUID=" + root_uuid +
        " ro console=ttyS0,115200n8 loglevel=6"
        " systemd.unit=poweroff.target systemd.show_status=yes\n"
        "initrd ($gaslux_linux_root)/boot/initramfs-linux-cachyos-lts.img\n"
        "boot\n"
    )


def verify_installed_poweroff_serial(data: bytes, root_uuid: str) -> None:
    """Require kernel *and* installed systemd to power off; GRUB alone is insufficient."""
    root_uuid = canonical_root_uuid(root_uuid)
    require(0 < len(data) <= MAX_SERIAL_BYTES,
            "missing or oversized installed-Linux serial")
    require(data.count(("GASLUX_VM_INSTALLED_ROOT_UUID_SELECTED:" +
                        root_uuid).encode("ascii")) == 1,
            "GRUB did not select the signed installed ext4 root by UUID")
    # The genuine, Windows-backed QEMU firstboot artifact #14489666084
    # contains both the Linux version and the native kernel command line.
    # Require those kernel-origin records, not only GRUB console output or
    # a systemd banner that can appear during an initramfs-only shutdown.
    require(re.search(
        rb"\[\s*[0-9]+\.[0-9]+\]\s+Linux version "
        rb"[0-9][^\r\n]{0,95}cachyos(?:-lts)?\b", data
    ) is not None, "installed CachyOS kernel version not observed")
    cmdlines = re.findall(
        rb"\[\s*[0-9]+\.[0-9]+\]\s+Kernel command line: "
        rb"([^\r\n]{1,700})", data
    )
    require(len(cmdlines) == 1,
            "missing or ambiguous kernel-origin command line")
    cmdline = cmdlines[0]
    require(
        len(re.findall(rb"(?:^|\s)root=", cmdline)) == 1
        and (b"root=UUID=" + root_uuid.encode("ascii")) in cmdline.split()
        and b"ro" in cmdline.split()
        and b"rw" not in cmdline.split()
        and b"systemd.unit=poweroff.target" in cmdline.split(),
        "installed Linux kernel did not use the exact read-only root/poweroff plan"
    )
    require((re.search(rb"systemd\[1\]|systemd [0-9]{3} running", data)
             is not None
             or re.search(rb"pid=1;[^\r\n]{0,160}comm=systemd;type=boot",
                          data) is not None),
            "installed systemd PID 1 was not observed")
    # Reject an initramfs-only shutdown. The independent VM log in PR #34
    # shows a real systemd "Switch Root" phase before the installed
    # CachyOS welcome banner. This must happen *before* final poweroff.
    switched = data.find(b"Switch Root")
    welcome = re.search(rb"Welcome to[^\r\n]{0,160}CachyOS", data)
    require(switched >= 0 and welcome is not None
            and switched < welcome.start(),
            "installed Linux did not transition from initramfs into native root")
    # Native Arch/CachyOS systemd output on a serial console uses ANSI
    # control codes. Do not demand a literal "Powering off." string when
    # the kernel emits the real terminal witness "reboot: Power down".
    require(b"System Power Off" in data
            and (b"Powering off." in data
                 or b"reboot: Power down" in data),
            "installed systemd and kernel did not complete poweroff")
    for marker in (
        b"GASLUX_VM_INSTALLED_ROOT_KERNEL_MISSING",
        b"GASLUX_VM_INSTALLED_ROOT_INITRD_MISSING",
        b"Kernel panic",
    ):
        require(marker not in data, "installed-OS boot emitted a fatal marker")


def probe_installed_root_readonly(
    *, overlay: Path, base: Path, nvram: Path, ovmf_code: Path,
    workspace: Path, plan: dict, run_id: str,
) -> dict[str, object]:
    """Boot prevalidated root with QEMU read-only storage and disposable EFI.

    No Archiso ISO, no control medium, no Windows ESP loader, no network.
    Native poweroff proves only a limited installed-root first boot.
    """
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "Linux"
            and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
            and os.environ.get("GASLUX_CACHYOS_INSTALLED_RO_BOOT_CONSENT")
                == CONSENT,
            "read-only installed-root boot requires explicit hosted QEMU consent")
    require(type(plan) is dict and plan.get("labOnly") is True
            and plan.get("writeAuthority") is False
            and plan.get("runId") == run_id
            and isinstance(run_id, str)
            and re.fullmatch(r"[a-z0-9-]{12,80}", run_id) is not None,
            "installed-root boot is not tied to a signed lab plan")
    root_uuid = canonical_root_uuid(plan.get("rootFsUuid"))
    require(workspace.is_absolute() and workspace.is_dir()
            and not workspace.is_symlink()
            and workspace.name.startswith("gaslux-win-x64-")
            and workspace.parent == Path(os.environ.get("RUNNER_TEMP", ""))
            and stat.S_IMODE(workspace.stat().st_mode) == 0o700,
            "installed-root probe is outside the hosted private workspace")
    require(base.parent == workspace and overlay.parent ==
            workspace / CHECKPOINT_DIR and nvram.parent == workspace,
            "installed-root probe would use foreign disk or EFI paths")
    _owned(base, workspace, "only-disposable-windows-target.qcow2", mode=0o400)
    _owned(overlay, workspace / CHECKPOINT_DIR, OVERLAY_NAME, mode=0o600)
    _owned(nvram, workspace, "ovmf-variables.fd")
    require(ovmf_code.is_file() and not ovmf_code.is_symlink()
            and ovmf_code.stat().st_size > 500_000,
            "trusted OVMF code unavailable")
    before_base = _sha(base)
    before_overlay = _sha(overlay)
    before_nvram = _sha(nvram)
    before_base_identity = qcow2_file_identity(base)
    image_info = _run(["qemu-img", "info", "-f", "qcow2",
                       "--output=json", str(overlay)])
    require(image_info.returncode == 0, "owned overlay metadata unavailable")
    import json
    try:
        metadata = json.loads(image_info.stdout)
    except ValueError as error:
        raise InstalledReadOnlyBootError("invalid owned QCOW2 metadata") from error
    require(metadata.get("format") == "qcow2"
            and metadata.get("virtual-size") == VIRTUAL_BYTES
            and metadata.get("backing-filename") == str(base)
            and metadata.get("backing-filename-format") == "qcow2",
            "read-only boot disk does not have the signed Windows COW backing")
    cfg = workspace / "cachyos-installed-readonly-boot.cfg"
    require(not cfg.exists() and not cfg.is_symlink(),
            "refusing to reuse EFI boot configuration")
    cfg.write_text(installed_poweroff_grub_config(root_uuid), encoding="ascii")
    check = _run(["grub-script-check", str(cfg)], timeout=30)
    require(check.returncode == 0, "installed-root GRUB configuration invalid")
    loader = workspace / "cachyos-installed-readonly-bootx64.efi"
    result = _run(["grub-mkstandalone", "--format=x86_64-efi",
                   "--output=" + str(loader),
                   "boot/grub/grub.cfg=" + str(cfg)], timeout=180)
    require(result.returncode == 0 and loader.is_file()
            and not loader.is_symlink(),
            "could not build isolated installed-root loader")
    boot_efi = workspace / "cachyos-installed-readonly-efi.raw"
    _write_lab_image(boot_efi, 96 * 1024**2, "GASLUXRO", "vfat")
    for directory in ("::/EFI", "::/EFI/BOOT"):
        created = _run(["mmd", "-i", str(boot_efi), directory])
        require(created.returncode == 0, "cannot make private EFI loader directory")
    _copy_to_fat(boot_efi, loader, "EFI/BOOT/BOOTX64.EFI")
    before_efi = _sha(boot_efi)
    trial_vars = workspace / "cachyos-installed-readonly-vars.fd"
    _copy_fresh_ovmf_vars(Path(OVMF_VARS), trial_vars)
    serial = workspace / "cachyos-installed-readonly-serial.log"
    stderr = workspace / "cachyos-installed-readonly-qemu-stderr.log"
    require(all(not path.exists() and not path.is_symlink()
                for path in (serial, stderr)),
            "refusing to reuse read-only installed-root serial evidence")
    require(Path("/dev/urandom").is_char_device(),
            "hosted QEMU entropy device is unavailable")
    cmd = [
        "qemu-system-x86_64",
        "-machine", "q35,accel=kvm,smm=on",
        "-global", "driver=cfi.pflash01,property=secure,value=on",
        "-cpu", "host", "-smp", "2", "-m", "4096",
        "-display", "none", "-monitor", "none",
        "-no-reboot", "-net", "none",
        "-drive", "if=pflash,format=raw,readonly=on,file=" + str(ovmf_code),
        "-drive", "if=pflash,format=raw,file=" + str(trial_vars),
        "-object", "rng-random,id=gasluxrng0,filename=/dev/urandom",
        "-device", "virtio-rng-pci,rng=gasluxrng0",
        "-device", "qemu-xhci",
        "-drive", "if=none,id=installedefi,format=raw,file=" +
            str(boot_efi) + ",readonly=on",
        "-device", "usb-storage,drive=installedefi,bootindex=1",
        "-drive", "if=none,id=installedroot,format=qcow2,file=" +
            str(overlay) + ",readonly=on",
        "-device", "usb-storage,drive=installedroot,bootindex=2",
        "-serial", "file:" + str(serial),
    ]
    with stderr.open("xb") as err:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=err)
        try:
            proc.wait(timeout=600)
        except subprocess.TimeoutExpired as error:
            proc.kill()
            proc.wait(timeout=30)
            raise InstalledReadOnlyBootError(
                "read-only installed CachyOS did not power off within timeout") from error
    require(proc.returncode == 0, "installed-readonly guest did not power off cleanly")
    require(serial.is_file() and not serial.is_symlink(), "missing installed-root serial")
    verify_installed_poweroff_serial(serial.read_bytes(), root_uuid)
    require(_sha(overlay) == before_overlay and
            _sha(base) == before_base and
            qcow2_file_identity(base) == before_base_identity and
            _sha(nvram) == before_nvram and
            _sha(boot_efi) == before_efi,
            "read-only installed boot modified Windows COW, baseline, EFI or NVRAM")
    return {
        "minimalInstalledReadOnlyBootVerified": True,
        "installedReadOnlyBootWindowsCOWUnchanged": True,
        "installedReadOnlyBootWindowsNVRAMUnchanged": True,
        "installedReadOnlyBootEFIUnchanged": True,
        "installedReadOnlyBootSerialSha256": _sha(serial),
        "installedReadOnlyGrubSha256": _sha(cfg),
        "installedReadOnlyBootloaderInstalledToWindowsESP": False,
        "firstBootWithWritableSystemVerified": False,
        "sameDiskDualBootVerified": False,
        "updatesVerified": False,
        "productionStorageWritesAuthorized": False,
    }


if __name__ == "__main__":
    raise SystemExit("Library only: requires the separately validated Windows laboratory COW.")
