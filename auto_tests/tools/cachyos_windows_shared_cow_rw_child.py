#!/usr/bin/env python3
"""Lab-only writable installed CachyOS boot on a DISCARDABLE CHILD QCOW2.

The Windows baseline and the already installed Linux/Windows COW are immutable
backings, never QEMU writable drives. QEMU receives exactly one private child
overlay as writable block storage, a fresh OVMF variables file, and a private
read-only EFI launcher. After a kernel/systemd firstboot, verify GPT, protected
Windows files, native fifth-root marker, source hashes, and discard the child.

This does NOT establish a usable login or native Windows ESP bootloader.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from cachyos_windows_shared_archiso_handoff import VIRTUAL_BYTES
from cachyos_windows_shared_cow_firstboot import (
    canonical_root_uuid, installed_poweroff_grub_config,
)
from cachyos_windows_shared_root_pacstrap_host import (
    _copy_fresh_ovmf_vars, _copy_to_fat, _owned, _run, _sha, require,
    _write_lab_image,
)
from windows_cachyos_cow_checkpoint import CHECKPOINT_DIR, OVERLAY_NAME
from windows_cachyos_overlay_reboot import gpt_windows
from windows_cachyos_qcow2_gpt_readonly import qcow2_file_identity
from cachyos_windows_archiso_signed_plan_lab import read_windows_file_hashes
from windows_x64_qemu_host_gate import OVMF_VARS

CONSENT = "I_ACCEPT_CHILD_QCOW2_WRITABLE_CACHYOS_FIRSTBOOT_VM_ONLY"
CHILD_NAME = "cachyos-installed-rw-private-child.qcow2"
MAX_SERIAL_BYTES = 2 * 1024 * 1024


class ChildCOWBootError(ValueError):
    """A disposable child-only writable root experiment did not pass."""


def check(ok: bool, message: str) -> None:
    if not ok:
        raise ChildCOWBootError(message)


def _run_checked(argv: list[str], *, timeout: int = 120) -> str:
    result = _run(argv, timeout=timeout)
    check(result.returncode == 0, "lab command failed: " + argv[0])
    return result.stdout


def writable_boot_grub(root_uuid: str) -> str:
    root_uuid = canonical_root_uuid(root_uuid)
    cfg = installed_poweroff_grub_config(root_uuid)
    old = (
        " ro console=ttyS0,115200n8 loglevel=6"
        " systemd.unit=poweroff.target systemd.show_status=yes"
    )
    check(cfg.count(old) == 1, "base read-only launcher changed")
    return cfg.replace(
        old,
        " rw console=ttyS0,115200n8 loglevel=6"
        " systemd.unit=multi-user.target systemd.show_status=yes",
    ).replace(
        "GASLUX_VM_INSTALLED_ROOT_UUID_SELECTED:",
        "GASLUX_VM_INSTALLED_RW_ROOT_UUID_SELECTED:",
    )


def installed_rw_service(run_id: str, root_uuid: str) -> tuple[bytes, bytes]:
    root_uuid = canonical_root_uuid(root_uuid)
    check(re.fullmatch(r"[a-z0-9-]{12,80}", run_id) is not None,
          "invalid run ID for writable guest proof")
    script = r"""#!/usr/bin/bash
set -Eeuo pipefail
run_id='__RUN_ID__'
root_uuid='__ROOT_UUID__'
[[ "$(cat /proc/1/comm)" == systemd ]]
[[ "$(cat /.gaslux-lab-root-owner)" == "$run_id" ]]
grep -Fxq 'ID=cachyos' /etc/os-release
root_device="$(findmnt -nr -o SOURCE --target /)"
[[ -b "$root_device" ]]
[[ "$(blkid -s UUID -o value "$root_device")" == "$root_uuid" ]]
[[ "$(findmnt -nr -o FSTYPE --target /)" == ext4 ]]
options="$(findmnt -nr -o OPTIONS --target /)"
[[ ",$options," == *,rw,* ]]
cmdline="$(cat /proc/cmdline)"
[[ " $cmdline " == *" root=UUID=$root_uuid "* ]]
[[ " $cmdline " == *" rw "* ]]
[[ " $cmdline " != *" ro "* ]]
[[ " $cmdline " == *" systemd.unit=multi-user.target "* ]]
[[ "$(cat /etc/hostname)" == gaslux-cachyos-lab ]]
grep -Fxq 'LANG=en_US.UTF-8' /etc/locale.conf
grep -Fxq 'KEYMAP=us' /etc/vconsole.conf
[[ "$(readlink /etc/localtime)" == /usr/share/zoneinfo/UTC ]]
getent passwd gaslux-lab | grep -Fq ':/home/gaslux-lab:/bin/bash'
id -nG gaslux-lab | tr ' ' '\n' | grep -Fxq wheel
grep -Fq 'gaslux-lab:' /etc/shadow
grep -Fq '%wheel ALL=(ALL:ALL) ALL' /etc/sudoers.d/10-gaslux-wheel
systemctl is-enabled --quiet sddm.service
systemctl is-enabled --quiet NetworkManager.service
systemctl is-enabled --quiet systemd-timesyncd.service
pacman -Q plasma-desktop >/dev/null
pacman -Q dolphin >/dev/null
pacman -Q konsole >/dev/null
install -d -m 0700 /var/lib/gaslux-lab
echo "GASLUX_VM_INSTALLED_CONFIGURED_DESKTOP_ACCOUNT_PASS:$run_id:$root_uuid"
first=/var/lib/gaslux-lab/child-rw-firstboot
second=/var/lib/gaslux-lab/child-rw-secondboot
if [[ -e "$first" || -L "$first" ]]; then
  [[ -f "$first" && ! -L "$first" && ! -e "$second" && ! -L "$second" ]]
  [[ "$(cat "$first")" == "$run_id" ]]
  printf '%s\n' "$run_id" > "$second"
  chmod 0600 "$second"
  sync
  echo "GASLUX_VM_INSTALLED_RW_CHILD_SECONDBOOT_PASS:$run_id:$root_uuid"
else
  [[ ! -e "$second" && ! -L "$second" ]]
  printf '%s\n' "$run_id" > "$first"
  chmod 0600 "$first"
  sync
  echo "GASLUX_VM_INSTALLED_RW_CHILD_FIRSTBOOT_PASS:$run_id:$root_uuid"
fi
"""
    script = script.replace("__RUN_ID__", run_id).replace("__ROOT_UUID__", root_uuid)
    unit = """[Unit]
Description=Gaslux ephemeral VM-only writable CachyOS root witness
After=local-fs.target
RequiresMountsFor=/var/lib/gaslux-lab
ConditionPathExists=/.gaslux-lab-root-owner

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/gaslux-rw-child-proof
ExecStartPost=/usr/bin/systemctl --no-block poweroff
TimeoutStartSec=90
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
"""
    return script.encode("ascii"), unit.encode("ascii")

def verify_rw_serial(data: bytes, run_id: str, root_uuid: str, *, second_boot: bool = False) -> None:
    root_uuid = canonical_root_uuid(root_uuid)
    check(re.fullmatch(r"[a-z0-9-]{12,80}", run_id) is not None,
          "invalid run ID")
    check(0 < len(data) <= MAX_SERIAL_BYTES, "missing/oversized RW COM1")
    check(data.count(("GASLUX_VM_INSTALLED_RW_ROOT_UUID_SELECTED:" +
                      root_uuid).encode("ascii")) == 1,
          "private EFI did not select the owned ext4")
    check(re.search(
        rb"\[\s*[0-9]+\.[0-9]+\]\s+Linux version "
        rb"[0-9][^\r\n]{0,110}cachyos(?:-lts)?\b", data,
    ) is not None, "installed native CachyOS kernel absent")
    lines = re.findall(
        rb"\[\s*[0-9]+\.[0-9]+\]\s+Kernel command line: ([^\r\n]{1,700})",
        data,
    )
    check(len(lines) == 1, "kernel command line missing/ambiguous")
    args = lines[0].split()
    check(args.count(b"root=UUID=" + root_uuid.encode("ascii")) == 1
          and len([p for p in args if p.startswith(b"root=")]) == 1
          and args.count(b"rw") == 1 and b"ro" not in args
          and args.count(b"systemd.unit=multi-user.target") == 1,
          "unexpected signed RW kernel command line")
    switch = data.find(b"Switch Root")
    welcome = re.search(rb"Welcome to[^\r\n]{0,160}CachyOS", data)
    marker = ("GASLUX_VM_INSTALLED_RW_CHILD_SECONDBOOT_PASS:"
              if second_boot else "GASLUX_VM_INSTALLED_RW_CHILD_FIRSTBOOT_PASS:")
    proof = (marker + run_id + ":" + root_uuid).encode("ascii")
    other = ("GASLUX_VM_INSTALLED_RW_CHILD_FIRSTBOOT_PASS:"
             if second_boot else "GASLUX_VM_INSTALLED_RW_CHILD_SECONDBOOT_PASS:")
    configured_proof = (
        "GASLUX_VM_INSTALLED_CONFIGURED_DESKTOP_ACCOUNT_PASS:"
        + run_id + ":" + root_uuid
    ).encode("ascii")
    check(switch >= 0 and welcome is not None and
          switch < welcome.start() and
          data.count(configured_proof) == 1
          and welcome.start() < data.find(configured_proof)
          and data.count(proof) == 1 and welcome.start() < data.find(proof)
          and other.encode("ascii") not in data,
          "RW proof is absent, duplicated or not from the installed root")
    check(b"System Power Off" in data and
          (b"Powering off." in data or b"reboot: Power down" in data),
          "installed RW system did not shut down cleanly")
    for marker in (b"Kernel panic", b"GASLUX_VM_INSTALLED_ROOT_KERNEL_MISSING",
                   b"GASLUX_VM_INSTALLED_ROOT_INITRD_MISSING", b"FAILED:"):
        check(marker not in data, "fatal installed RW kernel/systemd marker")


def _own_child(child: Path, workspace: Path) -> None:
    _owned(child, workspace, CHILD_NAME, mode=0o600)


def _stage_service(child: Path, root_uuid: str, run_id: str) -> None:
    import guestfs
    script, unit = installed_rw_service(run_id, root_uuid)
    g = guestfs.GuestFS(python_return_dict=True)
    try:
        g.add_drive_opts(str(child), format="qcow2", readonly=0)
        g.launch()
        disks = g.list_devices()
        check(len(disks) == 1 and g.blockdev_getsize64(disks[0]) == VIRTUAL_BYTES,
              "untrusted child QCOW2 disk/size")
        parts = g.list_partitions()
        check(len(parts) == 5, "child no longer has Windows plus fifth GPT")
        fifth = parts[4]
        check(g.vfs_type(fifth) == "ext4"
              and g.vfs_uuid(fifth).lower() == root_uuid
              and g.blockdev_getsize64(fifth) == 24 * 1024**3,
              "child fifth ext4 identity/geometry differs")
        g.mount(fifth, "/")
        try:
            check(g.read_file("/.gaslux-lab-root-owner").decode("ascii").strip()
                  == run_id, "child ext4 belongs to different transaction")
            check(g.is_file("/boot/vmlinuz-linux-cachyos-lts") and
                  g.is_file("/boot/initramfs-linux-cachyos-lts.img"),
                  "child lacks the authenticated installed kernel")
            service_path = "/etc/systemd/system/gaslux-rw-child-proof.service"
            script_path = "/usr/local/libexec/gaslux-rw-child-proof"
            link_path = (
                "/etc/systemd/system/multi-user.target.wants/"
                "gaslux-rw-child-proof.service"
            )
            check(not g.exists(service_path) and not g.exists(script_path)
                  and not g.exists(link_path) and
                  not g.exists("/var/lib/gaslux-lab/child-rw-firstboot"),
                  "foreign or previously used writable firstboot service")
            g.mkdir_p("/usr/local/libexec")
            g.mkdir_p("/etc/systemd/system/multi-user.target.wants")
            g.write(script_path, script)
            g.chmod(0o700, script_path)
            g.write(service_path, unit)
            g.chmod(0o644, service_path)
            g.ln_s(service_path, link_path)
            check(g.read_file(script_path) == script and
                  g.read_file(service_path) == unit,
                  "child RW witness service content changed")
            g.sync()
        finally:
            g.umount_all()
    finally:
        try:
            g.shutdown()
        finally:
            g.close()


def _read_child_marker(child: Path, root_uuid: str, run_id: str, *, second_boot: bool = False) -> None:
    import guestfs
    g = guestfs.GuestFS(python_return_dict=True)
    try:
        g.add_drive_opts(str(child), format="qcow2", readonly=1)
        g.launch()
        parts = g.list_partitions()
        check(len(parts) == 5 and
              g.vfs_type(parts[4]) == "ext4" and
              g.vfs_uuid(parts[4]).lower() == root_uuid,
              "child installed root identity changed during RW boot")
        state = g.tune2fs_l(parts[4])
        check(isinstance(state, dict)
              and state.get("Filesystem state") == "clean",
              "RW child root ext4 was not cleanly shut down")
        g.mount_ro(parts[4], "/")
        try:
            check(g.read_file("/var/lib/gaslux-lab/child-rw-firstboot")
                  == (run_id + "\n").encode("ascii"),
                  "guest did not write the exact owner-bound first-boot marker")
            if second_boot:
                check(g.read_file("/var/lib/gaslux-lab/child-rw-secondboot")
                      == (run_id + "\n").encode("ascii"),
                      "second boot did not persist its owner-bound marker")
            else:
                check(not g.exists("/var/lib/gaslux-lab/child-rw-secondboot"),
                      "second-boot marker unexpectedly exists before second boot")
        finally:
            g.umount_all()
    finally:
        try:
            g.shutdown()
        finally:
            g.close()


def probe_owned_rw_child(*, overlay: Path, base: Path, nvram: Path,
                         ovmf_code: Path, workspace: Path, plan: dict,
                         run_id: str) -> dict[str, object]:
    """RW in CHILD only. Never exposes production disks, nor modifies parent COW."""
    check(os.environ.get("GITHUB_ACTIONS") == "true"
          and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
          and os.environ.get("RUNNER_OS") == "Linux"
          and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
          and os.environ.get("GASLUX_CACHYOS_RW_CHILD_CONSENT") == CONSENT,
          "RW boot allowed only with explicit hosted private-child lab consent")
    check(type(plan) is dict and plan.get("labOnly") is True
          and plan.get("writeAuthority") is False
          and plan.get("runId") == run_id
          and isinstance(run_id, str)
          and re.fullmatch(r"[a-z0-9-]{12,80}", run_id) is not None,
          "missing signed parent-COW lab transaction")
    root_uuid = canonical_root_uuid(plan.get("rootFsUuid"))
    check(workspace.is_absolute() and workspace.is_dir()
          and not workspace.is_symlink()
          and workspace.name.startswith("gaslux-win-x64-")
          and workspace.parent == Path(os.environ.get("RUNNER_TEMP", ""))
          and stat.S_IMODE(workspace.stat().st_mode) == 0o700,
          "RW child not inside hosted private workspace")
    check(base.parent == workspace and
          overlay.parent == workspace / CHECKPOINT_DIR and
          nvram.parent == workspace, "RW child parent disks differ from trial")
    _owned(base, workspace, "only-disposable-windows-target.qcow2", mode=0o400)
    _owned(overlay, workspace / CHECKPOINT_DIR, OVERLAY_NAME, mode=0o600)
    _owned(nvram, workspace, "ovmf-variables.fd")
    check(ovmf_code.is_file() and not ovmf_code.is_symlink(),
          "trusted OVMF code is absent")
    child = workspace / CHILD_NAME
    check(not child.exists() and not child.is_symlink(),
          "refusing reused/foreign writable child")
    old_base = _sha(base)
    old_parent = _sha(overlay)
    old_nvram = _sha(nvram)
    before_parent = qcow2_file_identity(overlay)
    before_base = qcow2_file_identity(base)
    check(before_parent is not None and before_base is not None,
          "missing parent/backing QCOW2 identities")
    cfg = workspace / "cachyos-installed-rw-child-grub.cfg"
    loader = workspace / "cachyos-installed-rw-child-bootx64.efi"
    efi = workspace / "cachyos-installed-rw-child-efi.raw"
    trial_vars = workspace / "cachyos-installed-rw-child-vars.fd"
    serial = workspace / "cachyos-installed-rw-child-serial.log"
    stderr = workspace / "cachyos-installed-rw-child-stderr.log"
    check(all(not p.exists() and not p.is_symlink()
              for p in (cfg, loader, efi, trial_vars, serial, stderr)),
          "private RW child EFI/serial evidence already exists")
    try:
        _run_checked(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                      "-b", str(overlay), str(child)], timeout=60)
        os.chmod(child, 0o600)
        _own_child(child, workspace)
        raw_info = _run_checked(["qemu-img", "info", "-f", "qcow2",
                                 "--output=json", str(child)], timeout=45)
        info = json.loads(raw_info)
        check(info.get("format") == "qcow2"
              and info.get("virtual-size") == VIRTUAL_BYTES
              and info.get("backing-filename") == str(overlay)
              and info.get("backing-filename-format") == "qcow2",
              "RW child backing is not EXACT previously approved Windows COW")
        _stage_service(child, root_uuid, run_id)
        cfg.write_text(writable_boot_grub(root_uuid), encoding="ascii")
        _run_checked(["grub-script-check", str(cfg)], timeout=30)
        _run_checked([
            "grub-mkstandalone", "--format=x86_64-efi",
            "--output=" + str(loader),
            "boot/grub/grub.cfg=" + str(cfg),
        ], timeout=180)
        check(loader.is_file() and not loader.is_symlink(),
              "owned RW EFI loader generation failed")
        _write_lab_image(efi, 96 * 1024**2, "GASLUXRW", "vfat")
        _run_checked(["mmd", "-i", str(efi), "::/EFI"])
        _run_checked(["mmd", "-i", str(efi), "::/EFI/BOOT"])
        _copy_to_fat(efi, loader, "EFI/BOOT/BOOTX64.EFI")
        old_efi = _sha(efi)
        _copy_fresh_ovmf_vars(Path(OVMF_VARS), trial_vars)
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
            "-drive", "if=none,id=rwtrialefi,format=raw,file=" +
                str(efi) + ",readonly=on",
            "-device", "usb-storage,drive=rwtrialefi,bootindex=1",
            # ONLY this short-lived private child may be QEMU writable.
            "-drive", "if=none,id=rwchild,format=qcow2,file=" + str(child),
            "-device", "usb-storage,drive=rwchild,bootindex=2",
            "-serial", "file:" + str(serial),
        ]
        with stderr.open("xb") as err:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=err,
            )
            try:
                proc.wait(timeout=600)
            except subprocess.TimeoutExpired as error:
                proc.kill()
                proc.wait(timeout=30)
                raise ChildCOWBootError("installed RW child failed to power off") from error
        check(proc.returncode == 0, "installed RW child QEMU did not exit cleanly")
        check(serial.is_file() and not serial.is_symlink(),
              "missing RW child native serial witness")
        verify_rw_serial(serial.read_bytes(), run_id, root_uuid)
        _read_child_marker(child, root_uuid, run_id)
        # Persisted second boot on the SAME child QCOW2. No new volume,
        # ISO, ESP write, or change to the signed Windows/Linux parent.
        # The service must recognise the *first* marker and create a second
        # transaction-bound marker; repeated first-boot output is rejected.
        second_serial = workspace / "cachyos-installed-rw-child-second-serial.log"
        second_stderr = workspace / "cachyos-installed-rw-child-second-stderr.log"
        check(not second_serial.exists() and not second_serial.is_symlink()
              and not second_stderr.exists() and not second_stderr.is_symlink(),
              "second boot evidence already exists")
        second_cmd = list(cmd)
        second_cmd[second_cmd.index("file:" + str(serial))] = (
            "file:" + str(second_serial))
        with second_stderr.open("xb") as err:
            proc2 = subprocess.Popen(
                second_cmd, stdout=subprocess.DEVNULL, stderr=err)
            try:
                proc2.wait(timeout=600)
            except subprocess.TimeoutExpired as error:
                proc2.kill()
                proc2.wait(timeout=30)
                raise ChildCOWBootError(
                    "second RW child boot did not power off") from error
        check(proc2.returncode == 0,
              "second installed RW child QEMU did not exit cleanly")
        check(second_serial.is_file() and not second_serial.is_symlink(),
              "second RW child native serial missing")
        verify_rw_serial(second_serial.read_bytes(), run_id, root_uuid,
                         second_boot=True)
        _read_child_marker(child, root_uuid, run_id, second_boot=True)
        qcow = _run_checked(["qemu-img", "check", "-f", "qcow2", str(child)],
                            timeout=300)
        check("No errors were found" in qcow, "RW child QCOW2 is not consistent")
        with tempfile.TemporaryDirectory(
            prefix="gaslux-child-windows-gpt-", dir=workspace
        ) as tmp:
            front, back = gpt_windows(child, Path(tmp))
        check(hashlib.sha256(front + back).hexdigest() ==
              plan["gptWindowsSha256"],
              "Windows GPT changed in private RW child")
        check(read_windows_file_hashes(child) == plan["windowsHashes"],
              "Windows ESP/BCD/WinRE files changed in RW child")
        check(_sha(base) == old_base and _sha(overlay) == old_parent
              and _sha(nvram) == old_nvram and _sha(efi) == old_efi
              and qcow2_file_identity(overlay) == before_parent
              and qcow2_file_identity(base) == before_base,
              "RW child modified backing Windows/Linux COW, EFI or Windows NVRAM")
        result = {
            "installedWritableChildRunId": run_id,
            "installedWritableChildKernelAndSystemdBootVerified": True,
            "installedWritableChildNativeRootMarkerVerified": True,
            "installedWritableChildSecondBootVerified": True,
            "installedWritableChildSecondBootPersistentMarkerVerified": True,
            "installedWritableChildSecondSerialSha256": _sha(second_serial),
            "installedWritableChildWindowsGptUnchanged": True,
            "installedWritableChildWindowsProtectedHashesUnchanged": True,
            "installedWritableChildParentCOWUnchanged": True,
            "installedWritableChildBaseWindowsUnchanged": True,
            "installedWritableChildSerialSha256": _sha(serial),
            "installedWritableChildEFIUnchanged": True,
            "installedWritableChildOverlayDiscarded": False,
            "installedReadOnlyBootloaderInstalledToWindowsESP": False,
            "firstBootWithWritableSystemVerified": False,
            "sameDiskDualBootVerified": False,
            "productionStorageWritesAuthorized": False,
            "releaseEligible": False,
        }
    finally:
        # A dedicated rollback of the child only. Never discard the signed
        # parent Linux installation or the immutable Windows baseline here.
        if child.exists() or child.is_symlink():
            _own_child(child, workspace)
            child.unlink()
        check(not child.exists(), "private writable experiment child survived")
        check(_sha(base) == old_base and _sha(overlay) == old_parent
              and _sha(nvram) == old_nvram,
              "Windows or signed Linux parent changed during child discard")
    result["installedWritableChildOverlayDiscarded"] = True
    return result


if __name__ == "__main__":
    raise SystemExit("VM-only module: requires signed Windows COW host transaction.")
