#!/usr/bin/env python3
"""Stage the pinned Mint SquashFS root in partition 5 of the disposable Win10 COW.

CI-only. The Windows QCOW2 base and Windows partitions are never mounted RW.
Linux is booted from the same QCOW2 via QEMU direct-kernel handoff; this is
NOT proof of the production GRUB/ESP dual-boot menu.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import tempfile
import time

MINT_SHA256 = "a081ab202cfda17f6924128dbd2de8b63518ac0531bcfe3f1a1b88097c459bd4"
MINT_BYTES = 3091660800
MINT_URL = "https://pub.linuxmint.io/stable/22.3/linuxmint-22.3-cinnamon-64bit.iso"
CONSENT = "I_ACCEPT_MINT_ROOT_ON_HOSTED_WINDOWS10_COW_FIFTH_PARTITION"


class MintOverlayError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MintOverlayError(message)


def run(args: list[str], *, timeout: int = 120, capture: bool = True):
    return subprocess.run(
        args, check=True, text=True, capture_output=capture, timeout=timeout,
    )


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_target_configuration(target: Path, root_uuid: str) -> None:
    import uuid

    try:
        canonical_uuid = str(uuid.UUID(root_uuid))
    except (ValueError, AttributeError, TypeError) as exc:
        raise MintOverlayError("invalid Mint root filesystem UUID") from exc
    require(target.is_dir() and not target.is_symlink(),
            "Mint target mount is not a real directory")
    etc = target / "etc"
    require(etc.is_dir() and not etc.is_symlink(),
            "Mint target /etc is missing or unsafe")
    subprocess.run(
        ["sudo", "tee", str(etc / "fstab")],
        input=f"UUID={canonical_uuid} / ext4 defaults 0 1\n",
        check=True, text=True, stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["sudo", "tee", str(etc / "hostname")],
        input="GASLUXMINT\n", check=True, text=True,
        stdout=subprocess.DEVNULL,
    )


def guestmount_command(overlay: Path, target: Path) -> list[str]:
    """Mount the stopped COW through FUSE for the runner with kernel permission checks."""
    return [
        "sudo", "guestmount", "-a", str(overlay), "-m", "/dev/sda5",
        "--rw", "-o", "allow_other", "-o", "default_permissions", str(target),
    ]



def guestfish_copy_in_command(overlay: Path, source: Path) -> list[str]:
    """Transfer a root tree through libguestfs, not per-file FUSE syscalls."""
    return [
        "sudo", "guestfish", "--rw", "-a", str(overlay), "-m", "/dev/sda5",
        "copy-in", str(source) + "/.", "/",
    ]


def _guest_disk_audit(overlay: Path, expected_uuid: str | None = None):
    import guestfs

    guest = guestfs.GuestFS(python_return_dict=True)
    try:
        guest.add_drive_opts(str(overlay), format="qcow2", readonly=1)
        guest.launch()
        devices = guest.list_devices()
        require(len(devices) == 1, "ambiguous COW guest disk")
        dev = devices[0]
        require(guest.blockdev_getsize64(dev) == 128 * 1024**3,
                "unexpected Windows QCOW2 virtual size")
        suffix = "p" if dev[-1].isdigit() else ""
        parts = [dev + suffix + str(i) for i in range(1, 6)]
        require(guest.list_partitions() == parts,
                "Windows COW must contain exactly four Windows partitions and root #5")
        require(guest.blockdev_getsize64(parts[4]) == 24 * 1024**3,
                "partition #5 is not the transaction-owned 24-GiB extent")
        require(guest.vfs_type(parts[4]) == "ext4",
                "partition #5 is not ext4")
        root_uuid = guest.vfs_uuid(parts[4])
        require(bool(root_uuid) and (expected_uuid is None or root_uuid == expected_uuid),
                "Mint root UUID differs from the authenticated ext4 checkpoint")
        windows_hashes = [guest.checksum_device("sha256", part) for part in parts[:4]]
        require(len(windows_hashes) == 4 and all(len(x) == 64 for x in windows_hashes),
                "cannot checksum all four Windows partitions")
        return root_uuid, windows_hashes
    finally:
        try:
            guest.shutdown()
        finally:
            guest.close()


def install_mint_root_and_boot(
    *, overlay: Path, base: Path, nvram: Path, workspace: Path,
    ext4_proof: dict, iso: Path, evidence: Path,
) -> dict:
    """Copy Mint SquashFS to exact #5, build initramfs and direct-kernel boot it."""
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
            and os.environ.get("RUNNER_TEMP") == "/home/runner/work/_temp"
            and os.environ.get("GASLUX_MINT_COW_CONSENT") == CONSENT,
            "Mint-on-Windows-COW requires dedicated hosted-runner consent")
    require(workspace.is_dir() and not workspace.is_symlink()
            and workspace.resolve() == workspace
            and workspace.stat().st_uid == os.getuid()
            and stat.S_IMODE(workspace.stat().st_mode) == 0o700,
            "Windows VM workspace is not private and runner-owned")
    from windows_cachyos_cow_checkpoint import (
        CHECKPOINT_DIR, OVERLAY_NAME, validate_workspace, sha256_file,
        owned_regular,
    )
    from windows_cachyos_qcow2_gpt_readonly import qcow2_file_identity, require_unchanged_qcow2
    validate_workspace(base, nvram)
    checkpoint = base.parent / CHECKPOINT_DIR
    require(overlay == checkpoint / OVERLAY_NAME
            and checkpoint.is_dir() and not checkpoint.is_symlink()
            and stat.S_IMODE(checkpoint.stat().st_mode) == 0o700,
            "unexpected Windows COW checkpoint identity")
    owned_regular(overlay, checkpoint, OVERLAY_NAME)
    require(stat.S_IMODE(overlay.stat().st_mode) == 0o600,
            "Windows COW overlay permissions are unsafe")
    info = json.loads(run([
        "qemu-img", "info", "-f", "qcow2", "--output=json", str(overlay),
    ]).stdout)
    require(info.get("format") == "qcow2"
            and info.get("virtual-size") == 128 * 1024**3
            and info.get("backing-filename") == str(base)
            and info.get("backing-filename-format") == "qcow2"
            and not info.get("encrypted", False),
            "COW overlay is not bound to the exact Windows QCOW2")
    require(base.is_file() and not base.is_symlink()
            and stat.S_IMODE(base.stat().st_mode) == 0o400,
            "Windows QCOW2 backing must remain immutable")
    require(iso.is_file() and not iso.is_symlink()
            and iso.stat().st_size == MINT_BYTES
            and sha256(iso) == MINT_SHA256,
            "Mint ISO size or SHA-256 mismatch")
    require(type(ext4_proof) is dict
            and ext4_proof.get("onlyOwnedOverlayFifthPartitionFormatted") is True
            and ext4_proof.get("linuxRootFilesystemFormatted") is True
            and ext4_proof.get("windowsBackingQcow2UnchangedAfterExt4") is True
            and ext4_proof.get("sameDiskDualBootVerified") is False,
            "missing exact fifth-partition ext4 proof")
    expected_uuid = ext4_proof["rootFilesystem"]["filesystemUuid"]
    root_uuid, windows_before = _guest_disk_audit(overlay, expected_uuid)
    require(windows_before == ext4_proof["rootFilesystem"]["windowsFourPartitionSha256"],
            "Windows partition hashes differ from the pre-Mint ext4 checkpoint")
    base_identity = qcow2_file_identity(base)
    base_hash = sha256_file(base)
    nvram_hash = sha256_file(nvram)
    vars_baseline = checkpoint / "windows-ovmf-baseline.fd"
    vars_trial = checkpoint / "trial-ovmf-variables.fd"
    owned_regular(vars_baseline, checkpoint, vars_baseline.name)
    owned_regular(vars_trial, checkpoint, vars_trial.name)
    require(stat.S_IMODE(vars_baseline.stat().st_mode) == 0o400
            and stat.S_IMODE(vars_trial.stat().st_mode) == 0o600
            and sha256_file(vars_baseline) == nvram_hash,
            "Windows OVMF baseline or trial VARS ownership/hash mismatch")
    trial_vars_hash = sha256_file(vars_trial)
    require(base_hash and nvram_hash, "missing Windows baseline hashes")

    temp = Path(tempfile.mkdtemp(prefix="gaslux-mint-cow-", dir=workspace))
    iso_mount = temp / "iso"
    target = temp / "target"
    iso_mount.mkdir(mode=0o700)
    target.mkdir(mode=0o700)
    guest_mounted = False
    iso_mounted = False
    try:
        run(["sudo", "mount", "-o", "loop,ro,nosuid,nodev,noexec", str(iso), str(iso_mount)])
        iso_mounted = True
        resolver = (
            "source assets/live/libertix-distribution-common.sh; "
            "source assets/live/libertix-install-runtime-common.sh; "
            "resolve_distribution_rootfs_or_die \"$1\""
        )
        rootfs = Path(run(["bash", "-c", resolver, "gaslux-mint-root", str(iso_mount)]).stdout.strip())
        require(rootfs.is_file() and not rootfs.is_symlink(), "Mint SquashFS root is missing")
        validator = (
            "source assets/live/libertix-distribution-common.sh; "
            "source assets/live/libertix-install-runtime-common.sh; "
            "assert_distribution_rootfs_compatible_or_die \"$1\" linuxmint"
        )
        run(["bash", "-c", validator, "gaslux-mint-identity", str(rootfs)])
        unpacked = temp / "unpacked"
        unpacked.mkdir(mode=0o700)
        run(["sudo", "unsquashfs", "-f", "-processors", "2", "-d", str(unpacked), str(rootfs)],
            timeout=900, capture=False)
        # libguestfs copy-in streams a tar transfer into the ext4 guest directly.
        # Copying ~323k SquashFS entries through guestmount/FUSE incurred 20m
        # timeouts on hosted runners; keep FUSE only for chroot bind mounts.
        run(guestfish_copy_in_command(overlay, unpacked), timeout=1800, capture=False)
        run(guestmount_command(overlay, target), timeout=120)
        guest_mounted = True
        os_release = unpacked / "etc/os-release"
        require(os_release.is_file() and "ID=linuxmint" in os_release.read_text(),
                "extracted source is not Linux Mint")
        target_os_release = target / "etc/os-release"
        require(target_os_release.is_file()
                and "ID=linuxmint" in target_os_release.read_text(),
                "libguestfs transfer did not populate Mint root at ext4 /")
        kernels = sorted((unpacked / "boot").glob("vmlinuz-*"))
        require(len(kernels) == 1, "Mint target must contain one unambiguous kernel")
        kernel = kernels[0]
        version = kernel.name.removeprefix("vmlinuz-")
        require((unpacked / "lib/modules" / version).is_dir(),
                "Mint target kernel modules are missing")
        write_target_configuration(target, root_uuid)
        run(["sudo", "mount", "--bind", "/dev", str(target / "dev")])
        run(["sudo", "mount", "-t", "proc", "proc", str(target / "proc")])
        run(["sudo", "mount", "-t", "sysfs", "sysfs", str(target / "sys")])
        run(["sudo", "mount", "--bind", "/dev/pts", str(target / "dev/pts")])
        try:
            run(["sudo", "chroot", str(target), "/usr/bin/env", "-u",
                 "CASPER_GENERATE_UUID", "update-initramfs", "-u", "-k", version],
                timeout=600)
            initrd = target / "boot" / f"initrd.img-{version}"
            require(initrd.is_file() and initrd.stat().st_size > 1024 * 1024,
                    "Mint initramfs was not generated")
            listing = run(["sudo", "chroot", str(target), "lsinitramfs",
                           f"/boot/initrd.img-{version}"], timeout=120).stdout
            require("virtio_blk" in listing or "virtio/virtio_blk" in listing,
                    "Mint initramfs lacks virtio block support")
            require("conf/conf.d/default-boot-to-casper.conf" not in listing,
                    "Mint initramfs still redirects to Casper")
        finally:
            for path in (target / "dev/pts", target / "dev", target / "sys", target / "proc"):
                subprocess.run(["sudo", "umount", str(path)], check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        kernel_copy = temp / "vmlinuz"
        initrd_copy = temp / "initrd.img"
        run(["sudo", "cp", str(kernel), str(kernel_copy)])
        run(["sudo", "cp", str(initrd), str(initrd_copy)])
        run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(kernel_copy), str(initrd_copy)])
        kernel_copy.chmod(0o644)
        initrd_copy.chmod(0o644)
        run(["sudo", "guestunmount", str(target)], timeout=120)
        guest_mounted = False
        run(["sudo", "umount", str(iso_mount)], timeout=60)
        iso_mounted = False
        root_uuid_after_copy, windows_after_copy = _guest_disk_audit(overlay, expected_uuid)
        require(root_uuid_after_copy == root_uuid and windows_after_copy == windows_before,
                "Mint extraction changed Windows partitions or ext4 identity")

        serial = evidence / "mint-same-windows-cow-serial.log"
        require(not serial.exists() and not serial.is_symlink(),
                "refusing reused Mint boot evidence")
        monitor = temp / "mint-qemu-monitor.sock"
        require(not monitor.exists() and not monitor.is_symlink(),
                "refusing reused Mint QEMU monitor socket")
        qemu = subprocess.Popen([
            "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host",
            "-smp", "2", "-m", "4096", "-display", "none",
            "-monitor", f"unix:{monitor},server,nowait",
            "-net", "none", "-no-reboot", "-drive",
            f"if=none,id=windows-cow,format=qcow2,file={overlay}",
            "-device", "virtio-blk-pci,drive=windows-cow,bootindex=1",
            "-kernel", str(kernel_copy), "-initrd", str(initrd_copy),
            "-append", f"root=UUID={root_uuid} rw rootwait console=ttyS0,115200n8 "
                       "systemd.unit=multi-user.target "
                       "systemd.wants=serial-getty@ttyS0.service",
            "-serial", f"file:{serial}", "-boot", "order=c,menu=off",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 420
            while time.monotonic() < deadline:
                if serial.is_file():
                    raw = serial.read_bytes()
                    if b"GASLUXMINT login:" in raw and b"Linux version" in raw:
                        break
                if qemu.poll() is not None:
                    raise MintOverlayError("QEMU stopped before Mint installed-root login")
                time.sleep(3)
            else:
                raise MintOverlayError("Mint same-COW firstboot timed out")
            monitor_deadline = time.monotonic() + 30
            channel = None
            while time.monotonic() < monitor_deadline:
                if monitor.exists() and monitor.is_socket():
                    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    channel.connect(str(monitor))
                    break
                time.sleep(0.5)
            require(channel is not None, "Mint QEMU monitor did not become available")
            try:
                channel.recv(4096)
                channel.sendall(b"system_powerdown\n")
            finally:
                channel.close()
            try:
                qemu.wait(timeout=90)
            except subprocess.TimeoutExpired as exc:
                raise MintOverlayError("Mint guest did not complete ACPI poweroff") from exc
            require(qemu.returncode == 0, "Mint QEMU did not exit cleanly after guest poweroff")
            shutdown_log = serial.read_bytes()
            require(b"systemd-shutdown" in shutdown_log or b"Powering off" in shutdown_log,
                    "Mint guest did not emit a shutdown witness")
        finally:
            if qemu.poll() is None:
                qemu.terminate()
            try:
                qemu.wait(timeout=20)
            except subprocess.TimeoutExpired:
                qemu.kill()
                qemu.wait(timeout=10)
        require(serial.is_file() and b"GASLUXMINT login:" in serial.read_bytes(),
                "missing genuine Mint serial login witness")
        root_uuid_after, windows_after_boot = _guest_disk_audit(overlay, expected_uuid)
        require(root_uuid_after == root_uuid and windows_after_boot == windows_before,
                "Mint Linux boot changed Windows partitions or root UUID")
        require_unchanged_qcow2(base, base_identity)
        require(sha256_file(base) == base_hash and sha256_file(nvram) == nvram_hash
                and sha256_file(vars_baseline) == nvram_hash
                and sha256_file(vars_trial) == trial_vars_hash,
                "Windows backing QCOW2 or OVMF baseline/trial VARS changed")
        serial_hash = sha256(serial)
        proof = {
            "mintIsoSha256": MINT_SHA256,
            "mintIsoBytes": MINT_BYTES,
            "mintRootUuid": root_uuid,
            "mintKernel": kernel.name,
            "mintSquashfsRootCopiedToWindowsCOWPartition5": True,
            "mintFirstBootFromSameWindowsCOWVerified": True,
            "windowsFourPartitionSha256Unchanged": True,
            "windowsPartitionSha256": windows_before,
            "windowsBackingQcow2Unchanged": True,
            "windowsBackingQcow2Sha256": base_hash,
            "windowsOriginalNvramUnchanged": True,
            "windowsOriginalNvramSha256": nvram_hash,
            "windowsOvmfTrialVarsSha256": trial_vars_hash,
            "mintSerialSha256": serial_hash,
            "nativeGrubDualBootVerified": False,
            "sameDiskDualBootVerified": False,
            "updatesVerified": False,
            "rollbackVerified": False,
            "releaseEligible": False,
        }
        proof_path = evidence / "mint-same-windows-cow.json"
        require(not proof_path.exists() and not proof_path.is_symlink(),
                "refusing reused Mint COW proof")
        proof_path.write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n")
        (evidence / "mint-same-windows-cow-serial.sha256").write_text(
            f"{serial_hash}  {serial.name}\n", encoding="ascii")
        return proof
    finally:
        if guest_mounted:
            result = subprocess.run(["sudo", "guestunmount", str(target)],
                                    check=False, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            guest_mounted = result.returncode != 0
        if iso_mounted:
            result = subprocess.run(["sudo", "umount", str(iso_mount)],
                                    check=False, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            iso_mounted = result.returncode != 0
        mounts = subprocess.run(["findmnt", "-rn", "-o", "TARGET"],
                                check=False, capture_output=True, text=True)
        active = set(mounts.stdout.splitlines()) if mounts.returncode == 0 else {str(target), str(iso_mount)}
        nested_active = any(path == str(target) or path.startswith(str(target) + "/")
                            or path == str(iso_mount) or path.startswith(str(iso_mount) + "/")
                            for path in active)
        if not guest_mounted and not iso_mounted and not nested_active:
            subprocess.run(["sudo", "rm", "-rf", "--one-file-system", "--", str(temp)],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            print("WARNING: preserving Mint COW workspace because a mount remains active")
