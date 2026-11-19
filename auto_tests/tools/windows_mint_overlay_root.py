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
import re
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


def configure_lab_power_button(target: Path) -> None:
    """Make the disposable Mint guest's ACPI power-button policy explicit."""
    etc = target / "etc"
    systemd = etc / "systemd"
    require(etc.is_dir() and not etc.is_symlink()
            and systemd.is_dir() and not systemd.is_symlink(),
            "Mint systemd configuration directory is missing or unsafe")
    dropins = systemd / "logind.conf.d"
    if dropins.exists() or dropins.is_symlink():
        require(dropins.is_dir() and not dropins.is_symlink(),
                "Mint logind drop-in directory is unsafe")
    else:
        subprocess.run(
            ["sudo", "install", "-d", "-m", "0755", str(dropins)],
            check=True, text=True, stdout=subprocess.DEVNULL,
        )
    config = dropins / "90-gaslux-lab-power-button.conf"
    require(not config.is_symlink() and (not config.exists() or config.is_file()),
            "Mint logind power-button drop-in is not a regular file")
    content = "[Login]\\nHandlePowerKey=poweroff\\nHandlePowerKeyLongPress=poweroff\\n"
    subprocess.run(
        ["sudo", "tee", str(config)], input=content, check=True, text=True,
        stdout=subprocess.DEVNULL,
    )
    require(config.is_file() and not config.is_symlink()
            and config.read_text(encoding="utf-8") == content,
            "Mint logind power-button policy was not written exactly")


def configure_ephemeral_shutdown_service(target: Path) -> None:
    """Install a one-boot shutdown witness in the disposable CI-only COW root."""
    require(target.is_dir() and not target.is_symlink(),
            "Mint target mount is not a real directory")
    system_dir = target / "etc/systemd/system"
    wants_dir = system_dir / "multi-user.target.wants"
    unit = system_dir / "gaslux-ci-shutdown.service"
    link = wants_dir / "gaslux-ci-shutdown.service"
    require(system_dir.is_dir() and not system_dir.is_symlink(),
            "Mint systemd unit directory is missing or unsafe")
    require(not unit.exists() and not unit.is_symlink()
            and not link.exists() and not link.is_symlink(),
            "refusing to replace an existing Mint shutdown unit")
    subprocess.run(["sudo", "install", "-d", "-m", "0755", str(wants_dir)],
                   check=True, text=True, capture_output=True, timeout=30)
    contents = (
        "[Unit]\n"
        "Description=Gaslux disposable COW shutdown witness\n"
        "After=serial-getty@ttyS0.service\n"
        "Wants=serial-getty@ttyS0.service\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStartPre=/bin/sleep 15\n"
        "ExecStart=/bin/systemctl poweroff\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    subprocess.run(["sudo", "tee", str(unit)], input=contents, check=True,
                   text=True, stdout=subprocess.DEVNULL, timeout=30)
    subprocess.run(["sudo", "ln", "-s", "../gaslux-ci-shutdown.service", str(link)],
                   check=True, text=True, capture_output=True, timeout=30)
    require(unit.is_file() and not unit.is_symlink()
            and unit.read_text(encoding="utf-8") == contents
            and link.is_symlink()
            and link.readlink() == Path("../gaslux-ci-shutdown.service"),
            "ephemeral Mint shutdown witness was not installed exactly")


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

def guestfish_download_command(overlay: Path, guest_path: str, destination: Path) -> list[str]:
    """Download one guest file through read-only libguestfs, outside FUSE."""
    return [
        "sudo", "guestfish", "--ro", "-a", str(overlay), "-m", "/dev/sda5",
        "download", guest_path, str(destination),
    ]


def unmount_private_tree(mountpoint: Path) -> None:
    """Unmount one private chroot mount and all nested mounts, without lazy detach."""
    require(mountpoint.is_absolute() and not mountpoint.is_symlink(),
            "refusing unsafe chroot mount cleanup path")
    path = str(mountpoint)
    result = subprocess.run(
        ["sudo", "umount", "--recursive", path],
        check=False, text=True, capture_output=True, timeout=90,
    )
    mounts = subprocess.run(
        ["sudo", "findmnt", "-rn", "-o", "TARGET"],
        check=False, text=True, capture_output=True, timeout=30,
    )
    remaining = [
        line.strip() for line in mounts.stdout.splitlines()
        if line.strip() == path or line.strip().startswith(path + "/")
    ]
    if result.returncode != 0 or mounts.returncode != 0 or remaining:
        holders = subprocess.run(
            ["sudo", "fuser", "-vm", path],
            check=False, text=True, capture_output=True, timeout=30,
        )
        detail = (result.stderr or result.stdout or "").strip()
        holder_detail = (holders.stderr or holders.stdout or "").strip()
        raise MintOverlayError(
            f"chroot mount tree remains busy at {path}; "
            f"umount_rc={result.returncode}; findmnt_rc={mounts.returncode}; "
            f"remaining={remaining!r}; umount={detail}; holders={holder_detail}"
        )


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


def _kernel_module_names(modules_root: Path, version: str) -> tuple[set[str], set[str]]:
    """Return built-in and loadable module names from the exact Mint kernel tree."""
    root = modules_root / version
    require(root.is_dir() and not root.is_symlink(),
            "Mint kernel module directory is missing or unsafe")
    builtin_file = root / "modules.builtin"
    dep_file = root / "modules.dep"
    for metadata in (builtin_file, dep_file):
        require(metadata.is_file() and not metadata.is_symlink(),
                f"Mint kernel metadata is missing or unsafe: {metadata.name}")

    def module_name(value: str) -> str | None:
        name = Path(value).name
        match = re.fullmatch(r"(.+)\.ko(?:\.(?:xz|zst|gz))?", name)
        return match.group(1).replace("-", "_") if match else None

    builtins = {
        name for line in builtin_file.read_text(encoding="utf-8").splitlines()
        if (name := module_name(line.strip()))
    }
    loadable = {
        name for line in dep_file.read_text(encoding="utf-8").splitlines()
        if (name := module_name(line.partition(":")[0].strip()))
    }
    return builtins, loadable


def prepare_initramfs_modules(target: Path, version: str) -> tuple[set[str], set[str]]:
    """Require storage drivers and explicitly request loadable ones in initramfs."""
    builtins, loadable = _kernel_module_names(target / "lib/modules", version)
    required = {"virtio_pci", "virtio_blk", "ext4"}
    missing = sorted(required - builtins - loadable)
    require(not missing,
            "Mint kernel lacks required initramfs drivers: " + ", ".join(missing))

    etc = target / "etc"
    config_dir = etc / "initramfs-tools"
    config = config_dir / "modules"
    require(etc.is_dir() and not etc.is_symlink()
            and config_dir.is_dir() and not config_dir.is_symlink(),
            "Mint initramfs-tools configuration directory is missing or unsafe")
    if config.exists() or config.is_symlink():
        require(not config.is_symlink() and config.is_file(),
                "Mint initramfs modules configuration is not a regular file")
        original = config.read_text(encoding="utf-8")
    else:
        original = ""
    present = {
        line.split()[0] for line in original.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    additions = sorted(required - builtins - present)
    if additions:
        updated = original
        if updated and not updated.endswith("\n"):
            updated += "\n"
        updated += "".join(f"{name}\n" for name in additions)
        subprocess.run(
            ["sudo", "tee", str(config)], input=updated, check=True, text=True,
            stdout=subprocess.DEVNULL,
        )
    actual = config.read_text(encoding="utf-8")
    actual_modules = {
        line.split()[0] for line in actual.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    require(required <= builtins | actual_modules,
            "Mint initramfs modules configuration omitted a required driver")
    return builtins, loadable


def validate_initramfs_driver_support(
    modules_root: Path, version: str, listing: str,
) -> None:
    """Accept built-ins or verify each loadable storage driver is in the initramfs."""
    builtins, loadable = _kernel_module_names(modules_root, version)
    required = {"virtio_pci", "virtio_blk", "ext4"}
    require(required <= builtins | loadable,
            "Mint kernel lacks required virtio/ext4 driver capability")
    for name in sorted(required - builtins):
        pattern = re.compile(
            rf"(?:^|/){re.escape(name)}\.ko(?:\.(?:xz|zst|gz))?$"
        )
        require(any(pattern.search(line.strip()) for line in listing.splitlines()),
                f"Mint initramfs lacks loadable {name} driver")


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
        prepare_initramfs_modules(target, version)
        write_target_configuration(target, root_uuid)
        configure_ephemeral_shutdown_service(target)
        configure_lab_power_button(target)
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
        finally:
            # Reverse the mount dependency order. Recursive unmount handles
            # nested sysfs/procfs mounts created by initramfs tooling; lazy detach
            # is deliberately forbidden because it would hide live references.
            for bind_mount in (target / "dev/pts", target / "sys", target / "proc", target / "dev"):
                unmount_private_tree(bind_mount)
        # Release FUSE before reading large boot artifacts. guestfish downloads
        # directly from ext4 to runner-local storage, avoiding slow initramfs
        # traversal through the mounted guest filesystem. If guestunmount cannot
        # talk to its daemon, try the standard FUSE unmount once and verify that
        # the mount is actually gone; never continue with a live guestmount.
        try:
            run(["sudo", "guestunmount", str(target)], timeout=120)
        except subprocess.CalledProcessError as exc:
            fallback = subprocess.run(
                ["sudo", "fusermount3", "-u", str(target)],
                check=False, text=True, capture_output=True, timeout=60,
            )
            mounted = subprocess.run(
                ["sudo", "findmnt", "-rn", "--mountpoint", str(target)],
                check=False, text=True, capture_output=True, timeout=30,
            )
            if fallback.returncode != 0 or mounted.stdout.strip():
                detail = (fallback.stderr or fallback.stdout or "").strip()
                raise MintOverlayError(
                    "guestmount FUSE could not be safely unmounted; "
                    f"guestunmount exit={exc.returncode}; "
                    f"fusermount3 exit={fallback.returncode}; "
                    f"remaining mount={mounted.stdout.strip()!r}; {detail}"
                ) from exc
        guest_mounted = False
        kernel_copy = temp / "vmlinuz"
        initrd_copy = temp / "initrd.img"
        run(guestfish_download_command(overlay, f"/boot/{kernel.name}", kernel_copy),
            timeout=300)
        run(guestfish_download_command(overlay, f"/boot/initrd.img-{version}", initrd_copy),
            timeout=600)
        run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(kernel_copy), str(initrd_copy)])
        kernel_copy.chmod(0o644)
        initrd_copy.chmod(0o644)
        require(kernel_copy.is_file() and kernel_copy.stat().st_size > 1024 * 1024,
                "Mint kernel download from ext4 failed")
        require(initrd_copy.is_file() and initrd_copy.stat().st_size > 1024 * 1024,
                "Mint initramfs download from ext4 failed")
        listing = run(["lsinitramfs", str(initrd_copy)], timeout=600).stdout
        validate_initramfs_driver_support(unpacked / "lib/modules", version, listing)
        require("conf/conf.d/default-boot-to-casper.conf" not in listing,
                "Mint initramfs still redirects to Casper")
        run(["sudo", "umount", str(iso_mount)], timeout=60)
        iso_mounted = False
        root_uuid_after_copy, windows_after_copy = _guest_disk_audit(overlay, expected_uuid)
        require(root_uuid_after_copy == root_uuid and windows_after_copy == windows_before,
                "Mint extraction changed Windows partitions or ext4 identity")

        serial = evidence / "mint-same-windows-cow-serial.log"
        require(not serial.exists() and not serial.is_symlink(),
                "refusing reused Mint boot evidence")
        qemu = subprocess.Popen([
            "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host",
            "-smp", "2", "-m", "4096", "-display", "none",
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
                    raise MintOverlayError("QEMU stopped before Mint live-root serial login")
                time.sleep(3)
            else:
                raise MintOverlayError("Mint same-COW firstboot timed out")
            try:
                qemu.wait(timeout=120)
            except subprocess.TimeoutExpired as exc:
                raise MintOverlayError(
                    "ephemeral systemd shutdown witness did not power off the Mint guest"
                ) from exc
            require(qemu.returncode == 0, "Mint QEMU did not exit cleanly after systemd poweroff")
            shutdown_log = serial.read_bytes()
            require(b"systemd-shutdown" in shutdown_log or b"Powering off" in shutdown_log,
                    "Mint guest did not emit a systemd shutdown witness")
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
