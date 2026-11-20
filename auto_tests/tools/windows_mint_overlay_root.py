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


def read_target_os_release(root: Path) -> str:
    """Resolve Ubuntu's /etc/os-release inside extracted root, never the host."""
    root = root.resolve(strict=True)
    path = root / "etc/os-release"
    for _ in range(8):
        # A relative os-release link may traverse an intermediate symlink
        # (e.g. usr -> another directory). Lexical containment is insufficient.
        # Resolve each parent BEFORE following the final component, and refuse
        # all host paths outside the owned extracted root.
        require(path.parent.resolve(strict=False).is_relative_to(root),
                "target OS release symlink parent escapes extracted root")
        if not path.is_symlink():
            require(path.resolve(strict=False).is_relative_to(root),
                    "target OS release symlink escapes extracted root")
            require(path.is_file() and path.is_relative_to(root),
                    "target OS release file is missing or escapes extracted root")
            return path.read_text(encoding="utf-8")
        link = Path(os.readlink(path))
        path = (root / link.relative_to("/") if link.is_absolute()
                else path.parent / link)
        path = Path(os.path.normpath(str(path)))
        require(path.is_relative_to(root),
                "target OS release symlink escapes extracted root")
    raise MintOverlayError("target OS release symlink chain is too long")


def write_target_configuration(target: Path, root_uuid: str,
                               hostname: str = "GASLUXMINT") -> None:
    require(hostname in ("GASLUXMINT", "GASLUXZORIN"),
            "unrecognized disposable Ubuntu guest hostname")
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
        input=hostname + "\n", check=True, text=True,
        stdout=subprocess.DEVNULL,
    )


def guestmount_command(overlay: Path, target: Path) -> list[str]:
    """Mount the stopped COW through FUSE for the runner with kernel permission checks."""
    return [
        "sudo", "guestmount", "-a", str(overlay), "-m", "/dev/sda5",
        "--rw", "-o", "allow_other", "-o", "default_permissions", str(target),
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


def _import_tar_into_exact_owned_root(
    overlay: Path, archive: Path, root_uuid: str, windows_hashes: list[str],
) -> None:
    """Write only an authenticated fifth ext4 root via libguestfs, never FUSE cp.

    Caller has verified the private Windows-backed COW path, its backing chain,
    signed media and the pre-existing ext4 checkpoint. All disk/partition/hash
    comparisons happen before guestfs mounts anything writable.
    """
    import guestfs

    require(archive.is_file() and not archive.is_symlink()
            and archive.stat().st_uid == os.getuid()
            and stat.S_IMODE(archive.stat().st_mode) == 0o600
            and archive.stat().st_size > 1024 * 1024,
            "private Mint target archive missing or unsafe")
    require(type(root_uuid) is str and len(root_uuid) == 36
            and type(windows_hashes) is list and len(windows_hashes) == 4
            and all(type(digest) is str and len(digest) == 64
                    and all(c in "0123456789abcdef" for c in digest)
                    for digest in windows_hashes),
            "Mint COW write grant lacks exact filesystem or Windows hashes")

    guest = guestfs.GuestFS(python_return_dict=True)
    try:
        guest.add_drive_opts(str(overlay), format="qcow2", readonly=0)
        guest.launch()
        devices = guest.list_devices()
        require(len(devices) == 1, "Mint archive import requires exactly one virtual disk")
        disk = devices[0]
        require(guest.blockdev_getsize64(disk) == 128 * 1024**3,
                "Mint archive import disk geometry changed")
        suffix = "p" if disk[-1].isdigit() else ""
        parts = [disk + suffix + str(i) for i in range(1, 6)]
        require(guest.list_partitions() == parts,
                "Mint archive import requires the exact five-partition Windows layout")
        require(guest.blockdev_getsize64(parts[4]) == 24 * 1024**3
                and guest.vfs_type(parts[4]) == "ext4"
                and guest.vfs_uuid(parts[4]) == root_uuid,
                "Mint archive import fifth ext4 ownership or UUID changed")
        require([guest.checksum_device("sha256", p) for p in parts[:4]]
                == windows_hashes,
                "Windows partition hashes changed before Mint archive import")

        # Never mount or write any Windows partition or the Windows ESP.
        guest.mount(parts[4], "/")
        guest.tar_in(str(archive), "/", compress="gzip", xattrs=True, acls=True)
        require(guest.vfs_uuid(parts[4]) == root_uuid,
                "Mint archive import changed the owned root UUID")
        require([guest.checksum_device("sha256", p) for p in parts[:4]]
                == windows_hashes,
                "Windows partitions changed during Mint archive import")
        guest.sync()
    finally:
        try:
            guest.shutdown()
        finally:
            guest.close()


def prepare_mint_storage_initramfs_modules(target: Path, version: str) -> set[str]:
    """Fail closed unless the trusted Mint kernel can boot virtio-blk ext4.

    The SquashFS extraction runs entirely in private runner storage. Rebuild
    the initramfs *before* opening a Windows-backed overlay for rootfs writes.
    Ubuntu initramfs-tools must explicitly include these drivers because an
    offline chroot cannot detect the future guest's virtio PCI block device.
    """
    import re

    require(re.fullmatch(r"[A-Za-z0-9.+_-]{1,128}", version) is not None,
            "unsafe Mint installed kernel version")
    modules_root = target / "lib" / "modules" / version
    require(modules_root.is_dir() and not modules_root.is_symlink(),
            "Mint installed target kernel modules missing or linked")
    builtin_manifest = modules_root / "modules.builtin"
    require(builtin_manifest.is_file() and not builtin_manifest.is_symlink(),
            "Mint installed kernel built-in module manifest missing")
    builtins = set(
        name.rsplit("/", 1)[-1].removesuffix(".ko")
        for name in builtin_manifest.read_text(encoding="utf-8").splitlines()
        if name.endswith(".ko")
    )
    required = ("virtio_pci", "virtio_blk", "ext4")
    for name in required:
        loadable = any(
            module.is_file() and not module.is_symlink()
            for module in modules_root.rglob(name + ".ko*")
        )
        require(loadable or name in builtins,
                f"Mint kernel is missing required storage driver: {name}")

    tools = target / "etc" / "initramfs-tools"
    module_list = tools / "modules"
    require(tools.is_dir() and not tools.is_symlink()
            and not module_list.is_symlink()
            and (not module_list.exists() or module_list.is_file()),
            "unsafe Mint initramfs-tools modules path")
    original = module_list.read_text(encoding="utf-8") if module_list.exists() else ""
    require(len(original) < 64 * 1024, "Mint initramfs-tools modules file is oversized")
    present = set(original.splitlines())
    missing = [name for name in required if name not in present]
    if missing:
        new_file = (original + ("\n" if original and not original.endswith("\n") else "")
                    + "\n".join(missing) + "\n")
        subprocess.run(
            ["sudo", "tee", str(module_list)],
            input=new_file, check=True, text=True, stdout=subprocess.DEVNULL,
        )
    return builtins


def verify_mint_storage_initramfs(listing: str, builtins: set[str]) -> None:
    """Assert drivers are present in the installed initramfs or kernel itself."""
    import re

    for name in ("virtio_pci", "virtio_blk", "ext4"):
        if name in builtins:
            continue
        pattern = re.compile(r"(^|/)" + re.escape(name)
                             + r"\.ko(?:\.[A-Za-z0-9]+)?$", re.MULTILINE)
        require(pattern.search(listing) is not None,
                f"Mint installed initramfs lacks required storage module: {name}")


def install_mint_root_and_boot(
    *, overlay: Path, base: Path, nvram: Path, workspace: Path,
    ext4_proof: dict, iso: Path, evidence: Path,
    distribution: str = "mint",
) -> dict:
    """Stage verified Ubuntu-family root on owned fifth COW; direct-kernel boot.

    Lab-only proof, not native GRUB, production installation or kernel update.
    The Mint default and shared fifth-partition importer are preserved.
    """
    require(distribution in ("mint", "zorin"),
            "unsupported Ubuntu-family disposable COW distribution")
    iso_sha = (MINT_SHA256 if distribution == "mint" else
               "44649b97bd307fc4c8529205d098ebbf98575a1e1ba2ee7d7005b697af1721d5")
    iso_bytes = MINT_BYTES if distribution == "mint" else 3909091328
    os_id = "linuxmint" if distribution == "mint" else "zorin"
    hostname = "GASLUXMINT" if distribution == "mint" else "GASLUXZORIN"
    login_witness = (hostname + " login:").encode("ascii")
    iso_url = (MINT_URL if distribution == "mint" else
               "https://mirrors.univ-reims.fr/IMAGES/zorinos/18/Zorin-OS-18.1-Core-64-bit.iso")
    consent_key = ("GASLUX_MINT_COW_CONSENT" if distribution == "mint" else
                   "GASLUX_ZORIN_WINDOWS_COW_CONSENT")
    consent_value = (CONSENT if distribution == "mint" else
                     "I_ACCEPT_ZORIN_ROOT_ON_VERIFIED_HOSTED_WINDOWS10_COW")
    catalog = json.loads(Path("release-config.json").read_text(encoding="utf-8"))
    matches = [entry for entry in catalog["distributions"]
               if entry.get("id") == distribution]
    require(len(matches) == 1 and matches[0].get("osReleaseId") == os_id
            and matches[0].get("isoInstallerSha256") == iso_sha
            and matches[0].get("isoInstallerSizeBytes") == iso_bytes
            and matches[0].get("isoInstaller") == iso_url,
            "Ubuntu-family ISO metadata differs from pinned catalog")
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
            and os.environ.get("RUNNER_TEMP") == "/home/runner/work/_temp"
            and os.environ.get(consent_key) == consent_value,
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
            and iso.stat().st_nlink == 1
            and iso.stat().st_size == iso_bytes
            and sha256(iso) == iso_sha,
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

    temp = Path(tempfile.mkdtemp(prefix=f"gaslux-{distribution}-cow-", dir=workspace))
    iso_mount = temp / "iso"
    target = temp / "target"
    iso_mount.mkdir(mode=0o700)
    target.mkdir(mode=0o700)
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
            f"assert_distribution_rootfs_compatible_or_die \"$1\" {os_id}"
        )
        run(["bash", "-c", validator, "gaslux-mint-identity", str(rootfs)])
        unpacked = temp / "unpacked"
        unpacked.mkdir(mode=0o700)
        run(["sudo", "unsquashfs", "-f", "-processors", "2", "-d", str(unpacked), str(rootfs)],
            timeout=900, capture=False)
        os_release_text = read_target_os_release(unpacked)
        require(re.search(rf"(?m)^ID={re.escape(os_id)}$",
                          os_release_text) is not None,
                "extracted target is not Linux Mint")
        kernels = sorted((unpacked / "boot").glob("vmlinuz-*"))
        require(len(kernels) == 1, "Mint target must contain one unambiguous kernel")
        kernel = kernels[0]
        version = kernel.name.removeprefix("vmlinuz-")
        require((unpacked / "lib/modules" / version).is_dir(),
                "Mint target kernel modules are missing")
        # Prepare the installed initramfs on the SHA-verified extracted root
        # before making any guest disk write. This is the proven Mint/Zorin
        # installed-root approach from PR #181, without slow host FUSE copies.
        write_target_configuration(unpacked, root_uuid, hostname)
        kernel_builtins = prepare_mint_storage_initramfs_modules(unpacked, version)
        chroot_mounts = [
            (["sudo", "mount", "-t", "proc", "proc", str(unpacked / "proc")],
             unpacked / "proc"),
            (["sudo", "mount", "--bind", "/dev", str(unpacked / "dev")],
             unpacked / "dev"),
            (["sudo", "mount", "--bind", "/dev/pts", str(unpacked / "dev/pts")],
             unpacked / "dev/pts"),
        ]
        try:
            for command, _ in chroot_mounts:
                run(command, timeout=60)
            run(["sudo", "chroot", str(unpacked), "/usr/bin/env", "-u",
                 "CASPER_GENERATE_UUID", "update-initramfs", "-u", "-k", version],
                timeout=600)
            initrd = unpacked / "boot" / f"initrd.img-{version}"
            require(initrd.is_file() and initrd.stat().st_size > 1024 * 1024,
                    "Mint initramfs was not generated")
            listing = run(["sudo", "chroot", str(unpacked), "lsinitramfs",
                           f"/boot/initrd.img-{version}"], timeout=120).stdout
            verify_mint_storage_initramfs(listing, kernel_builtins)
            require("conf/conf.d/default-boot-to-casper.conf" not in listing,
                    "Mint initramfs still redirects to Casper")
        finally:
            # Do not tar host /dev or proc into the guest, nor recursively
            # delete the workspace when any chroot mount survived a failure.
            for _, path in reversed(chroot_mounts):
                if subprocess.run(["findmnt", "-rn", "-M", str(path)],
                                  check=False, stdout=subprocess.DEVNULL).returncode == 0:
                    run(["sudo", "umount", str(path)], timeout=90)
            for _, path in chroot_mounts:
                require(subprocess.run(
                    ["findmnt", "-rn", "-M", str(path)], check=False,
                    stdout=subprocess.DEVNULL).returncode != 0,
                    "refusing rootfs import with host chroot filesystem still mounted")

        kernel_copy = temp / "vmlinuz"
        initrd_copy = temp / "initrd.img"
        run(["sudo", "cp", str(kernel), str(kernel_copy)])
        run(["sudo", "cp", str(initrd), str(initrd_copy)])
        run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}",
             str(kernel_copy), str(initrd_copy)])
        kernel_copy.chmod(0o644)
        initrd_copy.chmod(0o644)

        # Compress once on the local filesystem; libguestfs unpacks inside
        # its isolated appliance directly to the validated fifth ext4 root.
        # Preserve numeric ownership, extended attributes, and POSIX ACLs.
        archive = temp / f"{distribution}-root.tar.gz"
        require(not archive.exists() and not archive.is_symlink(),
                "refusing reused Mint root archive")
        run(["sudo", "tar", "--numeric-owner", "--xattrs", "--acls",
             "-C", str(unpacked), "-czf", str(archive), "."],
            timeout=900, capture=False)
        run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(archive)])
        archive.chmod(0o600)
        _import_tar_into_exact_owned_root(overlay, archive, root_uuid, windows_before)
        archive.unlink()
        run(["sudo", "umount", str(iso_mount)], timeout=60)
        iso_mounted = False
        root_uuid_after_copy, windows_after_copy = _guest_disk_audit(overlay, expected_uuid)
        require(root_uuid_after_copy == root_uuid and windows_after_copy == windows_before,
                "Mint extraction changed Windows partitions or ext4 identity")

        serial = evidence / f"{distribution}-same-windows-cow-serial.log"
        require(not serial.exists() and not serial.is_symlink(),
                "refusing reused Mint boot evidence")
        monitor = temp / f"{distribution}-qemu-monitor.sock"
        qmp_monitor = temp / f"{distribution}-qmp-monitor.sock"
        require(not monitor.exists() and not monitor.is_symlink(),
                "refusing reused Mint QEMU monitor socket")
        require(not qmp_monitor.exists() and not qmp_monitor.is_symlink(),
                "refusing reused Zorin QMP monitor socket")
        qemu = subprocess.Popen([
            "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host",
            "-smp", "2", "-m", "4096", "-display", "none",
            "-monitor", f"unix:{monitor},server,nowait",
            # QMP command acknowledgements and ACPI POWERDOWN events are
            # required for Zorin. The original HMP Mint path is unchanged.
            *(
                ["-qmp", f"unix:{qmp_monitor},server=on,wait=off"]
                if distribution == "zorin" else []
            ),
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
                    if login_witness in raw and b"Linux version" in raw:
                        break
                if qemu.poll() is not None:
                    raise MintOverlayError("QEMU stopped before Mint installed-root login")
                time.sleep(3)
            else:
                raise MintOverlayError("Mint same-COW firstboot timed out")
            if distribution == "zorin":
                # Historical HMP fire-and-forget had no command ACK or
                # POWERDOWN event witness. Do not diagnose guest ACPI until
                # the hypervisor confirms it actually delivered the request.
                from zorin_qmp_powerdown import request_guest_acpi_powerdown
                qmp_proof = request_guest_acpi_powerdown(
                    qmp_monitor, timeout_seconds=20)
                qmp_evidence = evidence / "zorin-qmp-powerdown-request.json"
                require(not qmp_evidence.exists() and not qmp_evidence.is_symlink(),
                        "refusing reused Zorin QMP powerdown evidence")
                with qmp_evidence.open("x", encoding="utf-8") as stream:
                    json.dump({
                        "qmpCommandAcknowledged":
                            qmp_proof["qmpCommandAcknowledged"],
                        "qmpPowerdownEventObserved":
                            qmp_proof["qmpPowerdownEventObserved"],
                        "orderlyGuestShutdownProven": False,
                        "requestType": "ACPI-system_powerdown",
                        "nativeBootloaderProven": False,
                    }, stream, sort_keys=True, indent=2)
                    stream.write("\n")
            else:
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
                raise MintOverlayError(
                    f"{distribution} guest did not complete ACPI poweroff"
                ) from exc
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
        require(serial.is_file() and login_witness in serial.read_bytes(),
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
            f"{distribution}IsoSha256": iso_sha,
            f"{distribution}IsoBytes": iso_bytes,
            f"{distribution}RootUuid": root_uuid,
            f"{distribution}Kernel": kernel.name,
            f"{distribution}SquashfsRootCopiedToWindowsCOWPartition5": True,
            f"{distribution}FirstBootFromSameWindowsCOWVerified": True,
            "windowsFourPartitionSha256Unchanged": True,
            "windowsPartitionSha256": windows_before,
            "windowsBackingQcow2Unchanged": True,
            "windowsBackingQcow2Sha256": base_hash,
            "windowsOriginalNvramUnchanged": True,
            "windowsOriginalNvramSha256": nvram_hash,
            "windowsOvmfTrialVarsSha256": trial_vars_hash,
            f"{distribution}SerialSha256": serial_hash,
            "nativeGrubDualBootVerified": False,
            "sameDiskDualBootVerified": False,
            "updatesVerified": False,
            "rollbackVerified": False,
            "releaseEligible": False,
        }
        proof_path = evidence / f"{distribution}-same-windows-cow.json"
        require(not proof_path.exists() and not proof_path.is_symlink(),
                "refusing reused Mint COW proof")
        proof_path.write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n")
        (evidence / f"{distribution}-same-windows-cow-serial.sha256").write_text(
            f"{serial_hash}  {serial.name}\n", encoding="ascii")
        return proof
    finally:
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
        if not iso_mounted and not nested_active:
            subprocess.run(["sudo", "rm", "-rf", "--one-file-system", "--", str(temp)],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            print("WARNING: preserving Mint COW workspace because a mount remains active")
