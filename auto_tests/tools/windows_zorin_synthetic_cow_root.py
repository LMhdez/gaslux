#!/usr/bin/env python3
"""Genuine Zorin 18.1 root -> fifth ext4 of a synthetic Windows-shaped COW.

VM-only evidence. No installed Windows, production GRUB, or host block device.
All writable media are new regular files within a GitHub-hosted runner workspace.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

from windows_cachyos_overlay_ext4_only import VIRTUAL_BYTES, WINDOW_BYTES, format_only_fifth
from windows_mint_overlay_root import (
    _import_tar_into_exact_owned_root,
    prepare_mint_storage_initramfs_modules,
    verify_mint_storage_initramfs,
)

ZORIN_SHA256 = "44649b97bd307fc4c8529205d098ebbf98575a1e1ba2ee7d7005b697af1721d5"
ZORIN_BYTES = 3909091328
ZORIN_URL = "https://mirrors.univ-reims.fr/IMAGES/zorinos/18/Zorin-OS-18.1-Core-64-bit.iso"
CONSENT = "I_ACCEPT_ZORIN_ROOT_ON_SYNTHETIC_HOSTED_COW_ONLY"


class ZorinSyntheticError(RuntimeError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ZorinSyntheticError(reason)


def cmd(*args: str, timeout: int = 180, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args), check=True, timeout=timeout, text=True,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE if capture else None,
    )


def sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def ensure_hosted_only() -> Path:
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("RUNNER_TEMP") == "/home/runner/work/_temp"
        and os.environ.get("GASLUX_ZORIN_SYNTHETIC_COW_CONSENT") == CONSENT
        and os.geteuid() != 0,
        "explicit Zorin synthetic-COW GitHub-hosted consent required",
    )
    return Path("/home/runner/work/_temp")


def verify_official_zorin(iso: Path) -> None:
    import json
    catalog = json.loads(Path("release-config.json").read_text(encoding="utf-8"))
    matches = [d for d in catalog["distributions"] if d["id"] == "zorin"]
    require(len(matches) == 1, "missing or duplicate Zorin catalog ID")
    record = matches[0]
    require(
        record["name"] == "Zorin OS 18.1 Core"
        and record["osReleaseId"] == "zorin"
        and record["isoInstallerSha256"] == ZORIN_SHA256
        and record["isoInstallerSizeBytes"] == ZORIN_BYTES
        and record["isoInstaller"] == ZORIN_URL,
        "unexpected Zorin official release metadata",
    )
    require(
        iso.is_file() and not iso.is_symlink()
        and iso.stat().st_nlink == 1 and iso.stat().st_size == ZORIN_BYTES
        and sha256(iso) == ZORIN_SHA256,
        "Zorin 18.1 ISO is unverified or has changed",
    )


def inspect_fifth(overlay: Path, expected_uuid: str, windows_hashes: list[str]) -> None:
    """Independently re-read disk/partition hashes without opening it writable."""
    import guestfs
    guest = guestfs.GuestFS(python_return_dict=True)
    try:
        guest.add_drive_opts(str(overlay), format="qcow2", readonly=1)
        guest.launch()
        devices = guest.list_devices()
        require(len(devices) == 1, "ambiguous synthetic COW disk")
        disk = devices[0]
        suffix = "p" if disk[-1].isdigit() else ""
        parts = [disk + suffix + str(i) for i in range(1, 6)]
        require(guest.blockdev_getsize64(disk) == VIRTUAL_BYTES
                and guest.list_partitions() == parts,
                "synthetic Windows GPT geometry changed")
        require(guest.blockdev_getsize64(parts[4]) == 24 * 1024**3
                and guest.vfs_type(parts[4]) == "ext4"
                and guest.vfs_uuid(parts[4]) == expected_uuid,
                "unowned or changed Zorin root partition")
        actual = [guest.checksum_device("sha256", p) for p in parts[:4]]
        require(actual == windows_hashes, "Windows-shaped partition bytes changed")
        guest.mount_ro(parts[4], "/")
        # Ubuntu-family media commonly use /etc/os-release as a symlink
        # into /usr/lib/os-release. libguestfs.is_file defaults to lstat
        # semantics, so the old check incorrectly rejected a valid root.
        # Follow links only inside the guest mount, and still require an
        # exact Zorin release ID in the resolved regular file.
        require(guest.is_file("/etc/os-release", followsymlinks=True)
                and re.search(r"(?m)^ID=zorin$", guest.cat("/etc/os-release")) is not None,
                "imported fifth root is not genuine Zorin")
        require(guest.is_file("/etc/fstab"), "installed root lacks fstab")
        require(guest.is_dir("/boot"), "installed root lacks kernel")
    finally:
        try:
            guest.shutdown()
        finally:
            guest.close()


def run_synthetic_zorin(iso: Path, evidence: Path) -> dict:
    runner = ensure_hosted_only()
    verify_official_zorin(iso)  # full pinned hash BEFORE allocating any writable disk
    require(shutil.disk_usage(runner).free > 22 * 1024**3,
            "insufficient private runner space for Zorin root import")
    require(evidence.parent == runner and not evidence.is_symlink(),
            "evidence destination is not the runner's private scratch")
    require(not evidence.exists(), "refusing pre-existing evidence directory")

    workspace = Path(tempfile.mkdtemp(prefix="gaslux-zorin-synthetic-cow-", dir=runner))
    require(workspace.parent == runner and not workspace.is_symlink()
            and stat.S_IMODE(workspace.stat().st_mode) == 0o700,
            "unsafe synthetic COW workspace")
    iso_mount = workspace / "iso"
    unpacked = workspace / "root"
    for directory in (iso_mount, unpacked):
        directory.mkdir(mode=0o700)
    mounted_iso = False
    chroot_paths: list[Path] = []
    try:
        cmd("sudo", "mount", "-t", "iso9660", "-o", "ro,loop,nosuid,nodev,noexec",
            str(iso), str(iso_mount))
        mounted_iso = True
        resolver = (
            'set -Eeuo pipefail; '
            'source assets/live/libertix-distribution-common.sh; '
            'source assets/live/libertix-install-runtime-common.sh; '
            'resolve_distribution_rootfs_or_die "$1"'
        )
        rootfs = Path(cmd("bash", "-c", resolver,
                          "gaslux-zorin-synthetic", str(iso_mount)).stdout.strip())
        require(rootfs.is_file() and not rootfs.is_symlink()
                and rootfs.is_relative_to(iso_mount),
                "Zorin ISO has no unique trusted SquashFS root")
        validator = (
            'set -Eeuo pipefail; '
            'source assets/live/libertix-distribution-common.sh; '
            'source assets/live/libertix-install-runtime-common.sh; '
            'assert_distribution_rootfs_compatible_or_die "$1" zorin'
        )
        cmd("bash", "-c", validator, "gaslux-zorin-identity", str(rootfs))
        cmd("sudo", "unsquashfs", "-f", "-processors", "2", "-d",
            str(unpacked), str(rootfs), timeout=1100, capture=False)
        cmd("sudo", "umount", str(iso_mount))
        mounted_iso = False
        backing = workspace / "synthetic-no-windows.raw"
        overlay = workspace / "synthetic-zorin-cow.qcow2"
        archive = workspace / "zorin-root.tar.gz"
        fd = os.open(backing, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            os.ftruncate(fd, VIRTUAL_BYTES)
        finally:
            os.close(fd)
        require(backing.is_file() and not backing.is_symlink()
                and backing.stat().st_nlink == 1,
                "unsafe synthetic backing")
        cmd(
            "sgdisk", "-n", "1:2048:+100M", "-t", "1:ef00",
            "-n", "2:0:+16M", "-t", "2:0c01",
            "-n", "3:0:+256M", "-t", "3:0700",
            "-n", "4:0:+128M", "-t", "4:2700",
            "-n", "5:0:+24G", "-t", "5:8300", str(backing), timeout=60,
        )
        cmd("sgdisk", "-v", str(backing))
        cmd("qemu-img", "create", "-f", "qcow2", "-F", "raw",
            "-b", str(backing), str(overlay))
        backing.chmod(0o400)
        overlay.chmod(0o600)
        backing_before = sha256_window(backing)
        require(json.loads(cmd("qemu-img", "info", "-f", "qcow2",
                               "--output=json", str(overlay)).stdout).get(
                                   "backing-filename") == str(backing),
                "wrong synthetic COW backing")

        import guestfs
        guest = guestfs.GuestFS(python_return_dict=True)
        try:
            guest.add_drive_opts(str(overlay), format="qcow2", readonly=0)
            guest.launch()
            devices = guest.list_devices()
            require(len(devices) == 1, "ambiguous guestfs disk")
            disk = devices[0]
            require(guest.blockdev_getsize64(disk) == VIRTUAL_BYTES,
                    "unexpected synthetic disk geometry")
            before_gpt = guest.pread_device(disk, WINDOW_BYTES, 0)
            after_gpt = guest.pread_device(disk, WINDOW_BYTES,
                                           VIRTUAL_BYTES - WINDOW_BYTES)
            formatted = format_only_fifth(guest, before_gpt, after_gpt)
            uuid = formatted["filesystemUuid"]
            windows_hashes = formatted["windowsFourPartitionSha256"]
            require(formatted["allFourWindowsPartitionSha256Unchanged"] is True
                    and formatted["gptMirrorsByteIdenticalAfterExt4"] is True,
                    "unverified fifth ext4 formatting")
        finally:
            try:
                guest.shutdown()
            finally:
                guest.close()

        os_release = cmd("sudo", "cat", str(unpacked / "etc/os-release")).stdout
        require(re.search(r"(?m)^ID=zorin$", os_release) is not None,
                "extracted installed root has incorrect ID")
        kernels = sorted((unpacked / "boot").glob("vmlinuz-*"))
        require(len(kernels) == 1, "Zorin installed kernel is missing or ambiguous")
        kernel = kernels[0]
        version = kernel.name.removeprefix("vmlinuz-")
        require(re.fullmatch(r"[A-Za-z0-9.+_-]+", version) is not None,
                "unsafe Zorin kernel version")
        require((unpacked / "lib/modules" / version).is_dir(),
                "Zorin installed kernel modules are absent")
        # Update only the runner-local extracted Zorin tree. No Windows partition
        # is mounted anywhere, even inside the synthetic libguestfs appliance.
        for check in (unpacked / "etc", unpacked / "etc/initramfs-tools"):
            require(check.is_dir() and not check.is_symlink(),
                    "unsafe extracted Zorin configuration directory")
        for name in ("fstab", "hostname"):
            require(not (unpacked / "etc" / name).is_symlink(),
                    "refusing symlink in Zorin target config")
        subprocess.run(
            ["sudo", "tee", str(unpacked / "etc/fstab")],
            input=f"UUID={uuid} / ext4 defaults 0 1\n", text=True,
            check=True, timeout=30, stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            ["sudo", "tee", str(unpacked / "etc/hostname")],
            input="GASLUXZORIN\n", text=True,
            check=True, timeout=30, stdout=subprocess.DEVNULL,
        )

        builtins = prepare_mint_storage_initramfs_modules(unpacked, version)
        for source, target in (
            (("sudo", "mount", "-t", "proc", "proc"), unpacked / "proc"),
            (("sudo", "mount", "--bind", "/dev"), unpacked / "dev"),
            (("sudo", "mount", "--bind", "/dev/pts"), unpacked / "dev/pts"),
        ):
            # Register before opening a mount; failed mounts are inspected
            # during cleanup, preventing recursive deletion into host devices.
            chroot_paths.append(target)
            cmd(*source, str(target), timeout=45)
        cmd("sudo", "chroot", str(unpacked), "/usr/bin/env", "-u",
            "CASPER_GENERATE_UUID", "update-initramfs", "-u", "-k", version,
            timeout=900, capture=False)
        initrd = unpacked / "boot" / f"initrd.img-{version}"
        require(initrd.is_file() and not initrd.is_symlink()
                and initrd.stat().st_size > 1024 * 1024,
                "Zorin native initramfs was not generated")
        listing = cmd("sudo", "chroot", str(unpacked), "lsinitramfs",
                      f"/boot/initrd.img-{version}", timeout=120).stdout
        verify_mint_storage_initramfs(listing, builtins)
        require("default-boot-to-casper.conf" not in listing,
                "native Zorin initramfs still boots Casper")
        for path in reversed(chroot_paths):
            cmd("sudo", "umount", str(path), timeout=90)
        chroot_paths.clear()

        require(not archive.exists() and not archive.is_symlink(),
                "refusing reused private Zorin root archive")
        cmd("sudo", "tar", "--numeric-owner", "--xattrs", "--acls",
            "-C", str(unpacked), "-czf", str(archive), ".",
            timeout=1800, capture=False)
        cmd("sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(archive))
        archive.chmod(0o600)
        require(archive.is_file() and archive.stat().st_size > 1024 * 1024,
                "Zorin tar payload invalid")
        # Reuse the existing libguestfs importer from the Mint experiment.
        # It checks root UUID and hashes of all four other partitions before
        # opening any writable mount, and again after completing tar_in.
        _import_tar_into_exact_owned_root(overlay, archive, uuid, windows_hashes)
        archive.unlink()

        inspect_fifth(overlay, uuid, windows_hashes)
        require(sha256_window(backing) == backing_before,
                "immutable synthetic backing changed during Zorin import")
        report = {
            "source": "authentic-zorin-18.1-core-squashfs",
            "isoSha256": ZORIN_SHA256,
            "installedKernel": kernel.name,
            "installedRootUuid": uuid,
            "rootImportedIntoOwnedFifthExt4": True,
            "syntheticWindowsShapedPartitionsUnchanged": True,
            "syntheticWindowsPartitionSha256": windows_hashes,
            "syntheticBackingSampleSha256": backing_before,
            "installedZorinFirstBootVerified": False,
            "realWindowsInstalledInBacking": False,
            "sameDiskDualBootVerified": False,
            "productionGrubVerified": False,
            "updatesVerified": False,
            "rollbackVerified": False,
            "stable": False,
        }
        evidence.mkdir(mode=0o700)
        (evidence / "zorin-synthetic-cow-import.json").write_text(
            json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        print("PASS: genuine pinned Zorin 18.1 root imported into owned fifth ext4; "
              "four synthetic Windows-shaped partition hashes preserved", flush=True)
        print("NOT TESTED: installed Windows, boot, GRUB, updates, rollback", flush=True)
        return report
    finally:
        for path in reversed(chroot_paths):
            subprocess.run(["sudo", "umount", str(path)], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if mounted_iso:
            subprocess.run(["sudo", "umount", str(iso_mount)], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        mounts = subprocess.run(
            ["findmnt", "-rn", "-o", "TARGET"],
            check=False, capture_output=True, text=True, timeout=20,
        )
        active = (
            mounts.stdout.splitlines() if mounts.returncode == 0
            else [str(workspace)]
        )
        busy = any(path == str(workspace) or path.startswith(str(workspace) + "/")
                   for path in active)
        if busy:
            raise ZorinSyntheticError(
                "active mount or mount-table failure: preserve private Zorin workspace"
            )
        require(workspace.parent == runner and not workspace.is_symlink(),
                "unsafe private cleanup scope")
        subprocess.run(["sudo", "rm", "-rf", "--one-file-system", "--", str(workspace)],
                       check=True, timeout=90)


def sha256_window(backing: Path) -> str:
    with backing.open("rb") as handle:
        return hashlib.sha256(handle.read(4 * 1024 * 1024)).hexdigest()


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        raise SystemExit("Usage: windows_zorin_synthetic_cow_root.py ISO EVIDENCE_DIR")
    run_synthetic_zorin(Path(sys.argv[1]), Path(sys.argv[2]))
