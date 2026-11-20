#!/usr/bin/env python3
"""Run real CachyOS Archiso pacstrap on Windows GPT #5 in a disposable COW.

This is a GitHub-hosted KVM integration test, not a production installer.
The immutable Windows QCOW2 is only the qcow2 backing file; QEMU receives
exactly one writable external overlay plus read-only ISO/control media.
Only the already formatted fifth ext4 partition is writable in the guest.
No ESP, Windows filesystem, GPT, NVRAM or physical host disk is a target.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from typing import Any

from cachyos_windows_shared_archiso_handoff import ISO_SHA256, SERIAL, VIRTUAL_BYTES
from windows_x64_qemu_host_gate import OVMF_VARS
from cachyos_windows_archiso_signed_plan_lab import prepare, read_windows_file_hashes
from cachyos_windows_shared_cow_grant import (
    CONSENT as GRANT_CONSENT, issue_root_write_grant,
)
from windows_cachyos_cow_checkpoint import (
    CHECKPOINT_DIR, OVERLAY_NAME, sha256_file,
)
from windows_cachyos_overlay_reboot import gpt_windows
from windows_cachyos_qcow2_gpt_readonly import qcow2_file_identity

ARCHISO_CONSENT = "I_ACCEPT_PINNED_ARCHISO_READONLY_WINDOWS10_QCOW2_COW"
PACSTRAP_CONSENT = "I_ACCEPT_CACHYOS_SHARED_ROOT_PACSTRAP_ON_DISPOSABLE_WINDOWS_COW"
MAX_SERIAL_BYTES = 2 * 1024 * 1024


class SharedRootPacstrapError(ValueError):
    """The genuine Archiso root-only pacstrap experiment did not pass."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise SharedRootPacstrapError(reason)


def _run(argv: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv, capture_output=True, text=True, check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SharedRootPacstrapError("host command unavailable: " + argv[0]) from error


def _sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()



def _copy_fresh_ovmf_vars(template: Path, destination: Path) -> str:
    """Use clean disposable OVMF variables so Windows BootOrder cannot steal the live-ISO boot."""
    require(template.is_absolute() and template.is_file() and not template.is_symlink()
            and template.stat().st_size >= 64 * 1024,
            "clean OVMF variable template is missing or invalid")
    require(not destination.exists() and not destination.is_symlink(),
            "refusing to reuse Archiso trial NVRAM")
    with template.open("rb") as source, destination.open("xb") as target:
        shutil.copyfileobj(source, target, length=256 * 1024)
        target.flush()
        os.fsync(target.fileno())
    os.chmod(destination, 0o600)
    require(destination.is_file() and not destination.is_symlink()
            and destination.stat().st_size == template.stat().st_size
            and _sha(destination) == _sha(template),
            "fresh trial OVMF variables differ from the trusted template")
    return _sha(destination)

def _owned(path: Path, parent: Path, name: str, *, mode: int | None = None) -> None:
    require(path.parent == parent and path.name == name
            and path.is_file() and not path.is_symlink(),
            "foreign or redirected Windows COW file: " + name)
    item = path.lstat()
    require(stat.S_ISREG(item.st_mode) and item.st_uid == os.getuid()
            and item.st_nlink == 1 and item.st_size > 0,
            "Windows COW file is not an exclusive owned regular file")
    if mode is not None:
        require(stat.S_IMODE(item.st_mode) == mode,
                "unexpected Windows COW permissions: " + name)


def _verify_environment(base: Path, workspace: Path, iso: Path,
                        pinned_sha256: str) -> None:
    runner_temp = Path(os.environ.get("RUNNER_TEMP", ""))
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("GASLUX_CACHYOS_SHARED_ROOT_PACSTRAP_CONSENT")
            == PACSTRAP_CONSENT
        and os.environ.get("GASLUX_CACHYOS_ARCHISO_READONLY_CONSENT")
            == ARCHISO_CONSENT
        and os.environ.get("GASLUX_CACHYOS_VERIFIED_ISO_SHA256") == ISO_SHA256
        and pinned_sha256 == ISO_SHA256,
        "explicit hosted Windows 10 + pinned Archiso + root-only pacstrap consent required",
    )
    require(runner_temp.is_absolute() and runner_temp.is_dir()
            and not runner_temp.is_symlink() and runner_temp.resolve() == runner_temp
            and base.parent.parent == runner_temp
            and base.parent.name.startswith("gaslux-win-x64-")
            and base.parent.is_dir() and not base.parent.is_symlink()
            and stat.S_IMODE(base.parent.stat().st_mode) == 0o700
            and workspace == base.parent and workspace.is_dir()
            and not workspace.is_symlink(),
            "Windows QCOW2 is not in the private hosted-runner workspace")
    require(iso.is_absolute() and iso.name == "cachyos.iso"
            and iso.is_file() and not iso.is_symlink()
            and iso.parent.parent == runner_temp
            and iso.parent.name.startswith("gaslux-pinned-cachyos-"),
            "CachyOS ISO is not the private pinned download")
    require(_sha(iso) == pinned_sha256,
            "CachyOS ISO SHA-256 changed after download")
    _owned(base, workspace, "only-disposable-windows-target.qcow2", mode=0o400)


def _write_lab_image(path: Path, size_bytes: int, label: str,
                     filesystem: str, volume_uuid: str | None = None) -> None:
    require(not path.exists() and not path.is_symlink(),
            "refusing to reuse lab disk image: " + path.name)
    _run(["truncate", "-s", str(size_bytes), str(path)])
    if filesystem == "ext4":
        argv = ["mkfs.ext4", "-q", "-F"]
        if volume_uuid:
            argv.extend(["-U", volume_uuid])
        argv.append(str(path))
    elif filesystem == "vfat":
        argv = ["mkfs.vfat", "-F", "32", "-n", label, str(path)]
    else:
        raise SharedRootPacstrapError("unsupported disposable lab filesystem")
    result = _run(argv, timeout=180)
    require(result.returncode == 0, "could not format private lab control media")
    require(path.is_file() and not path.is_symlink(),
            "private lab image was not created")
    os.chmod(path, 0o600)


def _copy_to_fat(image: Path, source: Path, target: str) -> None:
    require(source.is_file() and not source.is_symlink(),
            "missing control-volume source: " + source.name)
    result = _run(["mcopy", "-i", str(image), str(source), "::/" + target])
    require(result.returncode == 0,
            "could not copy verified control artifact: " + target)


def _safe_generator_diagnostic(result: subprocess.CompletedProcess[str]) -> str:
    """Return only a bounded, redacted JSON error from the boot-config generator."""
    raw = (result.stderr or "").strip()
    if not raw or len(raw) > 4096:
        return (
            f"generator exited with status {result.returncode} "
            "without bounded structured diagnostics"
        )
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        payload = None
    message = payload.get("error") if isinstance(payload, dict) else None
    if not isinstance(message, str) or not message.strip():
        return (
            f"generator exited with status {result.returncode} "
            "without structured diagnostics"
        )
    message = re.sub(
        r"(?i)\b(token|password|secret|authorization|private[_ -]?key)\b"
        r"\s*[:=]\s*[^\s,;]+",
        r"\1=<redacted>",
        message,
    )
    message = re.sub(
        r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@",
        r"\1<redacted>@",
        message,
    )
    message = re.sub(
        r"(?<![A-Za-z0-9])/(?:[^\s/:]+/)*[^\s/:]+",
        "<private-path>",
        message,
    )
    message = re.sub(
        r"(?i)\b[A-Z]:\\(?:[^\s\\]+\\)*[^\s\\]+",
        "<private-path>",
        message,
    )
    message = " ".join(
        "".join(char if char.isprintable() else " " for char in message).split()
    )
    return message[:512] or "generator failed without a usable diagnostic"


def _create_boot_config(
    *, iso: Path, iso_sha256: str, iso_uuid: str, iso_mount: Path,
    workspace: Path, run_id: str, nonce: str, plan_sha: str, key_sha: str,
) -> Path:
    grub_cfg = workspace / "cachyos-shared-root-grub.cfg"
    report = workspace / "cachyos-generated-boot-report.json"
    result = _run([
        "python3", "auto_tests/tools/cachyos_generated_boot_config.py",
        str(iso), iso_sha256, iso_uuid, str(iso_mount), str(grub_cfg), str(report),
    ], timeout=180)
    if result.returncode != 0:
        diagnostic = _safe_generator_diagnostic(result)
        raise SharedRootPacstrapError(
            "Gaslux CachyOS backend could not render the verified live ISO boot: "
            + diagnostic
        )
    require(
        grub_cfg.is_file() and not grub_cfg.is_symlink()
        and report.is_file() and not report.is_symlink(),
        "CachyOS boot generator reported success without safe output files",
    )
    lines = grub_cfg.read_text(encoding="utf-8").splitlines(keepends=True)
    # Only in the disposable lab boot: diagnose missing firmware-visible ISO.
    search_lines = [i for i, line in enumerate(lines)
                    if line.startswith("    search --no-floppy --fs-uuid --set=gaslux_iso_dev ")]
    require(len(search_lines) == 1, "generated CachyOS ISO device lookup is ambiguous")
    lines[search_lines[0]] = (
        "    echo 'GASLUX_VM_ISO_UUID_SEARCH_BEGIN'\n"
        + lines[search_lines[0]]
        + "    if [ -z \"$gaslux_iso_dev\" ]; then\n"
        + "        echo 'GASLUX_VM_ISO_UUID_NOT_VISIBLE'\n"
        + "        ls\n"
        + "    fi\n"
    )
    kernel_lines = [i for i, line in enumerate(lines)
                    if line.startswith("    linux (gaslux_iso)/")]
    require(len(kernel_lines) == 1 and lines[kernel_lines[0]].endswith("\n"),
            "generated CachyOS GRUB entry is ambiguous")
    flags = (
        " systemd.mount-extra=LABEL=GASLUXCTL:/run/gaslux-control:vfat:ro,exec"
        " systemd.run=/run/gaslux-control/gaslux-launch.sh"
        " systemd.mask=serial-getty@ttyS0.service"
        " systemd.wants=kernel-command-line.service"
        " systemd.run_success_action=none systemd.run_failure_action=poweroff"
        " gaslux.run=" + run_id
        + " gaslux.nonce=" + nonce
        + " gaslux.plan_sha256=" + plan_sha
        + " gaslux.key_sha256=" + key_sha
    )
    lines[kernel_lines[0]] = lines[kernel_lines[0]][:-1] + flags + "\n"
    grub_cfg.write_text("".join(lines), encoding="utf-8")
    check = _run(["grub-script-check", str(grub_cfg)], timeout=30)
    require(check.returncode == 0, "generated signed CachyOS GRUB configuration is invalid")
    return grub_cfg


def _verify_installed_root(
    overlay: Path, plan: dict[str, Any], run_id: str,
) -> dict[str, Any]:
    import guestfs
    g = guestfs.GuestFS(python_return_dict=True)
    try:
        g.add_drive_opts(str(overlay), format="qcow2", readonly=1)
        g.launch()
        devices = g.list_devices()
        require(len(devices) == 1 and
                g.blockdev_getsize64(devices[0]) == VIRTUAL_BYTES,
                "post-pacstrap guestfs disk identity/size mismatch")
        parts = g.list_partitions()
        require(len(parts) == 5, "post-pacstrap disk no longer has exactly five GPT partitions")
        root_part = parts[4]
        require(g.vfs_type(root_part) == "ext4"
                and g.vfs_uuid(root_part).lower() == plan["rootFsUuid"]
                and g.blockdev_getsize64(root_part) == 24 * 1024**3,
                "post-pacstrap fifth ext4 identity/geometry changed")
        # A guest with a still-busy installation mount may only pass after
        # VM poweroff if its ext4 superblock is demonstrably clean. Query
        # the readonly COW snapshot before attempting any root mount.
        fs_state = g.tune2fs_l(root_part)
        require(isinstance(fs_state, dict)
                and fs_state.get("Filesystem state") == "clean",
                "post-poweroff installed ext4 is not clean")
        g.mount_ro(root_part, "/")
        try:
            os_release = g.read_file("/etc/os-release").decode("utf-8")
            release_lines = set(os_release.splitlines())
            require("ID=cachyos" in release_lines and "ID_LIKE=arch" in release_lines,
                    "installed root does not identify as native CachyOS")
            require(g.is_file("/boot/vmlinuz-linux-cachyos-lts")
                    and g.is_file("/boot/initramfs-linux-cachyos-lts.img")
                    and g.is_file("/var/lib/pacman/local/ALPM_DB_VERSION"),
                    "native kernel, initramfs or pacman database missing")
            require(g.read_file("/.gaslux-lab-root-owner").decode("ascii").strip()
                    == run_id, "installed root ownership marker differs from transaction")
            pacman_conf = g.read_file("/etc/pacman.conf").decode("utf-8")
            require("SigLevel = Required DatabaseOptional TrustedOnly" in pacman_conf
                    and "SigLevel = Never" not in pacman_conf
                    and "TrustAll" not in pacman_conf,
                    "installed package policy does not require trusted signatures")
            packages = g.glob_expand("/var/lib/pacman/local/linux-cachyos-lts-*")
            require(bool(packages), "native linux-cachyos-lts package record missing")
        finally:
            g.umount_all()
        return {
            "fifthRootExt4IdentityVerified": True,
            "nativeCachyOSOsReleaseVerified": True,
            "nativeKernelAndInitramfsPresent": True,
            "nativePacmanDatabasePresent": True,
            "strictInstalledPacmanPolicyVerified": True,
            "transactionOwnerMarkerVerified": True,
        }
    finally:
        try:
            g.shutdown()
        finally:
            g.close()



def _permit_owned_iso_staging_write(image: Path, mountpoint: Path) -> None:
    """Give the runner access only to the root of its newly mounted ext4 ISO.

    sudo mount makes the ext4 filesystem root owned by root even though the
    mountpoint directory was runner-owned. Refuse to chmod/chown anything until
    the kernel mount source is independently bound to this *specific* private
    regular file and its loop device, and never accept a host block device.
    """
    require(image.is_absolute() and mountpoint.is_absolute()
            and image.parent == mountpoint.parent
            and image.name == "cachyos-iso-source.raw"
            and mountpoint.name == "cachyos-iso-storage"
            and image.is_file() and not image.is_symlink()
            and mountpoint.is_dir() and not mountpoint.is_symlink()
            and image.stat().st_uid == os.getuid()
            and image.stat().st_nlink == 1
            and image.stat().st_size > 2 * 1024**3
            and mountpoint.parent.is_dir()
            and not mountpoint.parent.is_symlink()
            and stat.S_IMODE(mountpoint.parent.stat().st_mode) == 0o700,
            "ISO staging is not an exclusive runner-owned private image")
    observed = _run(["findmnt", "-rn", "-M", str(mountpoint),
                     "-o", "SOURCE,FSTYPE,OPTIONS"])
    require(observed.returncode == 0 and len(observed.stdout) < 2048,
            "private ISO staging mount is not observable")
    tokens = observed.stdout.strip().split(None, 2)
    require(len(tokens) == 3
            and re.fullmatch(r"/dev/loop[0-9]+", tokens[0]) is not None
            and tokens[1] == "ext4"
            and "rw" in tokens[2].split(",")
            and "ro" not in tokens[2].split(","),
            "ISO staging is not the expected read-write ext4 loop mount")
    backing = _run(["losetup", "--noheadings", "--output", "BACK-FILE",
                    tokens[0]])
    require(backing.returncode == 0
            and backing.stdout.strip() == str(image),
            "ISO staging loop is not backed by the owned private image")
    owner = f"{os.getuid()}:{os.getgid()}"
    for argv in (["sudo", "chown", "--", owner, str(mountpoint)],
                 ["sudo", "chmod", "--", "0700", str(mountpoint)]):
        result = _run(argv)
        require(result.returncode == 0,
                "cannot authorize runner writes to owned ISO staging only")
    st = mountpoint.stat()
    require(st.st_uid == os.getuid() and st.st_gid == os.getgid()
            and stat.S_IMODE(st.st_mode) == 0o700,
            "private ISO staging root did not acquire runner ownership")


def run_shared_root_pacstrap(
    *,
    iso: Path,
    pinned_sha256: str,
    base: Path,
    nvram: Path,
    ovmf_code: Path,
    workspace: Path,
    geometry: dict[str, Any],
    checkpoint: dict[str, Any],
    staged: dict[str, Any],
    third: dict[str, Any],
    ext4: dict[str, Any],
    fourth: dict[str, Any],
    fourth_serial: Path,
) -> dict[str, Any]:
    """Boot the pinned genuine Archiso and pacstrap only existing GPT #5 ext4."""
    _verify_environment(base, workspace, iso, pinned_sha256)
    require(ovmf_code.is_file() and not ovmf_code.is_symlink()
            and ovmf_code.stat().st_size > 500_000,
            "verified OVMF code image missing")
    overlay = base.parent / CHECKPOINT_DIR / OVERLAY_NAME
    _owned(overlay, base.parent / CHECKPOINT_DIR, OVERLAY_NAME, mode=0o600)
    _owned(nvram, base.parent, "ovmf-variables.fd")
    root_uuid = ext4.get("rootFilesystem", {}).get("filesystemUuid")
    root_partuuid = staged.get("linuxRoot", {}).get("uniqueGuid")
    require(isinstance(root_uuid, str) and isinstance(root_partuuid, str),
            "missing existing fifth ext4 UUID/PARTUUID")
    handoff = workspace / "cachyos-root-write-handoff"
    require(not handoff.exists() and not handoff.is_symlink(),
            "refusing to reuse previous root-write handoff")
    handoff.mkdir(mode=0o700)
    os.chmod(handoff, 0o700)
    signed = prepare(
        overlay, handoff, root_uuid, root_partuuid, pinned_sha256,
        windows_fourth_verified=True,
    )
    programs = {
        "cachyos_windows_shared_root_pacstrap.py":
            Path("auto_tests/tools/cachyos_windows_shared_root_pacstrap.py"),
        "cachyos_configure_installed.py":
            Path("auto_tests/tools/cachyos_configure_installed.py"),
        "cachyos_windows_shared_archiso_handoff.py":
            Path("auto_tests/tools/cachyos_windows_shared_archiso_handoff.py"),
        "cachyos_windows_shared_archiso_guest_probe.py":
            Path("auto_tests/tools/cachyos_windows_shared_archiso_guest_probe.py"),
        "windows_cachyos_qcow2_gpt_readonly.py":
            Path("auto_tests/tools/windows_cachyos_qcow2_gpt_readonly.py"),
        "strict-pacman.py": Path("assets/live/cachyos-strict-pacman.py"),
        "pacman-trust.py": Path("assets/live/cachyos-pacman-trust.py"),
        "gaslux-install.sh": Path("auto_tests/tools/gaslux-cachyos-shared-root-install.sh"),
        "gaslux-launch.sh": Path("auto_tests/tools/gaslux-cachyos-shared-root-launch.sh"),
    }
    grant_status = issue_root_write_grant(
        plan_path=handoff / "plan.json",
        plan_signature=handoff / "plan.sig",
        public_key=handoff / "public.pem",
        private_key=handoff / "private.pem",
        base=base, overlay=overlay, nvram=nvram, workspace=handoff,
        geometry=geometry, checkpoint=checkpoint, staged=staged,
        third=third, ext4=ext4, fourth=fourth,
        fourth_serial=fourth_serial, programs=programs,
    )
    plan = json.loads((handoff / "plan.json").read_bytes())
    run_id = plan["runId"]
    nonce = plan["bootNonce"]
    plan_sha = signed["planSha256"]
    key_sha = signed["pubSha256"]

    control = workspace / "gaslux-control.raw"
    control_size = 128 * 1024**2
    _write_lab_image(control, control_size, "GASLUXCTL", "vfat")
    lab_env = handoff / "lab.env"
    lab_env.write_text(
        "RUN_ID=" + run_id + "\n"
        + "ROOT_UUID=" + root_uuid + "\n"
        + "ROOT_PARTUUID=" + root_partuuid + "\n",
        encoding="ascii",
    )
    os.chmod(lab_env, 0o600)
    copies = [
        (lab_env, "lab.env"),
        (handoff / "plan.json", "plan.json"),
        (handoff / "plan.sig", "plan.sig"),
        (handoff / "public.pem", "public.pem"),
        (handoff / "root-write-grant.json", "root-write-grant.json"),
        (handoff / "root-write-grant.sig", "root-write-grant.sig"),
        (handoff / "host-checkpoint.json", "host-checkpoint.json"),
        (handoff / "host-overlay-backing-proof.json", "host-overlay-backing-proof.json"),
        (programs["cachyos_windows_shared_root_pacstrap.py"], "cachyos_windows_shared_root_pacstrap.py"),
        (programs["cachyos_configure_installed.py"], "cachyos_configure_installed.py"),
        (programs["cachyos_windows_shared_archiso_handoff.py"], "cachyos_windows_shared_archiso_handoff.py"),
        (programs["cachyos_windows_shared_archiso_guest_probe.py"], "cachyos_windows_shared_archiso_guest_probe.py"),
        (programs["windows_cachyos_qcow2_gpt_readonly.py"], "windows_cachyos_qcow2_gpt_readonly.py"),
        (programs["strict-pacman.py"], "strict-pacman.py"),
        (programs["pacman-trust.py"], "pacman-trust.py"),
        (programs["gaslux-install.sh"], "gaslux-install.sh"),
        (programs["gaslux-launch.sh"], "gaslux-launch.sh"),
    ]
    for source, target in copies:
        _copy_to_fat(control, source, target)

    iso_uuid = str(uuid.uuid4())
    iso_size = iso.stat().st_size
    iso_capacity = ((iso_size + 1024**3 - 1) // 1024**3 + 1) * 1024**3
    iso_image = workspace / "cachyos-iso-source.raw"
    _write_lab_image(iso_image, iso_capacity, "CACHYOSISO", "ext4", iso_uuid)
    storage_root = workspace / "cachyos-iso-storage"
    storage_root.mkdir(mode=0o700)
    mount_rw = _run(["sudo", "mount", "-o", "loop,rw", str(iso_image), str(storage_root)])
    require(mount_rw.returncode == 0, "could not mount private ext4 ISO storage")
    storage_iso = storage_root / "cachyos.iso"
    try:
        _permit_owned_iso_staging_write(iso_image, storage_root)
        require(not storage_iso.exists() and not storage_iso.is_symlink(),
                "refusing to overwrite ISO inside private storage")
        with iso.open("rb") as source, storage_iso.open("xb") as target:
            shutil.copyfileobj(source, target, length=4 * 1024 * 1024)
            target.flush()
            os.fsync(target.fileno())
        os.sync()
        require(_sha(storage_iso) == pinned_sha256
                and storage_iso.stat().st_size == iso_size,
                "copy into private ISO storage differs from pinned source")
    finally:
        unmount_rw = _run(["sudo", "umount", str(storage_root)])
        require(unmount_rw.returncode == 0, "could not close private writable ISO staging")
    mount_ro = _run(["sudo", "mount", "-o", "loop,ro", str(iso_image), str(storage_root)])
    require(mount_ro.returncode == 0, "could not remount private ISO storage read-only")
    iso_mount = workspace / "cachyos-iso-mounted"
    iso_mount.mkdir(mode=0o700)
    iso_mounted = False
    try:
        mount_iso = _run(["sudo", "mount", "-o", "ro,loop", str(storage_iso), str(iso_mount)])
        require(mount_iso.returncode == 0,
                "could not mount the exact stored CachyOS ISO read-only")
        iso_mounted = True
        grub_cfg = _create_boot_config(
            iso=storage_iso, iso_sha256=pinned_sha256, iso_uuid=iso_uuid,
            iso_mount=iso_mount, workspace=workspace, run_id=run_id,
            nonce=nonce, plan_sha=plan_sha, key_sha=key_sha,
        )
    finally:
        if iso_mounted:
            unmount_iso = _run(["sudo", "umount", str(iso_mount)])
            require(unmount_iso.returncode == 0,
                    "could not release read-only CachyOS ISO mount")
        unmount_storage = _run(["sudo", "umount", str(storage_root)])
        require(unmount_storage.returncode == 0,
                "could not release read-only ISO storage mount")
    boot_efi = workspace / "cachyos-liveboot.raw"
    _write_lab_image(boot_efi, 96 * 1024**2, "GASLUXBOOT", "vfat")
    for directory in ("::/EFI", "::/EFI/BOOT"):
        created = _run(["mmd", "-i", str(boot_efi), directory])
        require(created.returncode == 0, "could not create isolated UEFI fallback directory")
    standalone = workspace / "gaslux-cachyos-bootx64.efi"
    result = _run([
        "grub-mkstandalone", "--format=x86_64-efi", "--output=" + str(standalone),
        "boot/grub/grub.cfg=" + str(grub_cfg),
    ], timeout=180)
    require(result.returncode == 0 and standalone.is_file()
            and not standalone.is_symlink(), "could not build isolated UEFI Archiso loader")
    _copy_to_fat(boot_efi, standalone, "EFI/BOOT/BOOTX64.EFI")

    trial_vars = workspace / "cachyos-trial-ovmf-variables.fd"
    # Do not inherit Windows BootOrder into the live-ISO VM; original Windows NVRAM is only audited.
    _copy_fresh_ovmf_vars(Path(OVMF_VARS), trial_vars)
    before_base_sha = _sha(base)
    before_base_identity = qcow2_file_identity(base)
    before_nvram_sha = _sha(nvram)
    before_iso_image_sha = _sha(iso_image)
    before_control_sha = _sha(control)
    before_boot_efi_sha = _sha(boot_efi)
    serial = workspace / "cachyos-shared-root-pacstrap-serial.log"
    stderr = workspace / "cachyos-shared-root-pacstrap-qemu-stderr.log"
    require(not serial.exists() and not serial.is_symlink()
            and not stderr.exists() and not stderr.is_symlink(),
            "refusing to reuse Archiso pacstrap VM logs")
    qemu = [
        "qemu-system-x86_64",
        "-machine", "q35,accel=kvm,smm=on",
        "-global", "driver=cfi.pflash01,property=secure,value=on",
        "-cpu", "host", "-smp", "2", "-m", "6144",
        "-display", "none", "-monitor", "none", "-no-reboot",
        "-drive", "if=pflash,format=raw,readonly=on,file=" + str(ovmf_code),
        "-drive", "if=pflash,format=raw,file=" + str(trial_vars),
        "-device", "qemu-xhci",
        "-drive", "if=none,id=liveefi,format=raw,file=" + str(boot_efi) + ",readonly=on",
        "-device", "usb-storage,drive=liveefi,bootindex=1",
        "-drive", "if=none,id=iso_source,format=raw,file=" + str(iso_image) + ",readonly=on",
        # Keep the ISO carrier read-only, using the same firmware-visible USB
        # transport as our GRUB EFI launcher. OVMF/GRUB failed to discover
        # the old virtio-blk source by its exact ext4 filesystem UUID.
        "-device", "usb-storage,drive=iso_source,bootindex=2",
        # The sole writable Windows-containing disk is this owned COW overlay.
        # QEMU opens its protected backing QCOW2 read-only; it is never attached separately.
        "-drive", "if=none,id=windows_cow,format=qcow2,file=" + str(overlay),
        "-device", "virtio-blk-pci,drive=windows_cow,serial=" + SERIAL,
        "-drive", "if=none,id=gaslux_control,format=raw,file=" + str(control) + ",readonly=on",
        "-device", "virtio-blk-pci,drive=gaslux_control",
        "-netdev", "user,id=net0",
        "-device", "virtio-net-pci,netdev=net0",
        "-serial", "file:" + str(serial),
    ]
    with stderr.open("xb") as err:
        proc = subprocess.Popen(qemu, stdout=subprocess.DEVNULL, stderr=err)
        try:
            proc.wait(timeout=3600)
        except subprocess.TimeoutExpired as error:
            proc.kill()
            proc.wait(timeout=30)
            raise SharedRootPacstrapError("Archiso pacstrap guest timed out") from error
    require(proc.returncode == 0, "Archiso pacstrap guest did not power off cleanly")
    require(serial.is_file() and not serial.is_symlink()
            and 0 < serial.stat().st_size <= MAX_SERIAL_BYTES,
            "missing or oversized Archiso pacstrap COM1")
    serial_bytes = serial.read_bytes()
    pass_marker = ("GASLUX_SHARED_COW_ROOT_PACSTRAP_PASS:"
                   + run_id + ":" + root_uuid).encode("ascii")
    ordinary_umount = serial_bytes.count(
        b"GASLUX_SHARED_COW_ROOT_UNMOUNTED_IN_GUEST=1")
    deferred_umount = serial_bytes.count(
        b"GASLUX_SHARED_COW_ROOT_UNMOUNT_DEFERRED_TO_POWEROFF=1")
    require(ordinary_umount + deferred_umount == 1,
            "missing or ambiguous fifth root mount-cleanup evidence")
    if deferred_umount:
        require(serial_bytes.count(
            b"All filesystems, swaps, loop devices, MD devices and DM devices detached."
        ) == 1 and serial_bytes.count(b"Powering off.") >= 1,
                "guest did not report complete orderly systemd unmount")
    require(serial_bytes.count(pass_marker) == 1
            and serial_bytes.count(
                b"GASLUX_SHARED_COW_NATIVE_CACHYOS_PACSTRAP_ROOT_ONLY=1") == 1
            and serial_bytes.count(
                b"GASLUX_SHARED_COW_ESP_BOOTLOADER_NOT_INSTALLED=1") == 1
            and b"GASLUX_SHARED_COW_ROOT_PACSTRAP_FAILED" not in serial_bytes
            and b"GASLUX_SHARED_COW_PREWRITE_FAILURE" not in serial_bytes,
            "guest did not produce the unique native root-only pacstrap witness")

    require(_sha(base) == before_base_sha
            and qcow2_file_identity(base) == before_base_identity
            and _sha(nvram) == before_nvram_sha,
            "Windows backing QCOW2 or original OVMF variables changed during Archiso pacstrap")
    post_info = _run([
        "qemu-img", "info", "-f", "qcow2", "--output=json", str(overlay),
    ])
    require(post_info.returncode == 0, "cannot inspect post-pacstrap Windows COW overlay")
    try:
        post_info_doc = json.loads(post_info.stdout)
    except ValueError as error:
        raise SharedRootPacstrapError("invalid post-pacstrap QCOW2 info") from error
    require(post_info_doc.get("format") == "qcow2"
            and post_info_doc.get("virtual-size") == VIRTUAL_BYTES
            and post_info_doc.get("backing-filename") == str(base)
            and post_info_doc.get("backing-filename-format") == "qcow2",
            "post-pacstrap COW backing chain no longer identifies the immutable Windows base")
    _owned(overlay, base.parent / CHECKPOINT_DIR, OVERLAY_NAME, mode=0o600)
    require(_sha(iso_image) == before_iso_image_sha
            and _sha(control) == before_control_sha
            and _sha(boot_efi) == before_boot_efi_sha,
            "read-only ISO, control or EFI media changed during Archiso guest")
    post_qemu_check = _run(["qemu-img", "check", "-f", "qcow2", str(overlay)],
                           timeout=300)
    require(post_qemu_check.returncode == 0
            and "No errors were found" in
                (post_qemu_check.stdout + post_qemu_check.stderr),
            "post-pacstrap Windows COW overlay consistency check failed")
    with tempfile.TemporaryDirectory(prefix="gaslux-post-pacstrap-gpt-",
                                     dir=base.parent) as tmp:
        front, back = gpt_windows(overlay, Path(tmp))
    require(hashlib.sha256(front + back).hexdigest() == plan["gptWindowsSha256"],
            "GPT changed during root-only pacstrap")
    windows_hashes = read_windows_file_hashes(overlay)
    require(windows_hashes == plan["windowsHashes"],
            "Windows ESP/BCD/loader/WinRE changed during root-only pacstrap")
    before_root_only_firstboot_overlay_sha = _sha(overlay)
    root_status = _verify_installed_root(overlay, plan, run_id)
    require(_sha(base) == before_base_sha
            and qcow2_file_identity(base) == before_base_identity
            and _sha(nvram) == before_nvram_sha,
            "Windows base or firmware changed during post-install audit")
    # Experimental *read-only* firstboot smoke, after native pacstrap and
    # root validation, before the existing Windows COW discard transaction.
    # The guest receives neither Archiso nor writable Windows-backed storage.
    # Failure never skips the mandatory COW discard / Windows reboot step.
    from cachyos_windows_shared_cow_firstboot import (
        probe_installed_root_readonly,
    )
    try:
        firstboot_status = probe_installed_root_readonly(
            overlay=overlay, base=base, nvram=nvram,
            ovmf_code=ovmf_code, workspace=workspace, plan=plan,
            run_id=run_id)
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        firstboot_status = {
            "minimalInstalledReadOnlyBootVerified": False,
            "installedReadOnlyBootFailureType": type(error).__name__,
            "installedReadOnlyBootloaderInstalledToWindowsESP": False,
            "firstBootWithWritableSystemVerified": False,
        }
    # Preserve evidence and enforce Windows invariants regardless of whether
    # the new read-only Linux smoke passed, before discarding the owned COW.
    require(_sha(base) == before_base_sha
            and qcow2_file_identity(base) == before_base_identity
            and _sha(nvram) == before_nvram_sha
            and _sha(overlay) == before_root_only_firstboot_overlay_sha,
            "read-only installed boot modified source Windows COW/base/NVRAM")
    with tempfile.TemporaryDirectory(prefix="gaslux-post-boot-gpt-",
                                     dir=base.parent) as tmp:
        after_front, after_back = gpt_windows(overlay, Path(tmp))
    require(hashlib.sha256(after_front + after_back).hexdigest()
            == plan["gptWindowsSha256"]
            and read_windows_file_hashes(overlay) == plan["windowsHashes"],
            "Windows GPT or protected hashes changed during read-only installed boot")
    # Next guarded lab stage: RW writes ONLY to a NEW COW child of the installed
    # parent, never to the already attested parent or to Windows backing.
    # Gate it behind a *proven* installed read-only root boot.
    writable_child_status = {
        "installedWritableChildKernelAndSystemdBootVerified": False,
        "installedWritableChildOverlayDiscarded": False,
        "firstBootWithWritableSystemVerified": False,
        "sameDiskDualBootVerified": False,
        "productionStorageWritesAuthorized": False,
    }
    if firstboot_status.get("minimalInstalledReadOnlyBootVerified") is True:
        from cachyos_windows_shared_cow_rw_child import probe_owned_rw_child
        try:
            writable_child_status = probe_owned_rw_child(
                overlay=overlay, base=base, nvram=nvram,
                ovmf_code=ovmf_code, workspace=workspace, plan=plan,
                run_id=run_id)
        except (ValueError, OSError, subprocess.TimeoutExpired) as error:
            writable_child_status["installedWritableChildFailureType"] = (
                type(error).__name__)
    # A failed or successful nested RW experiment NEVER bypasses the original
    # Windows verification and the outer COW discard/reboot transaction.
    require(_sha(base) == before_base_sha
            and qcow2_file_identity(base) == before_base_identity
            and _sha(nvram) == before_nvram_sha
            and _sha(overlay) == before_root_only_firstboot_overlay_sha,
            "nested RW child modified original Windows base/parent/NVRAM")
    with tempfile.TemporaryDirectory(prefix="gaslux-final-windows-gpt-",
                                     dir=base.parent) as tmp:
        last_front, last_back = gpt_windows(overlay, Path(tmp))
    require(hashlib.sha256(last_front + last_back).hexdigest()
            == plan["gptWindowsSha256"]
            and read_windows_file_hashes(overlay) == plan["windowsHashes"],
            "nested RW stage altered Windows GPT/ESP/BCD/WinRE in parent")
    return {
        **grant_status,
        **root_status,
        **firstboot_status,
        **writable_child_status,
        "cachyosRootPacstrapped": True,
        "pacstrapExecuted": True,
        "rootUnmountedInGuest": ordinary_umount == 1,
        "rootUnmountCompletedByGuestShutdown": deferred_umount == 1,
        "labOnlyPacstrapCompleted": True,
        "cachyosInstalled": False,
        "cachyosFirstBootVerified": False,
        "windowsGptUnchangedAfterPacstrap": True,
        "windowsProtectedHashesUnchangedAfterPacstrap": True,
        "windowsBaseSha256UnchangedAfterPacstrap": True,
        "originalWindowsUefiUnchangedAfterPacstrap": True,
        "windowsEspWritesAllowed": False,
        "efiBootloaderInstalled": False,
        "sameDiskDualBootVerified": False,
        "windowsRecoveryAfterLinuxVerified": False,
        "rollbackProven": False,
        "productionStorageWritesAuthorized": False,
        "releaseEligible": False,
        "pacstrapSerialSha256": _sha(serial),
        "pacstrapQemuStderrSha256": _sha(stderr),
    }


if __name__ == "__main__":
    raise SystemExit("Library only: requires a signed host COW grant and explicit hosted KVM consent.")
