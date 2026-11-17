#!/usr/bin/env python3
"""Experimental QEMU-only CachyOS pacstrap into an existing owned GPT #5.

NOT a Windows installer, not production write authorization, not a bootloader
installer. This script never repartitions, formats, writes the Windows ESP,
modifies BCD/NVRAM or writes any Windows filesystem.

A signed read-only handoff is necessary but not sufficient. Lab writes are
separately gated on the exact hosted/QEMU environment and are limited to the
already formatted ext4 Linux root in a DISPOSABLE COW whose Windows backing
file is never attached to this VM as a separate writable drive.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile
from typing import Any
import uuid

from cachyos_windows_shared_archiso_guest_probe import (
    require_live_archiso, efi_mode_readonly, validate_lsblk_readonly,
)
from cachyos_windows_shared_archiso_handoff import (
    SERIAL, VIRTUAL_BYTES, SECTOR_BYTES, ISO_SHA256,
    canonical, validate_plan, verify, SharedDiskHandoffRejected,
)
from windows_cachyos_qcow2_gpt_readonly import (
    WINDOW_BYTES, SECTOR, header_at, part_array,
)

ROOT = Path("/mnt/gaslux-shared-root")
WIN_FILES = (
    (1, "/EFI/Microsoft/Boot/bootmgfw.efi", "espBootManagerSha256"),
    (1, "/EFI/Microsoft/Boot/BCD", "espBcdSha256"),
    (3, "/Windows/System32/winload.efi", "windowsLoaderSha256"),
    (4, "/Recovery/WindowsRE/Winre.wim", "winreImageSha256"),
)
LAB_CONSENT = "I_ACCEPT_SIGNED_CACHYOS_ROOT_ONLY_IN_DISPOSABLE_QEMU_COW"
SHA = re.compile(r"[a-f0-9]{64}\Z")


def require(ok: bool, why: str) -> None:
    if not ok:
        raise SharedDiskHandoffRejected(why)


def execute(argv: list[str], *, timeout: int = 60) -> str:
    completed = subprocess.run(argv, capture_output=True, text=True,
                               check=False, timeout=timeout)
    require(completed.returncode == 0,
            "lab command failed: " + argv[0])
    return completed.stdout


def sha_file(path: Path) -> str:
    """Hash a regular file through directory FDs, never following any symlink.

    Traversal is anchored at / and each component is opened with O_NOFOLLOW.
    This prevents a Windows junction/symlink or swapped intermediate directory
    from redirecting the prewrite evidence outside the RO-mounted partition.
    """
    require(isinstance(path, Path) and path.is_absolute()
            and all(part not in ("", ".", "..") for part in path.parts[1:])
            and len(path.parts) > 1,
            "invalid protected file path")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY
                        | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            next_dir = os.open(component, os.O_RDONLY | os.O_DIRECTORY
                               | os.O_NOFOLLOW | os.O_CLOEXEC,
                               dir_fd=directory)
            os.close(directory)
            directory = next_dir
        fd = os.open(path.parts[-1], os.O_RDONLY | os.O_NOFOLLOW
                     | os.O_CLOEXEC, dir_fd=directory)
        try:
            require(stat.S_ISREG(os.fstat(fd).st_mode),
                    "protected Windows source is not a regular file")
            digest = hashlib.sha256()
            while True:
                data = os.read(fd, 1024 * 1024)
                if not data:
                    break
                digest.update(data)
            return digest.hexdigest()
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def verify_mounted_source(
    mountpoint: Path, expected: Path, filesystem: str, *,
    readonly: bool, run=execute,
) -> None:
    """A mount type alone is insufficient: prove device and options as well."""
    require(mountpoint.is_absolute() and expected.is_absolute(),
            "nonabsolute protected mount identity")
    origin = run(["findmnt", "-n", "-M", str(mountpoint),
                  "-o", "SOURCE"]).strip()
    observed_type = run(["findmnt", "-n", "-M", str(mountpoint),
                         "-o", "FSTYPE"]).strip()
    options = set(run(["findmnt", "-n", "-M", str(mountpoint),
                       "-o", "OPTIONS"]).strip().split(","))
    expected_flags = {"ro", "nosuid", "nodev", "noexec"} if readonly else {
        "rw", "nosuid", "nodev",
    }
    require(origin == str(expected)
            and observed_type == filesystem
            and expected_flags.issubset(options)
            and not ({"rw"} if readonly else {"ro"}) & options,
            "mount source, filesystem or access flags differ from signed target")


def strict_gpt_evidence(
    disk: Path, plan: dict[str, Any],
) -> dict[str, Any]:
    """Read BOTH full GPT windows directly; prove all five signed records.

    Does not use the Windows-only 4-partition candidate as write authority.
    Refuses PMBR hybrids, shifted entries, damaged CRC, foreign slots, and
    a different disk/sector table even if lsblk appears correct.
    """
    require(disk.is_absolute() and disk.parent == Path("/dev")
            and re.fullmatch(r"vd[a-z]{1,2}", disk.name) is not None
            and not disk.is_symlink() and disk.is_block_device(),
            "chosen QEMU guest device is not one whole virtio disk")
    fd = os.open(str(disk), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        whole = os.fstat(fd)
        require(stat.S_ISBLK(whole.st_mode), "not a block device")
        actual_bytes = struct.unpack("=Q", fcntl.ioctl(
            fd, 0x80081272, bytes(8)))[0]  # Linux BLKGETSIZE64
        actual_sector = struct.unpack("=I", fcntl.ioctl(
            fd, 0x1268, bytes(4)))[0]  # Linux BLKSSZGET
        require(actual_bytes == VIRTUAL_BYTES
                and actual_sector == SECTOR_BYTES,
                "actual whole disk size/sector bytes differ from signed plan")
        front = os.pread(fd, WINDOW_BYTES, 0)
        back = os.pread(fd, WINDOW_BYTES, VIRTUAL_BYTES - WINDOW_BYTES)
        require(os.fstat(fd).st_rdev == whole.st_rdev,
                "whole guest device changed during bounded GPT reads")
    finally:
        os.close(fd)
    require(len(front) == len(back) == WINDOW_BYTES
            and front[510:512] == b"\x55\xaa", "missing bounded GPT/PMBR")
    records = [front[446+i*16:446+(i+1)*16] for i in range(4)]
    pmbr = records[0]
    expected_size = VIRTUAL_BYTES // SECTOR - 1
    start, span = struct.unpack_from("<II", pmbr, 8)
    require(pmbr[0] == 0 and pmbr[4] == 0xEE and start == 1
            and span in (expected_size, 0xFFFFFFFF)
            and not any(any(rec) for rec in records[1:]),
            "hybrid or invalid Windows protective MBR")
    total = VIRTUAL_BYTES // SECTOR
    primary = header_at(front, SECTOR, 1, total-1, total)
    backup = header_at(back, WINDOW_BYTES-SECTOR, total-1, 1, total)
    require(primary[56:72] == backup[56:72]
            and primary[40:56] == backup[40:56],
            "GPT disk GUID or usable range changed")
    entries = part_array(primary, front, back, total)
    require(entries == part_array(backup, front, back, total),
            "GPT primary/backup tables disagree")
    require(hashlib.sha256(primary[56:72]).hexdigest()
            == plan["diskGuidSha256"], "disk GUID differs from signed plan")
    require(len(entries) == 128 * 128 and
            not any(entries[5*128:]), "foreign sixth GPT record")
    require(hashlib.sha256(front + back).hexdigest()
            == plan["gptWindowsSha256"],
            "Windows GPT entry bytes differ from canonical signed dual-window baseline")
    for i, planned in enumerate(plan["partitions"]):
        row = entries[i*128:(i+1)*128]
        require(str(uuid.UUID(bytes_le=row[0:16])) ==
                    planned["typeGuid"]
                and str(uuid.UUID(bytes_le=row[16:32])) ==
                    planned["uniqueGuid"]
                and struct.unpack_from("<QQ", row, 32) ==
                    (planned["firstLba"], planned["lastLba"]),
                "signed Windows/owned-Linux GPT entry disagrees with real disk")
    return {
        "bothGptCopiesCrcVerified": True,
        "allWindowsAndOwnedLinuxEntriesIdenticalToSignedPlan": True,
        "protectiveMbrCanonical": span == expected_size,
        "protectiveMbrWindowsLabOversized": span == 0xFFFFFFFF,
        "productionWritesAuthorized": False,
    }


def protected_files_readonly(disk: Path, plan: dict[str, Any]) -> None:
    """Always inspect Windows from read-only guest mounts, never NTFS rw."""
    hashes = plan["windowsHashes"]
    for index, filename, field in WIN_FILES:
        part = Path("/dev/disk/by-partuuid") / plan["partitions"][index-1]["uniqueGuid"]
        require(part.is_symlink() and part.resolve().is_block_device(),
                "signed protected partition identity missing")
        source = part.resolve()
        require(execute(["lsblk", "-no", "PKNAME", str(source)]).strip()
                == disk.name, "protected partition is not on the signed disk")
        with tempfile.TemporaryDirectory(prefix="gaslux-win-ro-", dir="/run") as temp:
            mount_type = "vfat" if index == 1 else "ntfs3"
            execute(["mount", "-t", mount_type,
                     "-o", "ro,nosuid,nodev,noexec", str(source), temp])
            try:
                verify_mounted_source(Path(temp), source, mount_type,
                                      readonly=True)
                candidate = Path(temp) / filename.lstrip("/")
                digest = sha_file(candidate)
                require(SHA.fullmatch(digest) is not None
                        and digest == hashes[field],
                        "protected Windows content hash differs from signed plan")
            finally:
                execute(["umount", temp])
    print("GASLUX_SHARED_COW_WINDOWS_ESP_BCD_WINRE_HASHES_VERIFIED=1", flush=True)


def guest_plan(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], Path]:
    require_live_archiso()
    efi_mode_readonly()
    require(os.environ.get("GITHUB_ACTIONS_GUEST")
            == "I_ACCEPT_QEMU_GUEST_WITH_HOSTED_WINDOWS_COW"
            and os.environ.get("GASLUX_SHARED_COW_ROOT_INSTALL_CONSENT")
                == LAB_CONSENT
            and os.geteuid() == 0,
            "no explicit QEMU guest / root-only pacstrap consent")
    raw = args.plan.read_bytes()
    verify(args.plan, args.signature, args.public_key,
           Path("/proc/cmdline").read_text(encoding="utf-8"),
           independent_run_id=args.expected_run_id,
           independent_root_uuid=args.expected_root_uuid)
    plan = json.loads(raw)
    validate_plan(plan)
    require(plan["labOnly"] is True and plan["writeAuthority"] is False,
            "production write authority must never be inferred")
    topology = json.loads(execute([
        "lsblk", "--json", "--tree", "--bytes", "--output",
        "NAME,TYPE,PATH,SERIAL,SIZE,LOG-SEC,START,PARTTYPE,PARTUUID,FSTYPE,UUID,MOUNTPOINTS",
    ]))
    probe = validate_lsblk_readonly(plan, topology)
    require(probe["observedFivePartitionLayoutMatchesSignedPlan"]
            and probe["storageWritesAuthorized"] is False,
            "signed in-guest disk layout not validated")
    found = [item for item in topology["blockdevices"]
             if item.get("type") == "disk" and item.get("serial") == SERIAL]
    require(len(found) == 1 and
            re.fullmatch(r"/dev/vd[a-z]{1,2}", found[0]["path"]) is not None,
            "unexpected signed virtual disk source")
    disk = Path(found[0]["path"])
    require(disk.is_block_device() and
            not disk.is_symlink() and
            not any(x.get("mountpoints") not in (None, [], [None], [""])
                    for x in found[0]["children"]),
            "shared Windows disk is ambiguous or mounted")
    require(strict_gpt_evidence(disk, plan)["bothGptCopiesCrcVerified"],
            "independent GPT validation absent")
    protected_files_readonly(disk, plan)
    return plan, disk


def verify_lab_root_write_grant(
    args: argparse.Namespace, plan: dict[str, Any],
    *, control_dir: Path = Path("/run/gaslux-control"),
) -> None:
    """Require a second signed, strictly root-only COW lab grant.

    The normal plan explicitly denies production writes. An unsigned opt-in
    or a signed read-only plan by itself never authorizes pacstrap. The
    ephemeral lab signer must separately attest a host-owned/discardable
    overlay and immutable recovery checkpoint; guest independently enforces
    partition identity and all Windows hashes before any root mount.
    """
    require(args.root_write_grant is not None
            and args.grant_signature is not None,
            "no separate signed laboratory COW root-write grant")
    grant_file, signature_file = args.root_write_grant, args.grant_signature
    require(grant_file.is_file() and not grant_file.is_symlink()
            and 0 < grant_file.stat().st_size < 8192
            and signature_file.is_file() and not signature_file.is_symlink()
            and signature_file.stat().st_size == 64,
            "missing or oversized signed root-only grant")
    signed_bytes = grant_file.read_bytes()
    try:
        grant = json.loads(signed_bytes)
    except ValueError as error:
        raise SharedDiskHandoffRejected("invalid signed root-only grant") from error
    expected_keys = {
        "schemaVersion", "labOnly", "operation", "runId", "bootNonce",
        "signedPlanSha256", "targetVirtioSerial", "rootPartuuid",
        "rootFsUuid", "sourceWindowsGptSha256", "hostCheckpointSha256",
        "hostOverlayBackingProofSha256", "sourceImageReadOnly",
        "discardableOverlay", "windowsEspWritesAllowed",
        "strictPacmanBuilderSha256", "pacmanTrustGuardSha256",
    }
    require(type(grant) is dict and set(grant) == expected_keys
            and canonical(grant) == signed_bytes,
            "noncanonical, extra-field or ambiguous lab grant")
    require(type(grant["schemaVersion"]) is int
            and grant["schemaVersion"] == 1
            and grant["labOnly"] is True
            and grant["operation"] == "pacstrap-only-preexisting-fifth-ext4"
            and grant["runId"] == plan["runId"]
            and grant["bootNonce"] == plan["bootNonce"]
            and grant["targetVirtioSerial"] == SERIAL
            and grant["rootPartuuid"] == plan["partitions"][4]["uniqueGuid"]
            and grant["rootFsUuid"] == plan["rootFsUuid"]
            and grant["sourceWindowsGptSha256"] == plan["gptWindowsSha256"]
            and grant["signedPlanSha256"] == hashlib.sha256(
                args.plan.read_bytes()).hexdigest()
            and grant["sourceImageReadOnly"] is True
            and grant["discardableOverlay"] is True
            and grant["windowsEspWritesAllowed"] is False,
            "signed grant does not bind this exact fifth root and immutable COW")
    for name in ("hostCheckpointSha256", "hostOverlayBackingProofSha256"):
        value = grant[name]
        require(type(value) is str and SHA.fullmatch(value) is not None
                and value != "0" * 64,
                "missing host checkpoint / backing-chain attestation digest")
    outcome = subprocess.run([
        "openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
        str(args.public_key), "-sigfile", str(signature_file),
        "-rawin", "-in", str(grant_file),
    ], capture_output=True, timeout=20, check=False)
    require(outcome.returncode == 0,
            "Ed25519 root-only COW grant signature rejected")
    # A signed grant must authenticate the exact control programs that will
    # build and evaluate pacman's effective trust policy before root writes.
    # The real guest control medium is attached readonly=on and mounted ro.
    require(control_dir.is_absolute() and control_dir.is_dir()
            and not control_dir.is_symlink(),
            "missing canonical Archiso control directory for script identity")
    for filename, field in (
        ("strict-pacman.py", "strictPacmanBuilderSha256"),
        ("pacman-trust.py", "pacmanTrustGuardSha256"),
    ):
        expected = grant[field]
        require(type(expected) is str and SHA.fullmatch(expected) is not None
                and expected != "0" * 64,
                "signed package-policy program hash missing or malformed")
        source = control_dir / filename
        require(source.is_file() and not source.is_symlink()
                and 1024 < source.stat().st_size < 64 * 1024,
                "signed package-policy program is missing or unexpected")
        require(sha_file(source) == expected,
                "signed package-policy program bytes differ from root grant")


def prepare_signed_only_pacman(plan: dict[str, Any]) -> Path:
    """Prepare PR #34's effective signed-only policy on disposable /run tmpfs.

    This runs before the first writable Linux root mount. Missing read-only
    control scripts, keyrings, HTTPS mirrors, or effective signature policy
    are hard errors; no inherited live ISO pacman.conf is accepted.
    """
    control = Path("/run/gaslux-control")
    require(control.is_dir() and not control.is_symlink(),
            "missing verified read-only Archiso control volume")
    options = execute(["findmnt", "-rn", "-M", str(control), "-o", "OPTIONS"])
    require("ro" in options.split(","),
            "CachyOS pacman trust scripts must be read-only")
    builder = control / "strict-pacman.py"
    verifier = control / "pacman-trust.py"
    require(all(p.is_file() and not p.is_symlink()
                and p.stat().st_size > 1000 for p in (builder, verifier)),
            "trusted signed-only pacman builder or verifier missing")
    execute(["python3", str(builder), "--root", "/",
             "--run-id", plan["runId"], "--prepare-vm"], timeout=60)
    folder = Path("/run/gaslux-pacman-" + plan["runId"])
    require(folder.is_dir() and not folder.is_symlink()
            and folder.stat().st_uid == 0
            and stat.S_IMODE(folder.stat().st_mode) == 0o700,
            "non-private or missing strict pacman tmpfs policy")
    config = folder / "pacman-install.conf"
    target = folder / "pacman-target.conf"
    require(config.is_file() and not config.is_symlink()
            and target.is_file() and not target.is_symlink(),
            "missing immutable intended native pacman policy")
    execute(["python3", str(verifier), "--config", str(config)],
            timeout=40)
    require("SigLevel = Required DatabaseOptional TrustedOnly"
            in config.read_text(encoding="utf-8"),
            "missing exact signed-only pacman policy")
    return folder


def pacstrap_only(args: argparse.Namespace) -> None:
    plan, disk = guest_plan(args)
    verify_lab_root_write_grant(args, plan)
    root_id = plan["partitions"][4]["uniqueGuid"]
    by_id = Path("/dev/disk/by-partuuid") / root_id
    require(by_id.is_symlink() and by_id.resolve().is_block_device(),
            "fifth Linux partition symlink missing")
    root_partition = by_id.resolve()
    require(execute(["lsblk", "-no", "PKNAME", str(root_partition)]).strip()
            == disk.name, "fifth Linux root does not belong to signed Windows disk")
    require(execute(["blkid", "-s", "UUID", "-o", "value",
                     str(root_partition)]).strip().lower() ==
            plan["rootFsUuid"], "existing ext4 UUID not owned by transaction")
    require(ROOT.is_dir() and not ROOT.is_symlink()
            and ROOT.stat().st_uid == 0
            and stat.S_IMODE(ROOT.stat().st_mode) == 0o700
            and ROOT.parent == Path("/mnt")
            and not any(ROOT.iterdir()),
            "root mount target not empty, private or root-owned")
    for tool in ("pacstrap", "pacman-key", "arch-chroot", "mount", "umount"):
        require(subprocess.run(["which", tool], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL).returncode == 0,
                "missing native CachyOS stage capability: " + tool)
    require(Path("/usr/share/pacman/keyrings/archlinux.gpg").is_file()
            and Path("/usr/share/pacman/keyrings/cachyos.gpg").is_file(),
            "pinned live ISO lacks signing keyrings")
    strict_folder = prepare_signed_only_pacman(plan)
    strict_config = strict_folder / "pacman-install.conf"
    execute(["mount", "-t", "ext4", "-o", "rw,nosuid,nodev",
             str(root_partition), str(ROOT)])
    try:
        verify_mounted_source(ROOT, root_partition, "ext4", readonly=False)
        require(not (ROOT / "etc/os-release").exists()
                and set(x.name for x in ROOT.iterdir()) <= {"lost+found"},
                "pre-existing OS or foreign root content")
        # Only the transaction-owned ext4 root is writable in this VM.
        # NEVER pass /dev/sda, its ESP, WinRE or Windows partition to pacstrap.
        keyring = ROOT / "etc/pacman.d/gnupg"
        keyring.mkdir(parents=True, exist_ok=False)
        execute(["pacman-key", "--gpgdir", str(keyring), "--init"], timeout=90)
        execute(["pacman-key", "--gpgdir", str(keyring),
                 "--populate", "archlinux", "cachyos"], timeout=120)
        # Official keyring identity already proven in the separate
        # CachyOS VM-only installation test. Never change SigLevel.
        execute(["pacman-key", "--gpgdir", str(keyring), "--list-keys",
                 "882DCFE48E2051D48E2562ABF3B607488DB35A47"])
        packages = [
            "base", "linux-cachyos-lts", "mkinitcpio", "grub", "efibootmgr",
            "cachyos-keyring", "cachyos-mirrorlist", "cachyos-settings",
            "cachyos-hooks", "sudo", "e2fsprogs", "dosfstools", "python",
        ]
        execute(["pacstrap", "-K", "-C", str(strict_config), str(ROOT), *packages], timeout=2200)
        # Retain exact, signed-only repository policy for installed updates.
        import shutil
        shutil.copyfile(strict_folder / "pacman-target.conf", ROOT / "etc/pacman.conf")
        for name in ("mirrorlist", "cachyos-mirrorlist"):
            shutil.copyfile(strict_folder / name,
                            ROOT / "etc/pacman.d" / name)
        require((ROOT / "etc/pacman.conf").read_bytes() ==
                (strict_folder / "pacman-target.conf").read_bytes(),
                "installed package signature policy does not match validated source")
        require((ROOT / "boot/vmlinuz-linux-cachyos-lts").is_file()
                and (ROOT / "usr/share/libalpm/scripts/cachyos-branding").is_file(),
                "signed native kernel/CachyOS branding packages absent")
        execute(["arch-chroot", str(ROOT),
                 "/usr/share/libalpm/scripts/cachyos-branding", "os-release"],
                timeout=75)
        release = (ROOT / "etc/os-release").read_text(encoding="utf-8")
        require("ID=cachyos\n" in release
                and "ID_LIKE=arch\n" in release,
                "native CachyOS identity not established by signed branding")
        (ROOT / ".gaslux-lab-root-owner").write_text(
            plan["runId"] + "\n", encoding="ascii")
        os.sync()
    finally:
        execute(["umount", str(ROOT)])
    require(strict_gpt_evidence(disk, plan)["bothGptCopiesCrcVerified"],
            "Windows GPT changed during root-only package installation")
    protected_files_readonly(disk, plan)
    print("GASLUX_SHARED_COW_NATIVE_CACHYOS_PACSTRAP_ROOT_ONLY=1", flush=True)
    print("GASLUX_SHARED_COW_ESP_BOOTLOADER_NOT_INSTALLED=1", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument("--expected-root-uuid", required=True)
    parser.add_argument("--lab-install", action="store_true")
    parser.add_argument("--root-write-grant", type=Path)
    parser.add_argument("--grant-signature", type=Path)
    args = parser.parse_args()
    try:
        if args.lab_install:
            pacstrap_only(args)
        else:
            guest_plan(args)
            print("GASLUX_SHARED_COW_PREWRITE_GUEST_PROOF_ONLY=1",
                  flush=True)
        print("GASLUX_SHARED_COW_WINDOWS_INPLACE_RECOVERY_NOT_VERIFIED=1",
              flush=True)
    except (SharedDiskHandoffRejected, OSError, ValueError, RuntimeError,
            subprocess.TimeoutExpired) as exc:
        print("GASLUX_SHARED_COW_PREWRITE_FAILURE: " + str(exc), flush=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
