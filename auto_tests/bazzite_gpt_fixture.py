#!/usr/bin/env python3
"""Build and audit a disposable GPT layout fixture; never a Windows disk image.

The fixture has GPT type GUIDs and labels resembling an ESP, MSR and Windows
basic-data partition, but contains no Windows installation or filesystem.
It is for installer discovery only and cannot authorize installation.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

ROOT_NAME = "bazzite-gpt-fixture"
IMAGE_NAME = "windows-layout-no-os.raw"
OVERLAY_NAME = "gpt-layout-scratch.qcow2"
SIZE_GIB = 70
PARTITIONS = (
    (
        1,
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
        "GLX-ESP-NO-FILESYSTEM",
    ),
    (
        2,
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE",
        "GLX-MSR-NO-OS",
    ),
    (
        3,
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
        "GLX-WINDOWS-NO-OS",
    ),
)


class Refusal(RuntimeError):
    """Fail closed when fixture identity or geometry is not exact."""


def _run(*args: str, timeout: int = 60) -> str:
    result = subprocess.run(
        list(args), check=True, text=True, capture_output=True, timeout=timeout
    )
    return result.stdout


def _root(path: Path, runner_temp: Path, *, exists: bool) -> Path:
    if not path.is_absolute() or not runner_temp.is_absolute():
        raise Refusal("Paths must be absolute")
    if (
        path.name != ROOT_NAME
        or path.parent.resolve(strict=True) != runner_temp.resolve(strict=True)
    ):
        raise Refusal("Fixture must be a direct child of RUNNER_TEMP")
    if path.is_symlink():
        raise Refusal("Fixture symlink refused")
    if exists and (not path.is_dir() or not path.exists()):
        raise Refusal("Fixture directory missing")
    if not exists and (path.exists() or path.is_symlink()):
        raise Refusal("Refusing to reuse fixture directory")
    return path


def _file(path: Path) -> os.stat_result:
    if path.is_symlink():
        raise Refusal(f"Symlink refused: {path.name}")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise Refusal(f"Unsafe file identity: {path.name}")
    return info


def _hash_sparse(path: Path) -> str:
    """Hash allocated extents and their offsets without reading sparse zero ranges."""
    info = path.stat()
    digest = hashlib.sha256()
    digest.update(b"gaslux-sparse-file-v1\\0")
    digest.update(info.st_size.to_bytes(8, "big"))
    digest.update(info.st_blocks.to_bytes(8, "big"))
    fd = os.open(path, os.O_RDONLY)
    try:
        offset = 0
        while offset < info.st_size:
            try:
                data = os.lseek(fd, offset, os.SEEK_DATA)
            except OSError as exc:
                if exc.errno == errno.ENXIO:
                    break
                raise Refusal("Filesystem cannot prove sparse extent boundaries") from exc
            hole = os.lseek(fd, data, os.SEEK_HOLE)
            if hole <= data:
                raise Refusal("Invalid sparse extent geometry")
            digest.update(data.to_bytes(8, "big"))
            digest.update((hole - data).to_bytes(8, "big"))
            remaining = hole - data
            os.lseek(fd, data, os.SEEK_SET)
            while remaining:
                chunk = os.read(fd, min(4 * 1024 * 1024, remaining))
                if not chunk:
                    raise Refusal("Unexpected EOF inside allocated extent")
                digest.update(chunk)
                remaining -= len(chunk)
            offset = hole
    finally:
        os.close(fd)
    return digest.hexdigest()


def _inspect(root: Path, manifest: dict) -> None:
    image = root / IMAGE_NAME
    overlay = root / OVERLAY_NAME
    info = _file(image)
    overlay_info = _file(overlay)
    if (info.st_dev, info.st_ino) != tuple(manifest["baseIdentity"]):
        raise Refusal("GPT base inode identity changed")
    if (overlay_info.st_dev, overlay_info.st_ino) != tuple(manifest["overlayIdentity"]):
        raise Refusal("GPT overlay inode identity changed")
    if info.st_mode & 0o222:
        raise Refusal("GPT base must be read-only")
    if info.st_size != SIZE_GIB * 1024**3:
        raise Refusal("Unexpected GPT base size")
    if _hash_sparse(image) != manifest["baseSparseIdentitySha256"]:
        raise Refusal("GPT base hash changed")
    _run("sgdisk", "--verify", str(image))
    for number, type_guid, label in PARTITIONS:
        details = _run("sgdisk", f"--info={number}", str(image))
        normalized = details.upper()
        if type_guid not in normalized or label.upper() not in normalized:
            raise Refusal(
                f"GPT partition {number} identity mismatch: {details!r}"
            )
    overlay_info_json = json.loads(
        _run("qemu-img", "info", "--output=json", str(overlay))
    )
    if (
        overlay_info_json.get("format") != "qcow2"
        or overlay_info_json.get("virtual-size") != SIZE_GIB * 1024**3
        or Path(
            overlay_info_json.get("full-backing-filename", "/invalid")
        ).resolve()
        != image
    ):
        raise Refusal("Overlay backing identity or geometry mismatch")


def prepare(root: Path, runner_temp: Path) -> dict:
    root = _root(root, runner_temp, exists=False)
    root.mkdir(mode=0o700)
    image = root / IMAGE_NAME
    overlay = root / OVERLAY_NAME
    with image.open("xb") as stream:
        stream.truncate(SIZE_GIB * 1024**3)
    _run(
        "sgdisk",
        "--clear",
        "--new=1:2048:+300M",
        "--typecode=1:EF00",
        "--change-name=1:GLX-ESP-NO-FILESYSTEM",
        "--new=2:0:+16M",
        "--typecode=2:0C01",
        "--change-name=2:GLX-MSR-NO-OS",
        "--new=3:0:+24G",
        "--typecode=3:0700",
        "--change-name=3:GLX-WINDOWS-NO-OS",
        str(image),
    )
    _run("sgdisk", "--verify", str(image))
    image_info = _file(image)
    os.chmod(image, 0o444)
    _run(
        "qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", str(image), str(overlay)
    )
    overlay_info = _file(overlay)
    manifest = {
        "labOnly": True,
        "firmware": "uefi",
        "partitionTable": "gpt",
        "fixtureOnly": True,
        "containsWindowsInstallation": False,
        "containsFilesystems": False,
        "installationAuthorized": False,
        "storageInspectionOnly": True,
        "virtualSizeBytes": SIZE_GIB * 1024**3,
        "baseSparseIdentitySha256": _hash_sparse(image),
        "baseIdentity": [image_info.st_dev, image_info.st_ino],
        "overlayIdentity": [overlay_info.st_dev, overlay_info.st_ino],
        "root": str(root),
        "partitions": [
            {"number": n, "typeGuid": type_guid, "name": name}
            for n, type_guid, name in PARTITIONS
        ],
    }
    _inspect(root, manifest)
    partial = root / "manifest.json.partial"
    with partial.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    partial.replace(root / "manifest.json")
    return manifest


def audit(root: Path, runner_temp: Path, *, discard: bool) -> dict:
    root = _root(root, runner_temp, exists=True)
    manifest_path = root / "manifest.json"
    _file(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (
        manifest.get("root") != str(root)
        or manifest.get("labOnly") is not True
        or manifest.get("firmware") != "uefi"
        or manifest.get("partitionTable") != "gpt"
        or manifest.get("fixtureOnly") is not True
        or manifest.get("containsWindowsInstallation") is not False
        or manifest.get("containsFilesystems") is not False
        or manifest.get("installationAuthorized") is not False
        or manifest.get("storageInspectionOnly") is not True
        or manifest.get("virtualSizeBytes") != SIZE_GIB * 1024**3
    ):
        raise Refusal("Untrusted or contradictory GPT fixture manifest")
    _inspect(root, manifest)
    result = {
        "labOnly": True,
        "gptVerified": True,
        "containsWindowsInstallation": False,
        "containsFilesystems": False,
        "installationAuthorized": False,
        "baseUnchanged": True,
        "overlayDiscarded": False,
    }
    if discard:
        (root / OVERLAY_NAME).unlink()
        if _hash(root / IMAGE_NAME) != manifest["baseSparseIdentitySha256"]:
            raise Refusal("GPT base changed after overlay removal")
        result["overlayDiscarded"] = True
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("prepare", "audit", "discard"))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--runner-temp", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = (
            prepare(args.root, args.runner_temp)
            if args.operation == "prepare"
            else audit(args.root, args.runner_temp, discard=args.operation == "discard")
        )
    except (Refusal, OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        parser.exit(2, f"REFUSED: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
