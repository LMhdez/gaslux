#!/usr/bin/env python3
"""Disposable Bazzite QEMU-only disk ownership and backing-file audit.

This is a host-side CI laboratory tool, NOT a Gaslux Windows disk planner.
It never opens physical devices or authorizes installation on Windows media.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
from pathlib import Path

ROOT_NAME = "bazzite-owned-qcow2"
SIZE_GIB = 70
SERIAL_PATTERN = re.compile(r"GLXBAZ-[0-9A-F]{12}\Z")


class LabRefusal(RuntimeError):
    """Fail closed without modifying unrelated resources."""


def _owned_root(root: Path, runner_temp: Path, *, must_exist: bool) -> Path:
    if not root.is_absolute() or not runner_temp.is_absolute():
        raise LabRefusal("Both paths must be absolute")
    if root.name != ROOT_NAME or root.parent.resolve(strict=True) != runner_temp.resolve(strict=True):
        raise LabRefusal("Target must be a direct child of the private runner temp directory")
    if root.is_symlink():
        raise LabRefusal("Symlink lab directory refused")
    if must_exist and (not root.is_dir() or not root.exists()):
        raise LabRefusal("Missing private lab directory")
    if not must_exist and (root.exists() or root.is_symlink()):
        raise LabRefusal("Refusing to reuse an existing lab directory")
    return root


def _owned_file(path: Path) -> os.stat_result:
    if path.is_symlink():
        raise LabRefusal(f"Symlink refused: {path.name}")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise LabRefusal(f"Unsafe file identity: {path.name}")
    return info


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _qemu(*args: str) -> dict | None:
    result = subprocess.run(
        ["qemu-img", *args], check=True, text=True, capture_output=True, timeout=60
    )
    if args[0] == "info":
        return json.loads(result.stdout)
    return None


def _verify_images(root: Path, manifest: dict) -> None:
    base = root / "blank-base.qcow2"
    overlay = root / "scratch-overlay.qcow2"
    base_stat = _owned_file(base)
    overlay_stat = _owned_file(overlay)
    if (base_stat.st_dev, base_stat.st_ino) != tuple(manifest["baseIdentity"]):
        raise LabRefusal("Base inode identity changed")
    if (overlay_stat.st_dev, overlay_stat.st_ino) != tuple(manifest["overlayIdentity"]):
        raise LabRefusal("Overlay inode identity changed")
    if base_stat.st_mode & 0o222:
        raise LabRefusal("Base image must be read-only")
    size_bytes = SIZE_GIB * (1024**3)
    base_info = _qemu("info", "--output=json", str(base))
    overlay_info = _qemu("info", "--output=json", str(overlay))
    if (
        base_info is None
        or base_info.get("format") != "qcow2"
        or base_info.get("virtual-size") != size_bytes
        or base_info.get("backing-filename")
        or overlay_info is None
        or overlay_info.get("format") != "qcow2"
        or overlay_info.get("virtual-size") != size_bytes
        or Path(overlay_info.get("full-backing-filename", "/invalid")).resolve() != base
    ):
        raise LabRefusal("Unexpected QCOW2 geometry or backing-chain identity")
    if _sha256(base) != manifest["blankBaseSha256"]:
        raise LabRefusal("Immutable blank backing image changed")


def prepare(root: Path, runner_temp: Path) -> dict:
    root = _owned_root(root, runner_temp, must_exist=False)
    root.mkdir(mode=0o700)
    base = root / "blank-base.qcow2"
    overlay = root / "scratch-overlay.qcow2"
    _qemu("create", "-f", "qcow2", str(base), f"{SIZE_GIB}G")
    base_stat = _owned_file(base)
    os.chmod(base, 0o444)
    _qemu("create", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(overlay))
    overlay_stat = _owned_file(overlay)
    manifest = {
        "labOnly": True,
        "firmware": "uefi",
        "partitionTableRequested": "gpt",
        "windowsGuestAttached": False,
        "installationAuthorized": False,
        "storageInspectionOnly": True,
        "guestDiskCount": 1,
        "guestDiskSerial": "GLXBAZ-" + secrets.token_hex(6).upper(),
        "virtualSizeBytes": SIZE_GIB * 1024**3,
        "blankBaseSha256": _sha256(base),
        "baseIdentity": [base_stat.st_dev, base_stat.st_ino],
        "overlayIdentity": [overlay_stat.st_dev, overlay_stat.st_ino],
        "root": str(root),
    }
    _verify_images(root, manifest)
    temp = root / "manifest.json.partial"
    with temp.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(root / "manifest.json")
    return manifest


def audit(root: Path, runner_temp: Path, *, discard: bool) -> dict:
    root = _owned_root(root, runner_temp, must_exist=True)
    manifest_path = root / "manifest.json"
    _owned_file(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (
        manifest.get("root") != str(root)
        or manifest.get("labOnly") is not True
        or manifest.get("firmware") != "uefi"
        or manifest.get("partitionTableRequested") != "gpt"
        or manifest.get("windowsGuestAttached") is not False
        or manifest.get("installationAuthorized") is not False
        or manifest.get("storageInspectionOnly") is not True
        or manifest.get("guestDiskCount") != 1
        or not SERIAL_PATTERN.fullmatch(str(manifest.get("guestDiskSerial", "")))
        or manifest.get("virtualSizeBytes") != SIZE_GIB * 1024**3
    ):
        raise LabRefusal("Untrusted or contradictory host-only disk plan")
    _verify_images(root, manifest)
    result = {
        "labOnly": True,
        "windowsGuestAttached": False,
        "nativeInstallationVerified": False,
        "windowsDualBootVerified": False,
        "atomicUpdatesVerified": False,
        "windowsRecoveryVerified": False,
        "blankBackingUnchanged": True,
        "overlayDiscarded": False,
    }
    if discard:
        (root / "scratch-overlay.qcow2").unlink()
        if _sha256(root / "blank-base.qcow2") != manifest["blankBaseSha256"]:
            raise LabRefusal("Backing mismatch after overlay removal")
        result["overlayDiscarded"] = True
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["prepare", "audit", "discard"])
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--runner-temp", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = (
            prepare(args.root, args.runner_temp)
            if args.operation == "prepare"
            else audit(args.root, args.runner_temp, discard=args.operation == "discard")
        )
    except (LabRefusal, OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        parser.exit(2, f"REFUSED: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
