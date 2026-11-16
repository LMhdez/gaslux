#!/usr/bin/env python3
"""Audit the *effective* native Q4OS Calamares configuration extracted from one ISO.

LAB ONLY. Input provenance must be established by the read-only pinned-ISO
extraction shell tool. No target disk, installer or bootloader command is run.
"""

from __future__ import annotations

import hashlib
import re
import stat
from pathlib import Path

import yaml

_REQUIRED = (
    "etc__os-release",
    "etc__q4os_version",
    "etc__calamares__settings.conf",
    "etc__calamares__modules__partition.conf",
    "etc__calamares__modules__unpackfs.conf",
    "etc__calamares__modules__mount.conf",
    "etc__calamares__modules__fstab.conf",
    "etc__calamares__modules__bootloader.conf",
    "etc__calamares__modules__grubcfg.conf",
    "etc__calamares__modules__users.conf",
    "etc__calamares__modules__packages.conf",
    "etc__calamares__modules__displaymanager.conf",
)


class CalamaresRefusal(ValueError):
    """ISO-derived installer configuration did not satisfy the lab contract."""


class _UniqueYaml(yaml.SafeLoader):
    pass


def _unique_mapping(loader, node):
    result = {}
    for key_node, val_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise CalamaresRefusal("Non-string or repeated YAML key")
        result[key] = loader.construct_object(val_node)
    return result


_UniqueYaml.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def _content(root: Path, name: str) -> bytes:
    path = root / name
    try:
        meta = path.lstat()
        if not stat.S_ISREG(meta.st_mode) or not 0 < meta.st_size <= 128 * 1024:
            raise CalamaresRefusal("Missing, symlinked or oversized installer evidence: " + name)
        return path.read_bytes()
    except OSError as exc:
        raise CalamaresRefusal("Unreadable installer evidence: " + name) from exc


def _yaml(root: Path, name: str) -> dict:
    try:
        data = yaml.load(_content(root, name).decode("utf-8"), Loader=_UniqueYaml)
    except (UnicodeError, yaml.YAMLError, RecursionError) as exc:
        raise CalamaresRefusal("Invalid native Calamares YAML: " + name) from exc
    if not isinstance(data, dict):
        raise CalamaresRefusal("Installer settings must be YAML mappings")
    return data


def audit_q4os_calamares(root: Path) -> dict:
    """Validate source identity and relevant Calamares install/boot semantics.

    This intentionally does *not* authorize writes. Most important, Q4OS's
    default installEFIFallback=true could overwrite EFI/BOOT/BOOTX64.EFI
    on a Windows ESP, so that path is prohibited in a production backend.
    """
    if not isinstance(root, Path) or not root.is_absolute() or root.is_symlink():
        raise CalamaresRefusal("Evidence root must be an absolute non-symlink directory")
    if not root.is_dir():
        raise CalamaresRefusal("Installer evidence directory missing")

    files = {name: _content(root, name) for name in _REQUIRED}
    os_release = files["etc__os-release"].decode("utf-8")
    version = files["etc__q4os_version"].decode("utf-8").strip()
    if (
        re.search(r'(?m)^ID="?debian"?$', os_release) is None
        or re.search(r'(?m)^VERSION_ID="?13"?$', os_release) is None
        or version != "6.10-deb13u1"
    ):
        raise CalamaresRefusal("Pinned Q4OS 6.10 native identity mismatch")

    settings = _yaml(root, "etc__calamares__settings.conf")
    unpack = _yaml(root, "etc__calamares__modules__unpackfs.conf")
    boot = _yaml(root, "etc__calamares__modules__bootloader.conf")
    partition = _yaml(root, "etc__calamares__modules__partition.conf")
    packages = _yaml(root, "etc__calamares__modules__packages.conf")
    sequence = settings.get("sequence")
    if not isinstance(sequence, list) or len(sequence) != 3:
        raise CalamaresRefusal("Unexpected Calamares stage count")
    if not all(isinstance(v, dict) and len(v) == 1 for v in sequence):
        raise CalamaresRefusal("Malformed Calamares sequence")
    if list(sequence[0]) != ["show"] or list(sequence[1]) != ["exec"]:
        raise CalamaresRefusal("Unexpected Calamares stage order")
    jobs = sequence[1]["exec"]
    if not isinstance(jobs, list) or not all(isinstance(v, str) for v in jobs):
        raise CalamaresRefusal("Malformed Calamares execution jobs")
    for marker in (
        "partition",
        "mount",
        "unpackfs",
        "q4oshook2",
        "grubcfg",
        "bootloader",
        "q4oshook3",
        "packages",
        "initramfs",
        "q4oshook5",
        "umount",
    ):
        if jobs.count(marker) != 1:
            raise CalamaresRefusal("Native install job missing or repeated: " + marker)
    if jobs[:3] != ["partition", "mount", "unpackfs"]:
        raise CalamaresRefusal("Calamares target storage sequence mismatch")
    if not (jobs.index("grubcfg") < jobs.index("bootloader") < jobs.index("q4oshook3")):
        raise CalamaresRefusal("Calamares bootloader sequence mismatch")
    if settings.get("dont-chroot") is not False or settings.get("oem-setup") is not False:
        raise CalamaresRefusal("Q4OS is not configured for native installation")
    sources = unpack.get("unpack")
    if sources != [
        {
            "source": "/run/live/medium/live/filesystem.squashfs",
            "sourcefs": "squashfs",
            "destination": "",
        }
    ]:
        raise CalamaresRefusal("Q4OS payload source differs from pinned live filesystem")
    if (
        boot.get("efiBootLoader") != "grub"
        or boot.get("grubInstall") != "grub-install"
        or boot.get("grubCfg") != "/boot/grub/grub.cfg"
    ):
        raise CalamaresRefusal("Native Q4OS EFI GRUB config mismatch")
    if (
        partition.get("defaultFileSystemType") != "ext4"
        or partition.get("efi", {}).get("mountPoint") != "/boot/efi"
        or partition.get("initialPartitioningChoice") != "none"
    ):
        raise CalamaresRefusal("Q4OS partitioning policy differs from audited ISO")
    if packages.get("backend") != "apt":
        raise CalamaresRefusal("Unexpected package backend")
    return {
        "distribution": "q4os",
        "version": version,
        "nativeCalamaresConfigVerified": True,
        "nativeInstallSequenceObserved": True,
        "unpackSourceBoundToIsoRoot": True,
        "uefiBootloader": "grub",
        "upstreamInstallsEfiFallback": boot.get("installEFIFallback") is True,
        "windowsEspFallbackWriteAuthorized": False,
        "targetFilesystem": "ext4",
        "calamaresModulesSha256": {
            name: hashlib.sha256(contents).hexdigest() for name, contents in files.items()
        },
        "installedSystemBootVerified": False,
        "installationAuthorized": False,
        "diskWrites": 0,
    }
