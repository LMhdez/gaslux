#!/usr/bin/env python3
"""Read-only, fail-closed audit of native Q4OS process-job hook sources.

The transport MUST independently SHA-256-check the complete official ISO,
mount it read-only and extract these exact files from its live SquashFS.
This module never runs the extracted commands or authorizes installation.
"""

from __future__ import annotations

import hashlib
import re
import stat
from pathlib import Path

from gaslux_q4os_calamares_policy import CalamaresRefusal, _yaml, audit_q4os_calamares

_HOOK_SOURCES = (
    "usr/lib/calamares/modules/q4oshook2/module.desc",
    "usr/lib/calamares/modules/q4oshook3/module.desc",
    "usr/lib/calamares/modules/q4oshook5/module.desc",
    "usr/sbin/q4os-hook2a.sh",
    "usr/sbin/q4os-hook3a.sh",
    "usr/sbin/q4os-hook3b.sh",
    "usr/sbin/q4oshook1.sh",
    "usr/sbin/q4oshook4.sh",
    "usr/share/apps/q4os_system/bhooks/bhook1_50_live1.sh",
)

_MANIFEST = "q4os-hooks-files.sha256"
_SHA256_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9_.+-]+)$")


def _read_regular(path: Path, max_bytes: int) -> bytes:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= max_bytes:
            raise CalamaresRefusal(f"Q4OS source missing, symlinked or oversized: {path.name}")
        data = path.read_bytes()
        if len(data) != info.st_size:
            raise CalamaresRefusal(f"Q4OS source changed during read: {path.name}")
        return data
    except OSError as exc:
        raise CalamaresRefusal(f"Q4OS source unreadable: {path.name}") from exc


def audit_q4os_native_hooks(root: Path) -> dict:
    """Return exact source hashes, never executable authority.

    The result is *not* a claim that any Q4OS shell script is safe to run.
    """
    if not isinstance(root, Path) or not root.is_absolute() or root.is_symlink():
        raise CalamaresRefusal("Hook evidence root must be an absolute non-symlink directory")
    if not root.is_dir():
        raise CalamaresRefusal("Hook evidence root is missing")
    calamares = audit_q4os_calamares(root)
    hooks_dir = root / "native-hooks"
    if hooks_dir.is_symlink() or not hooks_dir.is_dir():
        raise CalamaresRefusal("Native hooks evidence directory invalid")
    expected = {p.replace("/", "__") for p in _HOOK_SOURCES}
    manifest = _read_regular(hooks_dir / _MANIFEST, 4096).decode("ascii", errors="strict")
    rows = manifest.splitlines()
    if len(rows) != len(expected):
        raise CalamaresRefusal("Q4OS native hook manifest entry count differs")
    source_hashes = {}
    for row in rows:
        match = _SHA256_LINE.fullmatch(row)
        if match is None:
            raise CalamaresRefusal("Malformed or unsafe Q4OS native hook manifest")
        expected_hash, filename = match.groups()
        if filename not in expected or filename in source_hashes:
            raise CalamaresRefusal("Unexpected, duplicate or missing Q4OS hook source")
        actual = hashlib.sha256(_read_regular(hooks_dir / filename, 131072)).hexdigest()
        if actual != expected_hash:
            raise CalamaresRefusal(f"Q4OS source SHA-256 mismatch: {filename}")
        source_hashes[filename] = actual
    if set(source_hashes) != expected:
        raise CalamaresRefusal("Missing required Q4OS hook source")
    scripts = [name for name in source_hashes if name.endswith(".sh")]
    descriptors = [name for name in source_hashes if name.endswith("__module.desc")]
    if len(scripts) != 6 or len(descriptors) != 3:
        raise CalamaresRefusal("Q4OS native module/script inventory incomplete")
    cfg = _yaml(root, "etc__calamares__settings.conf")
    jobs = cfg["sequence"][1]["exec"]
    indexes = [jobs.index(n) for n in ("q4oshook2", "bootloader", "q4oshook3", "initramfs", "q4oshook5")]
    if indexes != sorted(indexes):
        raise CalamaresRefusal("Q4OS module/GRUB/initramfs ordering differs")
    return {
        "distribution": "q4os",
        "version": calamares["version"],
        "sourcesFromVerifiedIsoPrerequisite": True,
        "nativeHookSourcesCount": len(source_hashes),
        "nativeHookSourceSha256": dict(sorted(source_hashes.items())),
        "moduleDescriptorSourceCount": len(descriptors),
        "shellSourceCount": len(scripts),
        "nativeCalamaresConfigVerified": True,
        "nativeHookCommandsExecuted": False,
        "hookExecutionAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "nativeInstallationProven": False,
        "diskWrites": 0,
    }
