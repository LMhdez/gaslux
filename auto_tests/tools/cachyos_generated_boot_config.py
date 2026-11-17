#!/usr/bin/env python3
"""Render the actual Gaslux Archiso handoff for a disposable QEMU boot.

Never installs Linux, signs a plan, changes boot firmware or accesses Windows.
Only the serial-console kernel diagnostics differ from the generated entry.
The source ISO is SHA-256 checked again by the CachyOS handoff backend.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parents[2]
_SOURCE = _HERE / "assets/live/cachyos-archiso-handoff.py"
_SPEC = importlib.util.spec_from_file_location("gaslux_lab_archiso_handoff", _SOURCE)
assert _SPEC is not None and _SPEC.loader is not None
_HANDOFF = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_HANDOFF)

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_DIAGNOSTIC_FLAGS = (
    " console=tty0 console=ttyS0,115200n8"
    " systemd.log_target=console systemd.log_level=info"
    " systemd.unit=multi-user.target"
)
_HEADER = (
    "serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1\n"
    "terminal_input serial\n"
    "terminal_output serial\n"
    "set default=gaslux-cachyos-archiso\n"
    "set timeout=0\n"
)


class LabBootError(ValueError):
    """The generated handoff cannot safely be used for a VM-only boot test."""


def require(ok: bool, message: str) -> None:
    if not ok:
        raise LabBootError(message)


def generate(
    iso_path: Path,
    pinned_sha256: str,
    volume_uuid: str,
    iso_root: Path,
) -> tuple[str, dict[str, Any]]:
    """Return exact backend-rendered GRUB, with only read-only serial diagnostics."""
    require(
        isinstance(pinned_sha256, str) and _HASH.fullmatch(pinned_sha256) is not None,
        "invalid SHA-256 pin",
    )
    require(
        isinstance(volume_uuid, str) and _UUID.fullmatch(volume_uuid) is not None,
        "invalid disposable volume UUID",
    )
    require(
        iso_path.name == "cachyos.iso" and iso_path.is_file() and not iso_path.is_symlink(),
        "expected a regular, unlinked cachyos.iso",
    )
    require(iso_path.parent.is_dir() and not iso_path.parent.is_symlink(), "unsafe ISO directory")
    require(iso_root.is_dir() and not iso_root.is_symlink(), "ISO root is absent or symlinked")
    require(iso_path.parent.resolve() != iso_root.resolve(), "ISO mounts must be distinct")

    plan = {
        "schemaVersion": 1,
        "firmware": "uefi",
        "secureBootEnabled": False,
        "runId": "gaslux-verified-boot-smoke",
        "isoStorageFilesystem": "ext4",
        "isoStorageUuid": volume_uuid,
        "isoRelativePath": "/cachyos.iso",
        "isoSha256": pinned_sha256,
        "isoSizeBytes": iso_path.stat().st_size,
    }
    handoff = _HANDOFF.prepare(\n        plan, storage_root=iso_path.parent, iso_root=iso_root,\n        require_mounted_iso=True,\n    )
    require(
        handoff["ok"] is True
        and handoff["isoSha256Verified"] is True
        and handoff["isoLayoutVerified"] is True
        and handoff["productionInstallSupported"] is False
        and handoff["windowsRecoveryVerified"] is False,
        "unexpected backend readiness or distribution identity",
    )

    original = handoff["grubEntry"]
    require(
        isinstance(original, str)
        and original.count("menuentry 'CachyOS Archiso (experimental)'") == 1,
        "unexpected backend GRUB menu",
    )
    lines = original.splitlines(keepends=True)
    linux = [i for i, line in enumerate(lines) if line.startswith("    linux (gaslux_iso)/")]
    initrd = [line for line in lines if line.startswith("    initrd (gaslux_iso)/")]
    require(
        len(linux) == 1
        and len(initrd) == 1
        and len([line for line in lines if line.startswith("    loopback ")]) == 1,
        "expected exactly one live kernel, initramfs and ISO loopback",
    )
    kernel = handoff["liveKernelPath"]
    initramfs = handoff["liveInitramfsPath"]
    require(
        lines[linux[0]].startswith(f"    linux (gaslux_iso)/{kernel} ")
        and initrd[0].strip() == f"initrd (gaslux_iso)/{initramfs}",
        "kernel/initramfs differ from backend identity",
    )
    require(
        "img_dev=UUID=" + volume_uuid + " img_loop=/cachyos.iso" in lines[linux[0]],
        "GRUB img_dev/img_loop no longer reflect the disposable disk",
    )
    require(lines[linux[0]].endswith("\n"), "GRUB kernel entry is not line-terminated")
    lines[linux[0]] = lines[linux[0]][:-1] + _DIAGNOSTIC_FLAGS + "\n"
    config = _HEADER + "".join(lines)
    evidence = {
        "schemaVersion": 1,
        "source": "gaslux-generated-cachyos-archiso-qemu-only",
        "runId": plan["runId"],
        "isoSha256": pinned_sha256,
        "grubSha256": hashlib.sha256(config.encode("utf-8")).hexdigest(),
        "generatedKernelPath": kernel,
        "generatedInitramfsPath": initramfs,
        "generatedFromBackend": True,
        "addedKernelFlags": _DIAGNOSTIC_FLAGS.strip().split(" "),
        "labVolumeUuid": volume_uuid,
        "sourcePlanSigned": False,
        "mountedIsoProvenByBackend": False,
        "actualBootVerified": False,
        "windowsInstalled": False,
        "windowsRecoveryVerified": False,
        "productionInstallSupported": False,
        "stable": False,
    }
    return config, evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("iso", type=Path)
    parser.add_argument("pinned_sha256")
    parser.add_argument("disposable_ext4_uuid")
    parser.add_argument("mounted_iso_root", type=Path)
    parser.add_argument("output_grub_cfg", type=Path)
    parser.add_argument("output_evidence_json", type=Path)
    args = parser.parse_args(argv)
    try:
        config, evidence = generate(
            args.iso,
            args.pinned_sha256,
            args.disposable_ext4_uuid,
            args.mounted_iso_root,
        )
        # The caller creates a private temp directory. Refuse replacing files.
        for file in (args.output_grub_cfg, args.output_evidence_json):
            require(
                not file.exists() and not file.is_symlink(),
                "refusing to overwrite existing boot artifact",
            )
            require(
                file.parent.is_dir() and not file.parent.is_symlink(),
                "boot artifact parent is unsafe",
            )
        for path, data in (
            (args.output_grub_cfg, config),
            (args.output_evidence_json, json.dumps(evidence, sort_keys=True) + "\n"),
        ):
            with path.open("x", encoding="utf-8") as stream:
                stream.write(data)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print("Verified backend GRUB generated for disposable VM only; Windows not tested.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
