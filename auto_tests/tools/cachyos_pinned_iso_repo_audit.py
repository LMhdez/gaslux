#!/usr/bin/env python3
"""Read-only policy audit of the EXACT SHA-pinned official CachyOS live ISO.

Runs the ISO's own pacman-conf in a read-only SquashFS chroot and delegates
signature requirements to the shared experimental pacman trust guard.
This never initializes keys, downloads packages, mounts writable volumes,
repairs policy, or installs Linux. A weak policy MUST block the next stage.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from collections.abc import Callable
from typing import Any

_HERE = Path(__file__).resolve().parents[2]
_GUARD = _HERE / "assets/live/cachyos-pacman-trust.py"
_SPEC = importlib.util.spec_from_file_location("gaslux_cachyos_repo_guard", _GUARD)
assert _SPEC and _SPEC.loader
_POLICY = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_POLICY)

_PIN = re.compile(r"[0-9a-f]{64}\Z")
_LOOP = re.compile(r"/dev/loop[0-9]+\Z")
_ROOTFS = Path("arch/x86_64/airootfs.sfs")
Runner = Callable[..., subprocess.CompletedProcess[str]]


class AuditError(ValueError):
    """Source is not the pinned read-only ISO or its package policy is unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditError(message)


def digest(file: Path) -> str:
    result = hashlib.sha256()
    with file.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def command(runner: Runner, argv: list[str]) -> str:
    try:
        output = runner(argv, capture_output=True, text=True, check=False, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AuditError("cannot inspect read-only source mount") from error
    require(output.returncode == 0 and isinstance(output.stdout, str)
            and len(output.stdout) < 16_384,
            "read-only mount inspection failed")
    return output.stdout.strip()


def verify_source_mount(
    path: Path, *, filesystem: str, expected_backing: Path, run: Runner
) -> None:
    require(path.is_dir() and not path.is_symlink() and path.resolve() == path,
            "source mount must be a canonical directory")
    observed = command(
        run, ["findmnt", "-rn", "-M", str(path), "-o", "SOURCE,FSTYPE,OPTIONS"]
    ).split()
    require(len(observed) == 3 and _LOOP.fullmatch(observed[0]) is not None
            and observed[1] == filesystem and "ro" in observed[2].split(","),
            "source must be a read-only loop mount of the expected filesystem")
    backing = command(run, [
        "losetup", "--noheadings", "--output", "BACK-FILE", observed[0]
    ])
    require(backing == str(expected_backing),
            "loop backing is not the original hashed ISO/Archiso image")


def audit(
    iso: Path,
    iso_root: Path,
    live_root: Path,
    pinned_sha256: str,
    *,
    run: Runner = subprocess.run,
) -> dict[str, Any]:
    """Do not allow any package installation unless this entire audit passes."""
    require(isinstance(pinned_sha256, str) and _PIN.fullmatch(pinned_sha256) is not None,
            "expected ISO SHA-256 pin is invalid")
    require(iso.is_absolute() and iso.is_file() and not iso.is_symlink()
            and iso.resolve() == iso,
            "ISO must be an explicit canonical regular file")
    require(digest(iso) == pinned_sha256, "official CachyOS ISO SHA-256 mismatch")

    verify_source_mount(iso_root, filesystem="iso9660", expected_backing=iso, run=run)
    rootfs_path = iso_root / _ROOTFS
    require(rootfs_path.is_file() and not rootfs_path.is_symlink()
            and rootfs_path.resolve().is_relative_to(iso_root),
            "official ISO rootfs is missing or redirected")
    verify_source_mount(
        live_root, filesystem="squashfs", expected_backing=rootfs_path, run=run
    )
    config = live_root / "etc/pacman.conf"
    require(config.is_file() and not config.is_symlink(),
            "official rootfs pacman.conf is missing or redirected")
    os_release = live_root / "etc/os-release"
    require(os_release.is_file() and not os_release.is_symlink()
            and "ID=cachyos" in os_release.read_text(encoding="utf-8").splitlines(),
            "official rootfs identity is not CachyOS")

    # The shared guard is not a parser: it invokes pacman-conf. Here we
    # use the *actual binary and included mirror files* of this hashed ISO.
    def guest_pacman_conf(
        argv: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        require(argv[:3] == ["pacman-conf", "--config", str(config)],
                "signature guard attempted an unexpected command")
        real = [
            "chroot", str(live_root), "/usr/bin/pacman-conf",
            "--config", "/etc/pacman.conf", *argv[3:]
        ]
        return run(real, **kwargs)

    try:
        policy = _POLICY.assess(config, run=guest_pacman_conf)
    except _POLICY.PolicyError as error:
        raise AuditError(
            "pinned CachyOS ISO package signature policy refused: " + str(error)
        ) from error
    return {
        "ok": True,
        "source": "gaslux-pinned-archiso-readonly-signature-audit-v1",
        "officialIsoSha256Verified": True,
        "isoSha256": pinned_sha256,
        "readOnlyIsoMountVerified": True,
        "readOnlySquashfsMountVerified": True,
        "actualIsoPacmanConfExecuted": True,
        "policy": policy,
        "pacstrapExecuted": False,
        "installedCachyosBootVerified": False,
        "windowsDualBootVerified": False,
        "windowsRollbackVerified": False,
        "productionReady": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("iso", type=Path)
    parser.add_argument("iso_root", type=Path)
    parser.add_argument("live_root", type=Path)
    parser.add_argument("pinned_sha256")
    parser.add_argument("output_json", type=Path)
    args = parser.parse_args(argv)
    outcome: dict[str, Any]
    status = 1
    try:
        require(os.geteuid() == 0, "read-only chroot audit requires root in ephemeral CI")
        require(not args.output_json.exists() and not args.output_json.is_symlink()
                and args.output_json.parent.is_dir(),
                "refusing to overwrite report or use an absent report directory")
        outcome = audit(
            args.iso, args.iso_root, args.live_root, args.pinned_sha256
        )
        status = 0
    except (AuditError, OSError, UnicodeError, TypeError, ValueError) as error:
        outcome = {
            "ok": False,
            "source": "gaslux-pinned-archiso-readonly-signature-audit-v1",
            "error": str(error),
            "packageInstallationBlocked": True,
            "installedCachyosBootVerified": False,
            "windowsRollbackVerified": False,
            "productionReady": False,
        }
    # Record failure too; an unavailable audit must never be a silent success.
    with args.output_json.open("x", encoding="utf-8") as stream:
        json.dump(outcome, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps(outcome, sort_keys=True))
    return status


if __name__ == "__main__":
    sys.exit(main())
