#!/usr/bin/env python3
"""Fail-closed Q4OS lab-only libguestfs appliance preflight.

Boots a REAL libguestfs/QEMU appliance on an exclusively owned synthetic GPT
file. Reuses the pinned Safety #265 GPT reader. Never accepts Windows media,
host block devices or installer writers. This is NOT independent attestation.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from libertix_disk_identity_gate import assert_snapshot_matches, inspect_gpt_image

SIZE = 64 * 1024 * 1024
SECTOR = 512
SAMPLE = 34 * SECTOR
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-generic$")


class ApplianceDenied(RuntimeError):
    """Refusal; no operating-system disk was accessed."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ApplianceDenied(reason)


def checksum(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def inspect_kernel(env: dict[str, str], module_root: Path = Path("/lib/modules")) -> dict:
    """Require a readable, owned private kernel matching packaged modules."""
    version = env.get("SUPERMIN_KERNEL_VERSION", "")
    require(bool(VERSION.fullmatch(version)), "KERNEL_VERSION_INVALID")
    image = Path(env.get("SUPERMIN_KERNEL") or "/not-present")
    modules = Path(env.get("SUPERMIN_MODULES") or "/not-present")
    require(
        image.is_absolute() and not image.is_symlink() and image.is_file(),
        "KERNEL_MISSING",
    )
    require(
        image.name == "vmlinuz-" + version
        and image.stat().st_uid == os.getuid()
        and bool(image.stat().st_mode & stat.S_IRUSR)
        and os.access(image, os.R_OK),
        "KERNEL_MISMATCH_OR_UNREADABLE",
    )
    require(
        image.parent.is_dir()
        and image.parent != Path("/")
        and not image.parent.is_symlink()
        and image.parent.stat().st_uid == os.getuid()
        and image.parent.stat().st_mode & 0o077 == 0,
        "KERNEL_NOT_PRIVATE",
    )
    require(
        modules == module_root / version
        and modules.is_dir()
        and not modules.is_symlink()
        and (modules / "modules.dep").is_file()
        and not (modules / "modules.dep").is_symlink(),
        "MODULES_MISSING_OR_MISMATCH",
    )
    require(
        env.get("LIBGUESTFS_BACKEND") == "direct",
        "GUESTFS_BACKEND_UNSUPPORTED",
    )
    return {
        "kernelVersion": version,
        "kernelReadable": True,
        "modulesVersionMatches": True,
        "kernelPrivateCopy": True,
        "guestfsBackend": "direct",
    }


def run(*command: str, timeout: int = 90) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    require(result.returncode == 0, "SYNTHETIC_DISK_PREPARE_FAILED")
    return result.stdout


def make_synthetic(folder: Path) -> Path:
    path = folder / "synthetic-gpt.raw"
    with path.open("xb") as stream:
        stream.truncate(SIZE)
    disk_guid = secrets.token_hex(16)
    # GUID construction by uuid avoids a second custom GPT parser.
    import uuid

    run(
        "sgdisk",
        "--clear",
        "--new=1:2048:4095",
        "--typecode=1:EF00",
        "--disk-guid=" + str(uuid.UUID(hex=disk_guid)),
        "--partition-guid=1:" + str(uuid.uuid4()),
        str(path),
    )
    require(path.stat().st_size == SIZE, "SYNTHETIC_GEOMETRY_CHANGED")
    return path


def observe_appliance(source: Path, folder: Path) -> dict:
    """Read raw sectors through libguestfs; no mounts and exactly one disk."""
    import guestfs

    # libguestfs labels must contain letters only (reuse audited Safety #267 rule).
    name = "gaslux" + "".join(secrets.choice("abcdef") for _ in range(12))
    appliance = None
    launched = False
    failure: Exception | None = None
    report: dict = {}
    stage = "GUESTFS_CREATE"
    try:
        appliance = guestfs.GuestFS(python_return_dict=True)
        stage = "GUESTFS_SET_BACKEND"
        appliance.set_backend("direct")
        stage = "GUESTFS_ATTACH_READONLY"
        appliance.add_drive_opts(str(source), format="raw", readonly=1, label=name)
        stage = "GUESTFS_LAUNCH"
        appliance.launch()
        launched = True
        stage = "GUESTFS_ENUMERATE"
        devices = appliance.list_devices()
        require(len(devices) == 1, "GUESTFS_MULTIPLE_OR_MISSING_DISKS")
        stage = "GUESTFS_GEOMETRY"
        labelled = "/dev/disk/guestfs/" + name
        require(
            appliance.blockdev_getsize64(labelled) == SIZE
            and appliance.blockdev_getsize64(devices[0]) == SIZE
            and appliance.blockdev_getss(labelled) == SECTOR,
            "GUESTFS_GEOMETRY_OR_LABEL_MISMATCH",
        )
        stage = "GUESTFS_READ_GPT"
        first = appliance.pread_device(labelled, SAMPLE, 0)
        last = appliance.pread_device(labelled, SAMPLE, SIZE - SAMPLE)
        require(
            len(first) == SAMPLE and len(last) == SAMPLE,
            "GUESTFS_GPT_WITNESS_INCOMPLETE",
        )
        stage = "GUESTFS_WITNESS_CREATE"
        sparse = folder / "guest-gpt-witness.raw"
        with sparse.open("xb") as out:
            out.truncate(SIZE)
            out.seek(0)
            out.write(first)
            out.seek(SIZE - SAMPLE)
            out.write(last)
        stage = "SAFETY_HOST_GPT"
        host = inspect_gpt_image(source, logical_sector_size=SECTOR)
        stage = "SAFETY_GUEST_GPT"
        guest = inspect_gpt_image(sparse, logical_sector_size=SECTOR)
        stage = "SAFETY_GPT_COMPARE"
        assert_snapshot_matches(host, guest)
        report = {
            "applianceBooted": True,
            "sourceReadOnly": True,
            "guestAttachedDrives": 1,
            "guestSelectedBy": "libguestfs-disk-label-and-GPT",
            "guestDiskSerialAuthenticated": False,
            "hostGuestGptMatches": True,
            "gptDiskGuid": host["partitionTableId"],
            "partitionCount": len(host["partitions"]),
            "logicalSectorBytes": SECTOR,
            "virtualSizeBytes": SIZE,
        }
    except Exception as exc:
        if isinstance(exc, ApplianceDenied):
            failure = exc
        else:
            failure = ApplianceDenied(
                stage + "_" + type(exc).__name__ + "_" + classify_diagnostic(str(exc))
            )
    finally:
        if launched:
            try:
                appliance.shutdown()
            except Exception:
                failure = failure or ApplianceDenied("GUESTFS_SHUTDOWN_FAILED")
        if appliance is not None:
            try:
                appliance.close()
            except Exception:
                failure = failure or ApplianceDenied("GUESTFS_CLOSE_FAILED")
    if failure is not None:
        raise failure
    report["applianceShutdownVerified"] = True
    return report


def classify_diagnostic(cause: str) -> str:
    """Allowlisted error code only. Never copy raw guest or supermin logs."""
    lowered = cause.lower()
    if "permission denied" in lowered or "not readable" in lowered:
        return "KERNEL_OR_MODULES_UNREADABLE"
    if "no suitable kernel" in lowered or "cannot find a kernel" in lowered:
        return "KERNEL_NOT_FOUND_BY_SUPERMIN"
    if "module" in lowered and ("missing" in lowered or "not found" in lowered):
        return "MODULE_DEPENDENCY_MISSING"
    if "supermin" in lowered:
        return "SUPERMIN_EXIT_NONZERO_CAUSE_UNCLASSIFIED"
    if "timeout" in lowered or "timed out" in lowered:
        return "APPLIANCE_BOOT_TIMEOUT"
    return "APPLIANCE_LAUNCH_FAILED_CAUSE_UNCLASSIFIED"


def lab_preflight(temp: Path, env: dict[str, str]) -> dict:
    require(
        env.get("GITHUB_ACTIONS") == "true"
        and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and env.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and platform.machine() == "x86_64",
        "NON_HOSTED_OR_UNEXPECTED_LAB",
    )
    require(
        temp.is_absolute()
        and temp.is_dir()
        and not temp.is_symlink()
        and temp.stat().st_uid == os.getuid(),
        "UNOWNED_TEMP_DIRECTORY",
    )
    kernel = inspect_kernel(env)
    require(
        Path("/dev/kvm").exists() and stat.S_ISCHR(Path("/dev/kvm").stat().st_mode),
        "KVM_UNAVAILABLE",
    )
    vfs = os.statvfs(temp)
    require(vfs.f_bavail * vfs.f_frsize > 384 * 1024 * 1024, "INSUFFICIENT_TEMP_SPACE")
    with tempfile.TemporaryDirectory(prefix="gaslux-q4os-guestfs-", dir=temp) as directory:
        folder = Path(directory)
        source = make_synthetic(folder)
        before = checksum(source)
        guest = observe_appliance(source, folder)
        after = checksum(source)
        require(before == after, "SYNTHETIC_SOURCE_MODIFIED")
    return {
        "schemaVersion": 1,
        "decision": "SYNTHETIC_APPLIANCE_PASS_NO_WRITER",
        "runnerScope": "GITHUB_HOSTED_SYNTHETIC_ONLY",
        "trustBoundary": "NOT_INDEPENDENT",
        "sourceSha256Before": before,
        "sourceSha256After": after,
        "syntheticSourceIntact": True,
        "temporarySourceRemoved": True,
        "installationAuthorized": False,
        "diskWritesAuthorized": False,
        "writerPresent": False,
        "rollbackVerified": False,
        **kernel,
        **guest,
    }


def main() -> int:
    temp = Path(os.environ.get("RUNNER_TEMP", "/no-runner-temp"))
    evidence = Path(os.environ.get("GASLUX_Q4OS_GUESTFS_EVIDENCE", "/no-evidence"))
    require(
        evidence.is_absolute()
        and evidence.parent == temp
        and evidence.is_dir()
        and not evidence.is_symlink()
        and evidence.stat().st_uid == os.getuid()
        and evidence.stat().st_mode & 0o077 == 0,
        "UNOWNED_EVIDENCE_DIRECTORY",
    )
    report: dict
    try:
        report = lab_preflight(temp, os.environ)
        status = 0
    except Exception as exc:
        # Diagnostic never reveals paths or raw exception text; the kernel
        # version is public package metadata, not a runner-specific path.
        text = str(exc)
        reason = text if isinstance(exc, ApplianceDenied) else classify_diagnostic(text)
        report = {
            "schemaVersion": 1,
            "decision": "BLOCKED_GUESTFS_APPLIANCE",
            "stage": "SYNTHETIC_QEMU_GUESTFS_PREFLIGHT",
            "reasonCode": reason[:96],
            "kernelVersion": os.environ.get("SUPERMIN_KERNEL_VERSION", "")[:64],
            "installationAuthorized": False,
            "diskWritesAuthorized": False,
            "writerPresent": False,
            "trustBoundary": "NOT_INDEPENDENT",
        }
        status = 1
    result = evidence / "q4os-guestfs-synthetic-preflight.json"
    require(not result.exists(), "EVIDENCE_DESTINATION_EXISTS")
    with result.open("x", encoding="utf-8") as out:
        json.dump(report, out, indent=2, sort_keys=True)
        out.write("\n")
    print("GASLUX_Q4OS_GUESTFS_PREFLIGHT=" + report["decision"])
    return status


if __name__ == "__main__":
    sys.exit(main())
