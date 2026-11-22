#!/usr/bin/env python3
"""Read-only Q4OS native ISO readiness evidence. Never launches QEMU or installers.

The published upstream checksum is not a signed Gaslux catalogue entry.
This module intentionally has no API to grant live-boot or storage authority.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import stat
from pathlib import Path

ISO_NAME = "q4os-6.10-x64.r2.iso"
ISO_SOURCE = "https://downloads.sourceforge.net/project/q4os/stable/q4os-6.10-x64.r2.iso"
UPSTREAM_CHECKSUM_PAGE = (
    "https://sourceforge.net/projects/q4os/files/stable/q4os-6.10-x64.r2.iso/download"
)
UPSTREAM_SHA256 = "1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d"
MIN_HISTORIC_BYTES = 1_500_000_001
MAX_HISTORIC_BYTES = 2_999_999_999
CHUNK_BYTES = 4 * 1024 * 1024

# This immutable source anchor is a public checksum, NOT an authenticated
# Gaslux signed catalogue or an independent upstream detached signature.
SIGNED_RELEASE_METADATA_VERIFIED = False

REASONS = frozenset(
    {
        "ISO_FD_INVALID",
        "ISO_FD_NOT_READ_ONLY",
        "ISO_FD_NOT_OWNED",
        "ISO_FD_NOT_REGULAR",
        "ISO_FD_LINKED",
        "ISO_FD_PUBLIC_PERMISSIONS",
        "ISO_SIZE_OUT_OF_RANGE",
        "ISO_DIGEST_MISMATCH",
        "ISO_CHANGED_DURING_READ",
        "ISO_SOURCE_DIRECTORY_UNTRUSTED",
        "ISO_SOURCE_NAME_INVALID",
        "ISO_READ_FAILURE",
    }
)


class MediaRefusal(ValueError):
    """Finite disclosure-safe refusal; never contains a filename or exception text."""


def _deny(reason: str) -> None:
    if reason not in REASONS:
        reason = "ISO_READ_FAILURE"
    raise MediaRefusal(reason)


def measure_fd(fd: int, expected_sha256: str, minimum_bytes: int, maximum_bytes: int) -> dict:
    """Pin and hash one actual read-only regular-file descriptor via pread().

    This reusable primitive can be tested with synthetic tiny files. Only
    measure_official_iso() supplies the authoritative fixed upstream digest
    and historical size bounds. No pathname is reopened after validation.
    """
    if type(fd) is not int or fd < 0:
        _deny("ISO_FD_INVALID")
    if (
        type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(char not in "0123456789abcdef" for char in expected_sha256)
        or type(minimum_bytes) is not int
        or type(maximum_bytes) is not int
        or minimum_bytes < 1
        or maximum_bytes < minimum_bytes
    ):
        _deny("ISO_FD_INVALID")
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        if flags & os.O_ACCMODE != os.O_RDONLY:
            _deny("ISO_FD_NOT_READ_ONLY")
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            _deny("ISO_FD_NOT_REGULAR")
        if before.st_uid != os.getuid():
            _deny("ISO_FD_NOT_OWNED")
        if before.st_nlink != 1:
            _deny("ISO_FD_LINKED")
        if before.st_mode & 0o077:
            _deny("ISO_FD_PUBLIC_PERMISSIONS")
        if not minimum_bytes <= before.st_size <= maximum_bytes:
            _deny("ISO_SIZE_OUT_OF_RANGE")

        digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            block = os.pread(fd, min(CHUNK_BYTES, before.st_size - offset), offset)
            if not block:
                _deny("ISO_CHANGED_DURING_READ")
            digest.update(block)
            offset += len(block)
        after = os.fstat(fd)

        def identity(item: os.stat_result) -> tuple:
            return (
                item.st_dev,
                item.st_ino,
                item.st_uid,
                item.st_nlink,
                item.st_mode,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )

        if identity(before) != identity(after):
            _deny("ISO_CHANGED_DURING_READ")
        if digest.hexdigest() != expected_sha256:
            _deny("ISO_DIGEST_MISMATCH")
        return {
            "sha256": digest.hexdigest(),
            "sizeBytes": after.st_size,
            "fdReadOnlyPinnedDuringMeasurement": True,
            "qemuFdBound": False,
        }
    except MediaRefusal:
        raise
    except (OSError, ValueError, TypeError, OverflowError):
        _deny("ISO_READ_FAILURE")


def measure_official_iso(path: Path) -> dict:
    """Measure a private runner-owned ISO through O_NOFOLLOW dirfd/openat.

    Boot is never authorized by this measurement: descriptor closes when
    the read finishes, and QEMU has not inherited or authenticated it.
    """
    if not isinstance(path, Path) or not path.is_absolute() or path.name != ISO_NAME:
        _deny("ISO_SOURCE_NAME_INVALID")
    parent = path.parent
    if parent.is_symlink():
        _deny("ISO_SOURCE_DIRECTORY_UNTRUSTED")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        directory = os.open(parent, flags | os.O_DIRECTORY)
        try:
            before = os.fstat(directory)
            if (
                not stat.S_ISDIR(before.st_mode)
                or before.st_uid != os.getuid()
                or before.st_mode & 0o077
            ):
                _deny("ISO_SOURCE_DIRECTORY_UNTRUSTED")
            fd = os.open(path.name, flags, dir_fd=directory)
            try:
                result = measure_fd(fd, UPSTREAM_SHA256, MIN_HISTORIC_BYTES, MAX_HISTORIC_BYTES)
                after = os.fstat(directory)
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    _deny("ISO_SOURCE_DIRECTORY_UNTRUSTED")
                return result
            finally:
                os.close(fd)
        finally:
            os.close(directory)
    except MediaRefusal:
        raise
    except (OSError, ValueError, TypeError):
        _deny("ISO_READ_FAILURE")


def readiness_manifest(iso_path: Path | None = None) -> dict:
    """Produce a source-to-boot *plan*, never a record of QEMU/Guest execution."""
    measured = measure_official_iso(iso_path) if iso_path is not None else None
    blockers = [
        "INDEPENDENT_SAFETY_APPROVAL_MISSING",
        "SIGNED_GASLUX_ISO_CATALOG_MISSING",
        "ISO_SIZE_NOT_FIXED_IN_SIGNED_METADATA",
        "ISO_TO_QEMU_FD_BINDING_NOT_OBSERVED",
        "QCOW2_CHECKPOINT_RECOVERY_NOT_OBSERVED",
        "GUEST_BOOT_NOT_OBSERVED",
    ]
    if measured is None:
        blockers.append("ISO_BYTES_NOT_RECHECKED_THIS_RUN")
    return {
        "schemaVersion": 1,
        "intent": "Q4OS_NATIVE_LIVE_BOOT_PREPARATION_ONLY",
        "decision": "DENY",
        "evidenceLevel": "MEDIA_HASH_ONLY" if measured is not None else "SOURCE_REFERENCE_ONLY",
        "source": {
            "distribution": "q4os",
            "release": "6.10",
            "revision": "r2",
            "architecture": "x86_64",
            "fileName": ISO_NAME,
            "officialDownloadSource": ISO_SOURCE,
            "publicChecksumPage": UPSTREAM_CHECKSUM_PAGE,
            "upstreamPublishedSha256": UPSTREAM_SHA256,
            "signedGasluxCatalogVerified": SIGNED_RELEASE_METADATA_VERIFIED,
            "exactCatalogSizeBytes": None,
            "historicalNativeInstaller": "Calamares",
            "installerObservedInThisRun": False,
        },
        "iso": {
            "sha256MatchedThisRun": measured is not None,
            "observed": measured,
            "isoFdRetainedForQemu": False,
        },
        "runtimeBindings": {
            "qemuProcessIdentityVerified": False,
            "qemuExecutableVerified": False,
            "qmpPeerVerified": False,
            "isoFdIdentityBoundToQemu": False,
            "qcow2FdIdentityBoundToQemu": False,
            "firmwareCodeAndVarsBoundToQemu": False,
            "qcow2GeometryVerified": False,
            "qcow2BackingVerified": False,
            "qcow2SnapshotRestorable": False,
        },
        "guest": {
            "qemuStarted": False,
            "isoBooted": False,
            "kernelBooted": False,
            "userspaceBooted": False,
            "guestObservationReceived": False,
            "guestOriginAttested": False,
        },
        "gates": {
            "independentSafetyApproved": False,
            "disposableVmStandingPolicy": True,
            "liveBootAuthorized": False,
            "QEMU_FD_BACKING_VERIFIED": False,
            "productionStorageWritesAuthorized": False,
            "q4osNativeInstallationVerified": False,
            "sameDiskDualBootVerified": False,
            "windowsInPlaceRollbackProven": False,
            "releaseEligible": False,
            "stable": False,
        },
        "blockers": blockers,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Q4OS source/FD audit only; no QEMU launch")
    parser.add_argument("--iso", type=Path, help="optional private, already-downloaded native ISO")
    args = parser.parse_args()
    try:
        report = readiness_manifest(args.iso)
    except MediaRefusal as exc:
        # Fixed code only: no private path, traceback, or arbitrary exception.
        print(json.dumps({"decision": "DENY", "reasonCode": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
