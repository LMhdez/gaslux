#!/usr/bin/env python3
"""Pin real OCI/RPM byte evidence, refuse claims of installed Atomic deployment.

No bootc/QEMU/guest execution, filesystem mount, disk access or writing.
A runner JSON record is never an independent installed deployment witness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

SOURCE_RUN = 45024613641
SOURCE_ARTIFACT = 14755572085
SOURCE_HEAD = "e4eee9712fe6d02eb927b4ef94da6780db512b66"
SOURCE_REPORT_SHA256 = "03790bd39a06943d3d9abc6dcd86dfb0c88ca52508e4ee2df9a9ce5bb156a4c9"
OCI_MANIFEST = "sha256:492f83c738838861464685aed341783c2ea2266c82a9f19f0c867fd301783fd4"
OCI_CONFIG = "sha256:938000b71e57a251c3720e90ad7422b6636b1cbcbecc928479c0a8f32350badb"
BOOTC_SHA256 = "f8944e5431de613133aa56bd7ac623dcf223f40ec3745a8c87b9cdcff4956e08"
RPM_DB_SHA256 = "5d916f9d9527497c01203cbb1e6eefda0c2b1e8729ffb851bc05f1e714cde275"
BUILD_ID = "b6de95c7102a4d12325589251e67353b9e4f936c"
RPM_DB_PATH = "usr/lib/sysimage/rpm-ostree-base-db/rpmdb.sqlite"
MAX_JSON = 64 * 1024
NO_AUTHORITY = (
    "installationAuthorized",
    "partitionWriteAuthorized",
    "gptMetadataWriteAuthorized",
    "windowsEspWriteAuthorized",
    "nvramWriteAuthorized",
    "secureBootEnrollmentAuthorized",
    "guestCommandChannelAuthorized",
    "nativeInstallationVerified",
    "stable",
    "windowsEspPreservationVerified",
    "bootloaderAndNVRAMWriteSetVerified",
    "bootcToFilesystemAvailableInBinaryVerified",
)


class Refusal(ValueError):
    """Invalid evidence or absent independent measurement authority."""


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise Refusal("Duplicate JSON property")
        value[key] = item
    return value


def _decode(raw: bytes, title: str) -> dict:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_JSON:
        raise Refusal(f"Invalid {title} byte length")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except Refusal:
        raise
    except (UnicodeError, ValueError) as exc:
        raise Refusal(f"Invalid {title} JSON") from exc
    if not isinstance(value, dict):
        raise Refusal(f"Invalid {title} JSON object")
    return value


def _regular_bytes(path: Path, label: str) -> bytes:
    """Bounded read-only FD; refuse symlinks and device/pipe paths."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_JSON:
            raise Refusal(f"Invalid {label} file type or length")
        content = bytearray()
        while len(content) <= MAX_JSON:
            portion = os.read(descriptor, min(65536, MAX_JSON + 1 - len(content)))
            if not portion:
                break
            content.extend(portion)
        after = os.fstat(descriptor)
        if (
            len(content) > MAX_JSON
            or len(content) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise Refusal(f"Changed or unbounded {label} evidence")
        return bytes(content)
    finally:
        os.close(descriptor)


def _valid_source_fields(source: dict) -> None:
    """Check byte-bound signed-OCI/RPM readback, not a runtime installation."""
    expected = {
        "status": "BOOTC_PRESENT_ROUTE_UNVERIFIED",
        "image": "ghcr.io/ublue-os/bazzite@" + OCI_MANIFEST,
        "manifestDigest": OCI_MANIFEST,
        "configDigest": OCI_CONFIG,
        "layersVerified": 256,
        "diffIdsVerified": 256,
        "allUncompressedLayerDigestsVerified": True,
        "arch": "amd64",
        "os": "linux",
        "elfBuildId": BUILD_ID,
        "elfMetadataVerified": True,
        "bootcVersionVerified": True,
        "bootcVersion": "1.17.1",
    }
    for key, value in expected.items():
        if type(source.get(key)) is not type(value) or source[key] != value:
            raise Refusal(f"Unproven signed OCI field: {key}")
    for key in NO_AUTHORITY:
        if source.get(key) is not False:
            raise Refusal(f"Source artifact asserts unauthorized capability: {key}")
    files = source.get("bootcFiles")
    if not isinstance(files, list) or len(files) != 1:
        raise Refusal("Ambiguous bootc path in source artifact")
    boot = files[0]
    if not isinstance(boot, dict) or boot.get("path") != "usr/bin/bootc":
        raise Refusal("Unexpected bootc path")
    if (
        boot.get("sha256") != BOOTC_SHA256
        or type(boot.get("size")) is not int
        or boot["size"] != 17915112
    ):
        raise Refusal("Unbound signed bootc ELF")
    rpm = source.get("bootcRpmIdentity")
    if not isinstance(rpm, dict) or rpm.get("status") != "BOOTC_RPM_IDENTITY_VERIFIED":
        raise Refusal("RPM package has no static identity binding")
    if rpm.get("rpmdbSha256") != RPM_DB_SHA256 or rpm.get("rpmdbPath") != RPM_DB_PATH:
        raise Refusal("Wrong or unbound RPM database")
    if (
        rpm.get("elfBuildId") != BUILD_ID
        or rpm.get("bootcRuntimeToFilesystemVerified") is not False
    ):
        raise Refusal("Misleading RPM/bootc runtime proof")
    info = rpm.get("rpmPackage")
    expected_rpm = {
        "name": "bootc",
        "epoch": 0,
        "version": "1.17.1",
        "release": "1.fc45",
        "architecture": "x86_64",
        "fileSha256": BOOTC_SHA256,
        "sourceRpm": "bootc-1.17.1-1.fc45.src.rpm",
    }
    if not isinstance(info, dict) or any(
        type(info.get(k)) is not type(v) or info[k] != v for k, v in expected_rpm.items()
    ):
        raise Refusal("RPM NEVRA or file hash substituted")


def assess(source_bytes: bytes, *, untrusted_deployment_bytes: bytes | None = None) -> dict:
    """Never promote runner/guest assertions into deployment authority."""
    result = {
        "decision": "REFUSED_SOURCE_EVIDENCE",
        "sourceArtifactByteMatched": False,
        "sourceCosignReverifiedInThisStep": False,
        "sourceAttestationReverifiedInThisStep": False,
        "bootcRpmBindingInSourceArtifact": False,
        "qcow2RealDeploymentObserved": False,
        "qcow2IdentityAndGeometryVerified": False,
        "nativeDeploymentVerified": False,
        "nativeInstallationVerified": False,
        "realLinuxBootVerified": False,
        "realWindowsBootVerified": False,
        "windowsEspPreservedVerified": False,
        "rollbackProven": False,
        "stable": False,
        **{k: False for k in NO_AUTHORITY},
        "provenanceSource": {
            "githubRun": SOURCE_RUN,
            "artifactId": SOURCE_ARTIFACT,
            "gitHead": SOURCE_HEAD,
            "ociManifest": OCI_MANIFEST,
        },
    }
    try:
        if hashlib.sha256(source_bytes).hexdigest() != SOURCE_REPORT_SHA256:
            raise Refusal("OCI report SHA-256 differs from pinned real artifact")
        _valid_source_fields(_decode(source_bytes, "pinned OCI"))
    except (Refusal, TypeError) as exc:
        result["reason"] = str(exc)[:240]
        return result
    result["sourceArtifactByteMatched"] = True
    result["bootcRpmBindingInSourceArtifact"] = True
    if untrusted_deployment_bytes is not None:
        try:
            _decode(untrusted_deployment_bytes, "untrusted deployment")
        except Refusal as exc:
            result["decision"] = "REFUSED_UNTRUSTED_DEPLOYMENT_REPORT"
            result["reason"] = str(exc)[:240]
            return result
        result["decision"] = "BLOCKED_UNAUTHENTICATED_DEPLOYMENT"
        result["reason"] = (
            "Guest/runner JSON is not independent QCOW2, disk, RPM, "
            "ESP, native boot or Windows recovery measurement"
        )
    else:
        result["decision"] = "SOURCE_ARTIFACT_MATCHED_DEPLOYMENT_UNPROVEN"
        result["reason"] = "No independently measured installed Atomic QCOW2 deployment supplied"
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oci-report", required=True, type=Path)
    parser.add_argument("--untrusted-deployment-report", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        source = _regular_bytes(args.oci_report, "OCI")
        claimed = (
            _regular_bytes(args.untrusted_deployment_report, "deployment")
            if args.untrusted_deployment_report is not None
            else None
        )
        decision = assess(source, untrusted_deployment_bytes=claimed)
    except (OSError, Refusal) as exc:
        decision = assess(b"")
        decision["reason"] = f"Cannot safely read pinned evidence: {exc}"[:240]
    args.output.write_text(json.dumps(decision, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(decision["decision"])
    raise SystemExit(2 if decision["decision"] == "SOURCE_ARTIFACT_MATCHED_DEPLOYMENT_UNPROVEN" else 3)


if __name__ == "__main__":
    main()
