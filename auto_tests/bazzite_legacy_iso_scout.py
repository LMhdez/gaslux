#!/usr/bin/env python3
"""Read-only Bazzite legacy ISO metadata and hypothetical partition proposal scout.

No ISO download, installation, guest execution, disk access or release authorization.
CDN checksum metadata is *discovery only*, not independently trusted provenance.
"""

from __future__ import annotations

import argparse
import json
import re
import uuid
from pathlib import Path

OFFICIAL_CANDIDATE = "https://download.bazzite.gg/bazzite-stable-amd64.iso"
ISO_NAME = "bazzite-stable-amd64.iso"
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GNU_LINE = re.compile(r"([0-9a-f]{64}) [ *](bazzite-stable-amd64\.iso)\Z")
BSD_LINE = re.compile(r"SHA256 \(bazzite-stable-amd64\.iso\) = ([0-9a-f]{64})\Z")
MIN_BYTES = 3 * 1024**3
MAX_BYTES = 16 * 1024**3


class LegacyRefusal(ValueError):
    """Refuse an unsupported or ambiguous discovery request."""


def require_uefi_gpt(firmware: str, partition_style: str, secure_boot_enabled: bool) -> None:
    if firmware != "uefi" or partition_style != "gpt":
        raise LegacyRefusal("Bazzite Gaslux backend is strictly UEFI/GPT-only")
    if type(secure_boot_enabled) is not bool or secure_boot_enabled:
        raise LegacyRefusal("Secure Boot requiring key enrollment is not authorized")


def parse_advertised_checksum(data: str) -> str:
    if not isinstance(data, str) or len(data.encode("utf-8")) > 4096:
        raise LegacyRefusal("Invalid checksum metadata length")
    lines = [line.strip() for line in data.splitlines() if line.strip()]
    if len(lines) != 1:
        raise LegacyRefusal("Missing or ambiguous checksum record")
    match = GNU_LINE.fullmatch(lines[0]) or BSD_LINE.fullmatch(lines[0])
    if match is None:
        raise LegacyRefusal("Checksum must identify the exact official legacy ISO filename")
    return match.group(1)


def inspect_candidate(
    *,
    firmware: str,
    partition_style: str,
    secure_boot_enabled: bool,
    iso_url: str,
    iso_http_status: int,
    checksum_http_status: int,
    signature_http_status: int,
    content_length: str,
    checksum_text: str,
) -> dict:
    require_uefi_gpt(firmware, partition_style, secure_boot_enabled)
    if iso_url != OFFICIAL_CANDIDATE:
        raise LegacyRefusal("Only the exact historical official CDN URL is in scope")
    if any(type(status) is not int or not 100 <= status <= 599 for status in (
        iso_http_status, checksum_http_status, signature_http_status
    )):
        raise LegacyRefusal("Missing or invalid CDN HTTP response")
    result = {
        "distributionId": "bazzite",
        "sourceFormat": "legacy-anaconda-iso-candidate",
        "candidateUrl": OFFICIAL_CANDIDATE,
        "firmware": "uefi",
        "partitionStyle": "gpt",
        "secureBootEnrollmentAuthorized": False,
        "sourceMetadataAvailable": False,
        "advertisedSha256": None,
        "advertisedSizeBytes": None,
        "detachedSignatureAdvertised": signature_http_status == 200,
        "detachedSignatureVerified": False,
        "isoBytesDownloaded": False,
        "isoSha256Verified": False,
        "immutableReleasePinAuthorized": False,
        "installerIdentityVerified": False,
        "manualPartitioningInGuestVerified": False,
        "windowsEspPreservedInGuest": False,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "nativeInstallationVerified": False,
        "windowsDualBootVerified": False,
        "windowsRecoveryVerified": False,
    }
    if iso_http_status != 200 or checksum_http_status != 200:
        result["discoveryStatus"] = "upstream-media-or-checksum-unavailable"
        return result
    if not content_length.isdecimal():
        result["discoveryStatus"] = "untrusted-or-absent-length"
        return result
    size = int(content_length)
    if not MIN_BYTES <= size <= MAX_BYTES:
        raise LegacyRefusal("Unexpected legacy ISO advertised size")
    result["advertisedSha256"] = parse_advertised_checksum(checksum_text)
    result["advertisedSizeBytes"] = size
    result["sourceMetadataAvailable"] = True
    result["discoveryStatus"] = "untrusted-cdn-metadata-only"
    return result


def inspect_partition_preview(preview: dict) -> dict:
    """Check only a *proposed* Blivet layout; never claim actual disk identity."""
    if not isinstance(preview, dict):
        raise LegacyRefusal("Invalid hypothetical layout")
    required = {
        "firmware", "partitionStyle", "secureBootEnabled", "transactionId",
        "windowsEspPartuuid", "ownedEspPartuuid", "ownedBootPartuuid",
        "ownedRootPartuuid", "windowsEspAction", "ownedEspFilesystem",
        "ownedBootFilesystem", "ownedRootFilesystem",
    }
    if set(preview) != required:
        raise LegacyRefusal("Unknown or missing layout properties")
    require_uefi_gpt(
        preview["firmware"], preview["partitionStyle"], preview["secureBootEnabled"]
    )
    if not isinstance(preview["transactionId"], str) or not re.fullmatch(
        r"[a-zA-Z0-9][a-zA-Z0-9_-]{15,63}", preview["transactionId"]
    ):
        raise LegacyRefusal("Missing strong transaction identifier")
    if (
        preview["windowsEspAction"] != "preserve-no-mount-no-format"
        or preview["ownedEspFilesystem"] != "vfat"
        or preview["ownedBootFilesystem"] != "ext4"
        or preview["ownedRootFilesystem"] != "btrfs"
    ):
        raise LegacyRefusal("Windows ESP must remain untouched; owned EFI/boot/Btrfs required")
    ids = []
    for key in ("windowsEspPartuuid", "ownedEspPartuuid", "ownedBootPartuuid", "ownedRootPartuuid"):
        value = preview[key]
        if not isinstance(value, str):
            raise LegacyRefusal("Non-string partition identity")
        try:
            parsed = uuid.UUID(value)
        except ValueError as exc:
            raise LegacyRefusal("Missing exact PARTUUID") from exc
        if str(parsed) != value.lower():
            raise LegacyRefusal("Noncanonical PARTUUID")
        ids.append(parsed)
    if len(set(ids)) != len(ids):
        raise LegacyRefusal("Windows and owned partition identities overlap")
    return {
        "hypotheticalLayoutPassesStaticPolicy": True,
        "onDiskIdentityVerified": False,
        "anacondaWriteSetVerified": False,
        "windowsEspPreservedInGuest": False,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso-url", default=OFFICIAL_CANDIDATE)
    parser.add_argument("--firmware", default="uefi")
    parser.add_argument("--partition-style", default="gpt")
    parser.add_argument("--secure-boot-enabled", action="store_true")
    parser.add_argument("--iso-status", type=int, required=True)
    parser.add_argument("--checksum-status", type=int, required=True)
    parser.add_argument("--signature-status", type=int, required=True)
    parser.add_argument("--content-length", default="")
    parser.add_argument("--checksum-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        checksum = (
            args.checksum_file.read_text(encoding="utf-8")
            if args.checksum_status == 200
            else ""
        )
        evidence = inspect_candidate(
            firmware=args.firmware, partition_style=args.partition_style,
            secure_boot_enabled=args.secure_boot_enabled, iso_url=args.iso_url,
            iso_http_status=args.iso_status, checksum_http_status=args.checksum_status,
            signature_http_status=args.signature_status,
            content_length=args.content_length, checksum_text=checksum,
        )
    except (LegacyRefusal, OSError, UnicodeError) as exc:
        parser.exit(2, f"REFUSED: {exc}\n")
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
