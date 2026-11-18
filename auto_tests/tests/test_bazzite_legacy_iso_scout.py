"""Bazzite legacy ISO discovery/Blivet preview fail-closed contracts (no disk access)."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))

from bazzite_legacy_iso_scout import (  # noqa: E402
    OFFICIAL_CANDIDATE,
    LegacyRefusal,
    inspect_candidate,
    inspect_partition_preview,
    parse_advertised_checksum,
)

SHA = "a" * 64
ISO = "bazzite-stable-amd64.iso"


def candidate(**overrides):
    options = {
        "firmware": "uefi",
        "partition_style": "gpt",
        "secure_boot_enabled": False,
        "iso_url": OFFICIAL_CANDIDATE,
        "iso_http_status": 200,
        "checksum_http_status": 200,
        "signature_http_status": 200,
        "content_length": str(8 * 1024**3),
        "checksum_text": f"{SHA}  {ISO}\n",
    }
    options.update(overrides)
    return inspect_candidate(**options)


def preview(**overrides):
    ids = [f"00000000-0000-4000-8000-{i:012d}" for i in range(1, 5)]
    options = {
        "firmware": "uefi", "partitionStyle": "gpt", "secureBootEnabled": False,
        "transactionId": "bazzite-lab-txn-0001",
        "windowsEspPartuuid": ids[0], "ownedEspPartuuid": ids[1],
        "ownedBootPartuuid": ids[2], "ownedRootPartuuid": ids[3],
        "windowsEspAction": "preserve-no-mount-no-format",
        "ownedEspFilesystem": "vfat", "ownedBootFilesystem": "ext4",
        "ownedRootFilesystem": "btrfs",
    }
    options.update(overrides)
    return inspect_partition_preview(options)


def test_official_metadata_is_not_media_or_installation_trust():
    result = candidate()
    assert result["sourceMetadataAvailable"] is True
    assert result["advertisedSha256"] == SHA
    assert result["detachedSignatureAdvertised"] is True
    for key in (
        "detachedSignatureVerified", "isoBytesDownloaded", "isoSha256Verified",
        "immutableReleasePinAuthorized", "installerIdentityVerified",
        "manualPartitioningInGuestVerified", "windowsEspPreservedInGuest",
        "installationAuthorized", "partitionWriteAuthorized",
        "windowsEspWriteAuthorized", "nativeInstallationVerified",
        "windowsDualBootVerified", "windowsRecoveryVerified",
    ):
        assert result[key] is False, key


@pytest.mark.parametrize("firmware,style", [
    ("bios", "mbr"), ("bios", "gpt"), ("uefi", "mbr"),
])
def test_unsupported_modes_refused_first(firmware, style):
    with pytest.raises(LegacyRefusal, match="UEFI/GPT"):
        candidate(firmware=firmware, partition_style=style, checksum_text="malformed")


@pytest.mark.parametrize("secure_boot", [True, None, 1, "false"])
def test_secure_boot_and_ambiguous_state_refused(secure_boot):
    with pytest.raises(LegacyRefusal, match="Secure Boot"):
        candidate(secure_boot_enabled=secure_boot)


@pytest.mark.parametrize("url", [
    "http://download.bazzite.gg/bazzite-stable-amd64.iso",
    "https://example.com/bazzite-stable-amd64.iso",
    "https://download.bazzite.gg/bazzite-stable-live-amd64.iso",
    "https://download.bazzite.gg/bazzite-stable-amd64.iso?latest=1",
])
def test_unknown_source_refused(url):
    with pytest.raises(LegacyRefusal, match="exact historical"):
        candidate(iso_url=url)


def test_unavailable_official_cdn_is_safe_diagnostic():
    result = candidate(iso_http_status=404, checksum_http_status=404, content_length="")
    assert result["discoveryStatus"] == "upstream-media-or-checksum-unavailable"
    assert result["installationAuthorized"] is False
    assert result["advertisedSha256"] is None


@pytest.mark.parametrize("length", ["", "-1", "not-a-number"])
def test_unreliable_content_length_remains_blocked(length):
    result = candidate(content_length=length)
    assert result["sourceMetadataAvailable"] is False


@pytest.mark.parametrize("length", ["1", str(20 * 1024**3)])
def test_unexpected_iso_size_refused(length):
    with pytest.raises(LegacyRefusal, match="size"):
        candidate(content_length=length)


@pytest.mark.parametrize("bad", [
    f"{SHA}  wrong.iso\n",
    f"{SHA}  {ISO}\n{SHA}  {ISO}\n",
    f"{SHA.upper()}  {ISO}\n",
    "not-a-checksum",
    "",
])
def test_invalid_checksum_refused(bad):
    with pytest.raises(LegacyRefusal):
        parse_advertised_checksum(bad)


def test_bsd_and_gnu_metadata_supported_but_not_trusted():
    assert parse_advertised_checksum(f"SHA256 ({ISO}) = {SHA}\n") == SHA
    assert parse_advertised_checksum(f"{SHA} *{ISO}\n") == SHA


def test_static_layout_requires_separate_esp_boot_and_btrfs():
    result = preview()
    assert result["hypotheticalLayoutPassesStaticPolicy"] is True
    for key in (
        "onDiskIdentityVerified", "anacondaWriteSetVerified",
        "windowsEspPreservedInGuest", "installationAuthorized",
        "partitionWriteAuthorized",
    ):
        assert result[key] is False


@pytest.mark.parametrize("change", [
    {"secureBootEnabled": True},
    {"firmware": "bios", "partitionStyle": "mbr"},
    {"windowsEspAction": "format"},
    {"windowsEspAction": "preserve"},
    {"ownedEspFilesystem": "ext4"},
    {"ownedRootFilesystem": "ext4"},
    {"ownedBootFilesystem": "btrfs"},
    {"transactionId": "weak"},
    {"ownedEspPartuuid": "00000000-0000-4000-8000-000000000001"},
    {"ownedBootPartuuid": "INVALID"},
    {"extra": True},
])
def test_unsafe_hypothetical_layout_rejected(change):
    with pytest.raises(LegacyRefusal):
        preview(**change)
