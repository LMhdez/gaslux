"""Bazzite backend's hard UEFI/GPT and Atomic restrictions: synthetic only."""

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets/live"))
from gaslux_bazzite_preflight import probe_bazzite  # noqa: E402
from gaslux_lab_media_probe import ProbeRefusal  # noqa: E402


@pytest.fixture
def media(tmp_path):
    data = bytearray(40 * 2048)
    data[32768:32775] = b"\x01CD001\x01"
    data[34816:34823] = b"\xffCD001\x01"
    iso = tmp_path / "atomic.iso"
    iso.write_bytes(data)
    os_release = tmp_path / "os-release"
    os_release.write_text(
        'ID=fedora\nPRETTY_NAME="Fedora Linux 42 (Bazzite)"\nOSTREE_VERSION=42\n',
        encoding="utf-8",
    )
    return {
        "iso_path": str(iso),
        "iso_size": iso.stat().st_size,
        "iso_sha256": hashlib.sha256(data).hexdigest(),
        "os_release_path": str(os_release),
        "firmware": "uefi",
        "partition_style": "gpt",
        "secure_boot_enabled": False,
        "bootloader": "grub",
        "ram_mib": 8192,
        "target_disk_gib": 64,
        "target_root_fs": "btrfs",
        "installer_kind": "fedora-atomic-native",
    }


def test_fedora_based_bazzite_identity_is_diagnostic_only(media):
    result = probe_bazzite(**media)
    assert result["osReleaseId"] == "fedora"
    assert result["installationAuthorized"] is False
    assert result["atomicDeploymentVerified"] is False
    assert result["nativeInstallerVerified"] is False


@pytest.mark.parametrize(
    "change",
    [
        {"firmware": "bios", "partition_style": "mbr"},
        {"firmware": "uefi", "partition_style": "mbr"},
        {"firmware": "bios", "partition_style": "gpt"},
        {"secure_boot_enabled": True},
        {"target_disk_gib": 49},
        {"ram_mib": 4096},
        {"target_root_fs": "ext4"},
        {"installer_kind": "debian-squashfs"},
        {"bootloader": "systemd-boot"},
        {"iso_sha256": "0" * 64},
    ],
)
def test_unsafe_modes_resources_atomic_and_media_refused(media, change):
    media.update(change)
    with pytest.raises(ProbeRefusal):
        probe_bazzite(**media)


def test_bios_rejected_before_iso_read(media):
    media["firmware"] = "bios"
    media["partition_style"] = "mbr"
    media["iso_path"] = "/nonexistent/disk.iso"
    with pytest.raises(ProbeRefusal, match="UEFI/GPT"):
        probe_bazzite(**media)


def test_generic_fedora_without_bazzite_marker_refused(media):
    Path(media["os_release_path"]).write_text(
        'ID=fedora\nPRETTY_NAME="Fedora Linux 42"\n', encoding="utf-8"
    )
    with pytest.raises(ProbeRefusal, match="identity"):
        probe_bazzite(**media)


def test_possible_future_bazzite_os_id_is_not_install_authorization(media):
    Path(media["os_release_path"]).write_text(
        'ID=bazzite\nPRETTY_NAME="Bazzite"\n', encoding="utf-8"
    )
    assert probe_bazzite(**media)["installationAuthorized"] is False
