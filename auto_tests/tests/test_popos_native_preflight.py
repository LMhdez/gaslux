"""Pop!_OS independent preflight tests (synthetic, no installer or disk writes)."""

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets/live"))
from gaslux_lab_media_probe import ProbeRefusal  # noqa: E402
from gaslux_popos_preflight import probe_popos  # noqa: E402


@pytest.fixture
def media(tmp_path):
    contents = bytearray(40 * 2048)
    contents[32768:32775] = b"\x01CD001\x01"
    contents[34816:34823] = b"\xffCD001\x01"
    iso = tmp_path / "pop.iso"
    iso.write_bytes(contents)
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=pop\nVERSION_ID="24.04"\n', encoding="utf-8")
    return {
        "iso_path": str(iso),
        "iso_size": iso.stat().st_size,
        "iso_sha256": hashlib.sha256(contents).hexdigest(),
        "os_release_path": str(os_release),
        "image_variant": "generic",
        "firmware": "uefi",
        "partition_style": "gpt",
        "secure_boot_enabled": False,
        "bootloader": "systemd-boot",
        "full_disk_encryption": False,
        "windows_shared_disk": True,
    }


@pytest.mark.parametrize(
    ("firmware", "table", "loader"),
    [("uefi", "gpt", "systemd-boot"), ("bios", "mbr", "grub")],
)
def test_supported_candidate_modes_are_only_diagnostics(media, firmware, table, loader):
    media.update(firmware=firmware, partition_style=table, bootloader=loader)
    outcome = probe_popos(**media)
    assert outcome["installationAuthorized"] is False
    assert outcome["isoToLiveIdentityBindingProven"] is False
    assert outcome["nativeInstallerAgentVerified"] is False
    assert outcome["backend"] == "system76"


@pytest.mark.parametrize(
    "change",
    [
        {"secure_boot_enabled": True},
        {"image_variant": "unverified"},
        {"firmware": "uefi", "partition_style": "mbr"},
        {"firmware": "bios", "partition_style": "gpt"},
        {"bootloader": "grub"},
        {"full_disk_encryption": True},
        {"iso_sha256": "0" * 64},
        {"windows_shared_disk": "false"},
    ],
)
def test_unsafe_popos_candidates_rejected(media, change):
    media.update(change)
    with pytest.raises(ProbeRefusal):
        probe_popos(**media)


def test_untrusted_linux_identity_fails(media):
    Path(media["os_release_path"]).write_text("ID=ubuntu\n")
    with pytest.raises(ProbeRefusal, match="identity"):
        probe_popos(**media)


def test_non_shared_encryption_is_still_not_authorized(media):
    media["windows_shared_disk"] = False
    media["full_disk_encryption"] = True
    assert probe_popos(**media)["installationAuthorized"] is False
