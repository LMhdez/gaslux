"""Q4OS native media vs Windows-folder setup: synthetic tests only."""

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets/live"))
from gaslux_lab_media_probe import ProbeRefusal  # noqa: E402
from gaslux_q4os_preflight import probe_q4os  # noqa: E402


@pytest.fixture
def media(tmp_path):
    data = bytearray(40 * 2048)
    data[32768:32775] = b"\x01CD001\x01"
    data[34816:34823] = b"\xffCD001\x01"
    iso = tmp_path / "q4os.iso"
    iso.write_bytes(data)
    os_release = tmp_path / "os-release"
    os_release.write_text(
        'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n',
        encoding="utf-8",
    )
    version = tmp_path / "q4os_version"
    version.write_text("6.10-deb13u1\n", encoding="utf-8")
    return {
        "iso_path": str(iso),
        "iso_size": iso.stat().st_size,
        "iso_sha256": hashlib.sha256(data).hexdigest(),
        "os_release_path": str(os_release),
        "q4os_version_path": str(version),
        "firmware": "uefi",
        "partition_style": "gpt",
        "secure_boot_enabled": False,
        "bootloader": "grub",
        "source_kind": "native-live-calamares",
    }


@pytest.mark.parametrize(
    ("firmware", "table"),
    [("uefi", "gpt"), ("bios", "mbr")],
)
def test_native_candidate_only_diagnostic(media, firmware, table):
    media.update(firmware=firmware, partition_style=table)
    result = probe_q4os(**media)
    assert result["osReleaseId"] == "debian"
    assert result["q4osIdentityBoundToIso"] is False
    assert result["calamaresPayloadVerified"] is False
    assert result["installationAuthorized"] is False


@pytest.mark.parametrize(
    "change",
    [
        {"source_kind": "windows-winsetup-folder"},
        {"firmware": "uefi", "partition_style": "mbr"},
        {"firmware": "bios", "partition_style": "gpt"},
        {"bootloader": "systemd-boot"},
        {"secure_boot_enabled": True},
        {"iso_sha256": "0" * 64},
    ],
)
def test_q4os_wrong_source_layout_or_media_rejected(media, change):
    media.update(change)
    with pytest.raises(ProbeRefusal):
        probe_q4os(**media)


@pytest.mark.parametrize(
    ("os_release", "version"),
    [
        ("ID=q4os\nVERSION_ID=6\n", "6.10-deb13u1"),
        ("ID=debian\nVERSION_ID=12\n", "6.10-deb13u1"),
        ("ID=debian\nVERSION_ID=13\n", "7.0-deb13u1"),
        ("ID=debian\nVERSION_ID=13\n", "../6.10"),
    ],
)
def test_q4os_identity_requires_separate_native_version_marker(
    media, os_release, version
):
    Path(media["os_release_path"]).write_text(os_release, encoding="utf-8")
    Path(media["q4os_version_path"]).write_text(version, encoding="utf-8")
    with pytest.raises(ProbeRefusal):
        probe_q4os(**media)


def test_missing_native_version_marker_refused(media):
    Path(media["q4os_version_path"]).unlink()
    with pytest.raises(ProbeRefusal, match="version evidence"):
        probe_q4os(**media)
