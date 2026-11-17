"""Laboratory-only regressions; synthetic ISO images are not boot evidence."""

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets/live"))
from gaslux_lab_media_probe import (  # noqa: E402
    ProbeRefusal,
    diagnostic,
    verify_iso_header_and_hash,
)


def fake_iso(tmp_path):
    data = bytearray(40 * 2048)
    data[16 * 2048] = 1
    data[16 * 2048 + 1 : 16 * 2048 + 6] = b"CD001"
    data[16 * 2048 + 6] = 1
    data[17 * 2048] = 255
    data[17 * 2048 + 1 : 17 * 2048 + 6] = b"CD001"
    data[17 * 2048 + 6] = 1
    path = tmp_path / "candidate.iso"
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


def test_pinned_iso_header_and_digest(tmp_path):
    iso, digest = fake_iso(tmp_path)
    assert verify_iso_header_and_hash(str(iso), iso.stat().st_size, digest)["iso9660Header"]


@pytest.mark.parametrize("mutation", ["size", "hash", "header", "symlink", "relative"])
def test_iso_rejection(tmp_path, mutation):
    iso, digest = fake_iso(tmp_path)
    size = iso.stat().st_size
    path = str(iso)
    if mutation == "size":
        size += 1
    elif mutation == "hash":
        digest = "a" * 64
    elif mutation == "header":
        content = bytearray(iso.read_bytes())
        content[16 * 2048 + 1] = 0
        iso.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
    elif mutation == "symlink":
        alias = tmp_path / "alias.iso"
        alias.symlink_to(iso)
        path = str(alias)
    else:
        path = "candidate.iso"
    with pytest.raises(ProbeRefusal):
        verify_iso_header_and_hash(path, size, digest)


def test_probe_is_not_install_authorization(tmp_path):
    iso, digest = fake_iso(tmp_path)
    identity = tmp_path / "os-release"
    identity.write_text('NAME="Pop!_OS"\nID=pop\nVERSION_ID="24.04"\n')
    result = diagnostic(
        iso_path=str(iso),
        expected_size=iso.stat().st_size,
        expected_sha256=digest,
        os_release_path=str(identity),
        expected_os_id="pop",
        firmware="uefi",
        partition_style="gpt",
        secure_boot_enabled=False,
        bootloader="systemd-boot",
        backend="system76",
        allowed_modes={"uefi/gpt": "systemd-boot"},
        require_secure_boot_disabled=True,
    )
    assert result["result"] == "diagnostic-only"
    assert result["installationAuthorized"] is False
    assert result["signedCatalogVerified"] is False
    assert result["isoToLiveIdentityBindingProven"] is False
    assert result["diskWrites"] == 0


def test_wrong_identity_rejected(tmp_path):
    iso, digest = fake_iso(tmp_path)
    identity = tmp_path / "os-release"
    identity.write_text("ID=fedora\n")
    with pytest.raises(ProbeRefusal, match="identity"):
        diagnostic(
            iso_path=str(iso),
            expected_size=iso.stat().st_size,
            expected_sha256=digest,
            os_release_path=str(identity),
            expected_os_id="pop",
            firmware="uefi",
            partition_style="gpt",
            secure_boot_enabled=False,
            bootloader="systemd-boot",
            backend="system76",
            allowed_modes={"uefi/gpt": "systemd-boot"},
        )


def test_secure_boot_and_unsupported_layout_refused_before_media_access():
    args = dict(
        iso_path="/definitely/not-present.iso",
        expected_size=100000,
        expected_sha256="a" * 64,
        os_release_path="/no/os-release",
        expected_os_id="pop",
        firmware="uefi",
        partition_style="gpt",
        secure_boot_enabled=True,
        bootloader="systemd-boot",
        backend="system76",
        allowed_modes={"uefi/gpt": "systemd-boot"},
        require_secure_boot_disabled=True,
    )
    with pytest.raises(ProbeRefusal, match="Secure Boot"):
        diagnostic(**args)
    args.update(firmware="bios", partition_style="mbr", secure_boot_enabled=False)
    with pytest.raises(ProbeRefusal, match="Unsupported"):
        diagnostic(**args)


def test_os_release_duplicate_keys_fail(tmp_path):
    from gaslux_lab_media_probe import read_os_release_evidence

    path = tmp_path / "os-release"
    path.write_text("ID=pop\nID=fedora\n")
    with pytest.raises(ProbeRefusal, match="duplicate"):
        read_os_release_evidence(str(path))
