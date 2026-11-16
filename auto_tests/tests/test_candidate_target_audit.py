"""Pure fixture audits: not evidence of an actually installed or booted system."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets/live"))
from gaslux_candidate_target_audit import audit_candidate_target  # noqa: E402
from gaslux_lab_media_probe import ProbeRefusal  # noqa: E402

RUN_ID = "candidate-run-20261116"
ROOT_UUID = "12345678-1234-1234-1234-123456789abc"
ESP_UUID = "1234-ABCD"
WINDOWS_BYTES = b"MZ" + b"WindowsLoaderFixture"


def make_fixture(tmp_path, distro):
    root = tmp_path / distro
    root.mkdir()

    def file(path, data):
        dst = root / path
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(data, encoding="utf-8")

    file(".gaslux-stage-owner", RUN_ID + "\n")
    root_fs = "btrfs" if distro == "bazzite" else "ext4"
    file(
        "etc/fstab",
        f"UUID={ROOT_UUID} / {root_fs} defaults 0 1\n"
        f"UUID={ESP_UUID} /boot/efi vfat umask=0077 0 2\n",
    )
    loader = root / "boot/efi/EFI/Microsoft/Boot/bootmgfw.efi"
    loader.parent.mkdir(parents=True)
    loader.write_bytes(WINDOWS_BYTES)
    if distro == "popos":
        file("etc/os-release", "ID=pop\n")
        file(
            "var/lib/dpkg/status",
            "".join(
                f"Package: {name}\nStatus: install ok installed\n\n"
                for name in ("pop-desktop", "linux-system76", "systemd-boot")
            ),
        )
        file("boot/efi/loader/entries/pop.conf", "title Pop_OS\nlinux /EFI/Pop_OS/vmlinuz.efi\n")
    elif distro == "q4os":
        file("etc/os-release", 'ID=debian\nVERSION_ID="13"\n')
        file("etc/q4os_version", "6.10-deb13u1\n")
        file("boot/grub/grub.cfg", "menuentry 'Q4OS' { linux /vmlinuz }\n")
    elif distro == "bazzite":
        file("etc/os-release", 'ID=fedora\nPRETTY_NAME="Fedora Linux (Bazzite)"\n')
        (root / "ostree/deploy").mkdir(parents=True)
        file("boot/loader/entries/ostree.conf", "title Bazzite\noptions ostree=/ostree\n")
    backend = {"popos": "system76", "q4os": "q4os-native", "bazzite": "fedora-atomic"}[distro]
    args = {
        "root": root,
        "distribution_id": distro,
        "backend": backend,
        "run_id": RUN_ID,
        "expected_root_uuid": ROOT_UUID,
        "firmware_layout": "uefi/gpt",
        "esp_uuid": ESP_UUID,
        "windows_loader_sha256": hashlib.sha256(WINDOWS_BYTES).hexdigest(),
    }
    return args


@pytest.mark.parametrize("distro", ["popos", "q4os", "bazzite"])
def test_target_evidence_never_claims_boot_or_rollback(tmp_path, distro):
    args = make_fixture(tmp_path, distro)
    result = audit_candidate_target(**args)
    assert result["ownershipMarkerVerified"] is True
    assert result["windowsLoaderFileHashMatches"] is True
    assert result["linuxBootVerified"] is False
    assert result["windowsBootVerified"] is False
    assert result["recoveryVerified"] is False
    assert result["rootBlockDeviceVerified"] is False
    assert result["installationAuthorized"] is False


@pytest.mark.parametrize(
    "change",
    [
        {"run_id": "foreign-run-123456"},
        {"expected_root_uuid": "11111111-1111-1111-1111-111111111111"},
        {"esp_uuid": "0000-0000"},
        {"windows_loader_sha256": "f" * 64},
        {"firmware_layout": "bios/mbr"},
        {"backend": "fedora-atomic"},
    ],
)
def test_foreign_or_changed_target_rejected(tmp_path, change):
    args = make_fixture(tmp_path, "popos")
    args.update(change)
    with pytest.raises(ProbeRefusal):
        audit_candidate_target(**args)


@pytest.mark.parametrize("distro", ["popos", "q4os", "bazzite"])
def test_windows_loader_tampering_rejected(tmp_path, distro):
    args = make_fixture(tmp_path, distro)
    path = args["root"] / "boot/efi/EFI/Microsoft/Boot/bootmgfw.efi"
    path.write_bytes(b"MZ" + b"tampered")
    with pytest.raises(ProbeRefusal, match="Windows Boot Manager"):
        audit_candidate_target(**args)


def test_symlinked_windows_bootmanager_refused(tmp_path):
    args = make_fixture(tmp_path, "q4os")
    original = args["root"] / "boot/efi/EFI/Microsoft/Boot/bootmgfw.efi"
    original.unlink()
    original.symlink_to("/etc/passwd")
    with pytest.raises(ProbeRefusal, match="Symlink"):
        audit_candidate_target(**args)


def test_missing_pop_package_and_q4os_version_refused(tmp_path):
    pop = make_fixture(tmp_path, "popos")
    (pop["root"] / "var/lib/dpkg/status").write_text("Package: unrelated\n")
    with pytest.raises(ProbeRefusal, match="System76"):
        audit_candidate_target(**pop)
    q4 = make_fixture(tmp_path, "q4os")
    (q4["root"] / "etc/q4os_version").write_text("7.0")
    with pytest.raises(ProbeRefusal, match="Q4OS"):
        audit_candidate_target(**q4)


def test_atomic_bios_is_rejected_before_target_read(tmp_path):
    args = make_fixture(tmp_path, "bazzite")
    args.update(firmware_layout="bios/mbr", root=Path("/not-a-real-mount"))
    with pytest.raises(ProbeRefusal):
        audit_candidate_target(**args)


def test_mbr_fixture_does_not_pretend_uefi_proof(tmp_path):
    args = make_fixture(tmp_path, "q4os")
    args["firmware_layout"] = "bios/mbr"
    args["esp_uuid"] = "none"
    args["windows_loader_sha256"] = None
    result = audit_candidate_target(**args)
    assert result["windowsLoaderFileHashMatches"] is False
    assert result["windowsBootVerified"] is False
