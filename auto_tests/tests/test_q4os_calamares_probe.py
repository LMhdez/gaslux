"""Q4OS official Calamares evidence transport tests; no target installation."""

import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "gaslux_q4os_calamares_probe.sh"


def test_must_bind_every_configuration_file_to_one_verified_iso():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "sha256sum -c --status" in source
    assert "sudo mount -o loop,ro,nosuid,nodev,noexec" in source
    assert 'squash="$work/iso/live/filesystem.squashfs"' in source
    assert 'unsquashfs -cat "$squash" "$file"' in source
    for key in (
        "etc/os-release",
        "etc/q4os_version",
        "etc/calamares/settings.conf",
        "etc/calamares/modules/partition.conf",
        "etc/calamares/modules/unpackfs.conf",
        "etc/calamares/modules/bootloader.conf",
    ):
        assert key in source
    assert "INSTALLATION_AUTHORIZED=false" in source
    assert "qemu-system" not in source
    assert "mkfs." not in source
    assert "calamares -d" not in source


def test_refuse_symlinked_iso_before_mount_or_any_write(tmp_path):
    source = tmp_path / "real.iso"
    source.write_bytes(b"synthetic data")
    link = tmp_path / "alias.iso"
    link.symlink_to(source)
    result = subprocess.run(
        ["bash", str(SCRIPT), str(link), "0" * 64, str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "ISO must be an ordinary, non-symlink regular file" in result.stderr


def test_refuse_missing_trust_anchor_before_mount(tmp_path):
    source = tmp_path / "real.iso"
    source.write_bytes(b"synthetic data")
    result = subprocess.run(
        ["bash", str(SCRIPT), str(source), "untrusted", str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Missing independently pinned ISO digest" in result.stderr


def test_refuse_symlinked_evidence_location_before_mount(tmp_path):
    source = tmp_path / "real.iso"
    source.write_bytes(b"synthetic data")
    real = tmp_path / "actual"
    real.mkdir()
    link = tmp_path / "alias"
    link.symlink_to(real)
    result = subprocess.run(
        ["bash", str(SCRIPT), str(source), "0" * 64, str(link)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Evidence directory must exist and not be a symlink" in result.stderr


def test_q4os_native_process_hook_sources_are_pinned_inert_evidence():
    source = SCRIPT.read_text(encoding="utf-8")
    for name in (
        "usr/lib/calamares/modules/q4oshook2/module.desc",
        "usr/lib/calamares/modules/q4oshook3/module.desc",
        "usr/lib/calamares/modules/q4oshook5/module.desc",
        "usr/sbin/q4os-hook2a.sh",
        "usr/sbin/q4os-hook3a.sh",
        "usr/sbin/q4os-hook3b.sh",
        "usr/sbin/q4oshook1.sh",
        "usr/sbin/q4oshook4.sh",
        "usr/share/apps/q4os_system/bhooks/bhook1_50_live1.sh",
    ):
        assert name in source
    assert 'unsquashfs -ll "$squash" "$file"' in source
    assert 'unsquashfs -cat "$squash" "$file"' in source
    assert "q4os-hooks-files.sha256" in source
    assert "Q4OS_HOOK_EXECUTION_AUTHORIZED=false" in source
    assert 'bash "$dest"' not in source
    assert 'sh "$dest"' not in source
    assert "chroot " not in source
    assert "grub-install" not in source
    assert "mkfs." not in source


def test_corrupted_iso_fails_before_reading_any_native_hooks(tmp_path):
    fake = tmp_path / "q4os.iso"
    fake.write_bytes(b"corrupted")
    result = subprocess.run(
        ["bash", str(SCRIPT), str(fake), "0" * 64, str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Full official ISO SHA-256 mismatch" in result.stderr
