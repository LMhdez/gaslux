"""Unit tests for Q4OS Calamares ISO inventory; no host or VM disks touched."""

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gaslux_q4os_calamares_inventory as probe  # noqa: E402


def _fixture(tmp_path, monkeypatch):
    iso = tmp_path / "official.iso"
    squashfs = tmp_path / "filesystem.squashfs"
    iso.write_bytes(b"synthetic-not-official")
    squashfs.write_bytes(b"synthetic-squashfs")
    files = {
        "etc/q4os_version": b"6.10\n",
        "etc/os-release": b"ID=debian\nVERSION_ID=13\n",
        "etc/calamares/settings.conf": (
            b"sequence:\n  - show: [partition, users]\n"
            b"  - exec: [mount, unpackfs, bootloader]\n"
            b"dont-chroot: false\n"
        ),
        "etc/calamares/modules/unpackfs.conf": b"unpack: []\n",
    }
    paths = {key: "-" for key in files}
    paths["usr/bin/calamares"] = "-"
    monkeypatch.setattr(probe, "sha256_file", lambda _: probe.PINNED_Q4OS_SHA256)
    monkeypatch.setattr(probe, "listing_paths", lambda _: paths)
    monkeypatch.setattr(probe, "squashfs_cat", lambda _, name: files[name])
    return iso, squashfs, files, paths


def test_same_iso_config_identity_and_module_provenance_are_recorded(tmp_path, monkeypatch):
    iso, squashfs, files, _ = _fixture(tmp_path, monkeypatch)
    out = tmp_path / "evidence"
    result = probe.inventory(iso, squashfs, out)
    assert result["source"] == "same-pinned-official-iso-live-squashfs"
    assert result["q4osVersionFile"] == "etc/q4os_version"
    assert result["q4osVersionText"] == "6.10"
    assert result["calamaresBinaryPresent"]
    assert result["calamaresSettingsFile"] == "etc/calamares/settings.conf"
    assert result["calamaresDontChroot"] is False
    assert result["sequence"]["exec"] == ["mount", "unpackfs", "bootloader"]
    assert result["manifest"]["etc/calamares/settings.conf"]["sha256"] == (
        hashlib.sha256(files["etc/calamares/settings.conf"]).hexdigest()
    )
    assert (out / "source/etc/q4os_version").read_bytes() == b"6.10\n"
    assert (out / "calamares-inventory.json").is_file()
    assert result["installationAuthorized"] is False
    assert result["firstBootProven"] is False
    assert result["windowsPreservationProven"] is False


def test_missing_installer_does_not_become_authorized(tmp_path, monkeypatch):
    iso, squashfs, _, paths = _fixture(tmp_path, monkeypatch)
    del paths["usr/bin/calamares"]
    del paths["etc/calamares/settings.conf"]
    out = probe.inventory(iso, squashfs, tmp_path / "out")
    assert not out["calamaresBinaryPresent"]
    assert out["calamaresSettingsFile"] is None
    assert not out["installationAuthorized"]


def test_wrong_digest_refused_before_squashfs_reads(tmp_path, monkeypatch):
    iso, squashfs, _, _ = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(probe, "sha256_file", lambda _: "f" * 64)
    with pytest.raises(ValueError, match="does not match pinned"):
        probe.inventory(iso, squashfs, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_symlinked_iso_and_live_root_refused(tmp_path, monkeypatch):
    iso, squashfs, _, _ = _fixture(tmp_path, monkeypatch)
    iso_link = tmp_path / "link.iso"
    iso_link.symlink_to(iso)
    squash_link = tmp_path / "link.squashfs"
    squash_link.symlink_to(squashfs)
    with pytest.raises(ValueError, match="symlink"):
        probe.inventory(iso_link, squashfs, tmp_path / "out1")
    with pytest.raises(ValueError, match="symlink"):
        probe.inventory(iso, squash_link, tmp_path / "out2")


def test_squashfs_cat_rejects_parent_traversal(tmp_path):
    with pytest.raises(ValueError, match="Unsafe"):
        probe.squashfs_cat(tmp_path / "fake.squashfs", "../etc/shadow")


def test_invalid_and_empty_modules_are_not_reported_as_exec():
    assert probe.modules_in_sequence("not-a-map") == {"show": [], "exec": []}
    assert probe.modules_in_sequence({"sequence": [{"exec": "unexpected"}]}) == {
        "show": [],
        "exec": [],
    }
