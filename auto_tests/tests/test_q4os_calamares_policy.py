"""Synthetic native Calamares policy regressions; never an install test."""

import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets/live"))
from gaslux_q4os_calamares_policy import (  # noqa: E402
    CalamaresRefusal,
    audit_q4os_calamares,
)


@pytest.fixture
def evidence(tmp_path):
    settings = {
        "oem-setup": False,
        "dont-chroot": False,
        "sequence": [
            {"show": ["welcome", "partition", "users", "summary"]},
            {
                "exec": [
                    "partition",
                    "mount",
                    "unpackfs",
                    "q4oshook2",
                    "grubcfg",
                    "bootloader",
                    "q4oshook3",
                    "packages",
                    "initramfs",
                    "q4oshook5",
                    "umount",
                ]
            },
            {"show": ["finished"]},
        ],
    }
    contents = {
        "etc__os-release": 'ID=debian\nVERSION_ID="13"\n',
        "etc__q4os_version": "6.10-deb13u1\n",
        "etc__calamares__settings.conf": yaml.safe_dump(settings),
        "etc__calamares__modules__partition.conf": yaml.safe_dump(
            {
                "efi": {"mountPoint": "/boot/efi"},
                "defaultFileSystemType": "ext4",
                "initialPartitioningChoice": "none",
            }
        ),
        "etc__calamares__modules__unpackfs.conf": yaml.safe_dump(
            {
                "unpack": [
                    {
                        "source": "/run/live/medium/live/filesystem.squashfs",
                        "sourcefs": "squashfs",
                        "destination": "",
                    }
                ]
            }
        ),
        "etc__calamares__modules__bootloader.conf": yaml.safe_dump(
            {
                "efiBootLoader": "grub",
                "grubInstall": "grub-install",
                "grubCfg": "/boot/grub/grub.cfg",
                "installEFIFallback": True,
            }
        ),
        "etc__calamares__modules__packages.conf": "backend: apt\n",
        "etc__calamares__modules__mount.conf": "extraMounts: []\n",
        "etc__calamares__modules__fstab.conf": "mountOptions: default\n",
        "etc__calamares__modules__grubcfg.conf": "overwrite: false\n",
        "etc__calamares__modules__users.conf": "setRootPassword: true\n",
        "etc__calamares__modules__displaymanager.conf": "displaymanagers: []\n",
    }
    for name, text in contents.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def _change_yaml(evidence, name, change):
    path = evidence / name
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    change(data)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def test_verified_config_still_forbids_installation_and_windows_esp_writes(evidence):
    result = audit_q4os_calamares(evidence)
    assert result["nativeCalamaresConfigVerified"] is True
    assert result["unpackSourceBoundToIsoRoot"] is True
    assert result["upstreamInstallsEfiFallback"] is True
    assert result["windowsEspFallbackWriteAuthorized"] is False
    assert result["installationAuthorized"] is False
    assert result["installedSystemBootVerified"] is False
    assert result["diskWrites"] == 0
    assert all(len(digest) == 64 for digest in result["calamaresModulesSha256"].values())


@pytest.mark.parametrize(
    ("file", "field", "value"),
    [
        ("etc__calamares__modules__unpackfs.conf", "unpack", []),
        ("etc__calamares__modules__bootloader.conf", "efiBootLoader", "systemd-boot"),
        ("etc__calamares__modules__partition.conf", "defaultFileSystemType", "btrfs"),
        ("etc__calamares__modules__partition.conf", "initialPartitioningChoice", "erase"),
        ("etc__calamares__settings.conf", "dont-chroot", True),
        ("etc__calamares__settings.conf", "oem-setup", True),
        ("etc__calamares__modules__packages.conf", "backend", "pacman"),
    ],
)
def test_refuse_mismatched_native_config(evidence, file, field, value):
    _change_yaml(evidence, file, lambda d: d.update({field: value}))
    with pytest.raises(CalamaresRefusal):
        audit_q4os_calamares(evidence)


def test_refuse_reordered_partitioning(evidence):
    def reorder(settings):
        settings["sequence"][1]["exec"][:3] = ["mount", "partition", "unpackfs"]

    _change_yaml(evidence, "etc__calamares__settings.conf", reorder)
    with pytest.raises(CalamaresRefusal, match="storage sequence"):
        audit_q4os_calamares(evidence)


def test_refuse_missing_q4os_hook(evidence):
    def remove_hook(settings):
        settings["sequence"][1]["exec"].remove("q4oshook5")

    _change_yaml(evidence, "etc__calamares__settings.conf", remove_hook)
    with pytest.raises(CalamaresRefusal, match="q4oshook5"):
        audit_q4os_calamares(evidence)


def test_refuse_duplicate_yaml_keys(evidence):
    path = evidence / "etc__calamares__modules__unpackfs.conf"
    path.write_text("unpack: []\nunpack: []\n", encoding="utf-8")
    with pytest.raises(CalamaresRefusal, match="repeated YAML key"):
        audit_q4os_calamares(evidence)


def test_refuse_symlinked_config_even_if_target_contains_correct_data(evidence):
    path = evidence / "etc__calamares__modules__bootloader.conf"
    original = path.read_bytes()
    path.unlink()
    real = evidence / "other.conf"
    real.write_bytes(original)
    path.symlink_to(real)
    with pytest.raises(CalamaresRefusal, match="symlinked"):
        audit_q4os_calamares(evidence)


def test_refuse_invalid_distribution_version(evidence):
    (evidence / "etc__q4os_version").write_text("6.11-deb13u1\n", encoding="utf-8")
    with pytest.raises(CalamaresRefusal, match="identity"):
        audit_q4os_calamares(evidence)
