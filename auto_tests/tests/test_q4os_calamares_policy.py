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
from gaslux_q4os_hook_policy import audit_q4os_native_hooks  # noqa: E402


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


_HOOK_PATHS = (
    "usr/lib/calamares/modules/q4oshook2/module.desc",
    "usr/lib/calamares/modules/q4oshook3/module.desc",
    "usr/lib/calamares/modules/q4oshook5/module.desc",
    "usr/sbin/q4os-hook2a.sh",
    "usr/sbin/q4os-hook3a.sh",
    "usr/sbin/q4os-hook3b.sh",
    "usr/sbin/q4oshook1.sh",
    "usr/sbin/q4oshook4.sh",
    "usr/share/apps/q4os_system/bhooks/bhook1_50_live1.sh",
)


def _synthetic_hook_evidence(evidence):
    import hashlib

    folder = evidence / "native-hooks"
    folder.mkdir()
    lines = []
    for path in _HOOK_PATHS:
        name = path.replace("/", "__")
        content = ("# inert synthetic fixture\n" if path.endswith(".sh") else "type: process\n").encode()
        (folder / name).write_bytes(content)
        lines.append(f"{hashlib.sha256(content).hexdigest()}  {name}")
    (folder / "q4os-hooks-files.sha256").write_text(
        "\n".join(sorted(lines)) + "\n", encoding="ascii"
    )
    return folder


def test_q4os_hook_sources_stay_non_executable_even_when_manifest_is_valid(evidence):
    _synthetic_hook_evidence(evidence)
    report = audit_q4os_native_hooks(evidence)
    assert report["nativeHookSourcesCount"] == 9
    assert report["moduleDescriptorSourceCount"] == 3
    assert report["shellSourceCount"] == 6
    assert report["nativeHookCommandsExecuted"] is False
    assert report["hookExecutionAuthorized"] is False
    assert report["nativeInstallationProven"] is False
    assert report["windowsEspWriteAuthorized"] is False
    assert report["diskWrites"] == 0


def test_refuse_q4os_hook_source_tampering(evidence):
    folder = _synthetic_hook_evidence(evidence)
    (folder / "usr__sbin__q4os-hook2a.sh").write_text("changed contents\n")
    with pytest.raises(CalamaresRefusal, match="SHA-256 mismatch"):
        audit_q4os_native_hooks(evidence)


def test_refuse_symlinked_q4os_hook_source(evidence):
    folder = _synthetic_hook_evidence(evidence)
    target = folder / "usr__sbin__q4os-hook2a.sh"
    target.unlink()
    target.symlink_to(folder / "usr__sbin__q4oshook1.sh")
    with pytest.raises(CalamaresRefusal, match="symlinked"):
        audit_q4os_native_hooks(evidence)


def test_refuse_hook_manifest_path_traversal(evidence):
    folder = _synthetic_hook_evidence(evidence)
    manifest = folder / "q4os-hooks-files.sha256"
    lines = manifest.read_text().splitlines()
    lines[0] = lines[0].split("  ")[0] + "  ../../unauthorized.sh"
    manifest.write_text("\n".join(lines) + "\n")
    with pytest.raises(CalamaresRefusal, match="Malformed or unsafe"):
        audit_q4os_native_hooks(evidence)


def test_refuse_native_hook_sequence_reordered(evidence):
    _synthetic_hook_evidence(evidence)

    def move_hook(settings):
        jobs = settings["sequence"][1]["exec"]
        jobs.remove("q4oshook5")
        jobs.insert(jobs.index("bootloader"), "q4oshook5")

    _change_yaml(evidence, "etc__calamares__settings.conf", move_hook)
    with pytest.raises(CalamaresRefusal, match="ordering"):
        audit_q4os_native_hooks(evidence)


def test_refuse_unsupported_q4os_release_for_native_hooks(evidence):
    _synthetic_hook_evidence(evidence)
    (evidence / "etc__q4os_version").write_text("6.11-deb13u1\n")
    with pytest.raises(CalamaresRefusal, match="identity"):
        audit_q4os_native_hooks(evidence)
