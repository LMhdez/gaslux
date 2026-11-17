"""Calamares inert 29-job overlay tests (synthetic files; no disk writes)."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets/live"))

from gaslux_q4os_calamares_inert_profile import (  # noqa: E402
    JOBS,
    create_inert_calamares_profile,
)
from gaslux_q4os_calamares_policy import CalamaresRefusal  # noqa: E402
from gaslux_q4os_hook_policy import _HOOK_SOURCES, _NATIVE_DESCRIPTORS  # noqa: E402


@pytest.fixture
def evidence(tmp_path):
    data = {
        "etc__os-release": 'ID=debian\nVERSION_ID="13"\n',
        "etc__q4os_version": "6.10-deb13u1\n",
        "etc__calamares__settings.conf": yaml.safe_dump(
            {
                "dont-chroot": False,
                "oem-setup": False,
                "sequence": [
                    {
                        "show": [
                            "welcome", "locale", "keyboard", "packagechooser",
                            "partition", "users", "summary",
                        ]
                    },
                    {"exec": list(JOBS)},
                    {"show": ["finished"]},
                ],
            }
        ),
        "etc__calamares__modules__partition.conf": yaml.safe_dump(
            {
                "defaultFileSystemType": "ext4",
                "initialPartitioningChoice": "none",
                "efi": {"mountPoint": "/boot/efi"},
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
                "grubMkconfig": "grub-mkconfig",
                "efiBootMgr": "efibootmgr",
            }
        ),
        "etc__calamares__modules__packages.conf": yaml.safe_dump(
            {
                "backend": "apt",
                "update_db": False,
                "update_system": False,
                "operations": [{"try_remove": ["live-tools"]}],
            }
        ),
        "etc__calamares__modules__mount.conf": "extraMounts: []\n",
        "etc__calamares__modules__fstab.conf": "mountOptions: default\n",
        "etc__calamares__modules__grubcfg.conf": "overwrite: false\n",
        "etc__calamares__modules__users.conf": "setRootPassword: true\n",
        "etc__calamares__modules__displaymanager.conf": "displaymanagers: []\n",
    }
    for name, contents in data.items():
        (tmp_path / name).write_text(contents, encoding="utf-8")
    hookdir = tmp_path / "native-hooks"
    hookdir.mkdir()
    manifest = []
    for path in _HOOK_SOURCES:
        name = path.replace("/", "__")
        desc_name = path.split("/")[-2] if path.endswith("module.desc") else None
        if desc_name:
            command, timeout = _NATIVE_DESCRIPTORS[desc_name]
            payload = yaml.safe_dump(
                {
                    "type": "job", "name": desc_name, "interface": "process",
                    "command": command, "timeout": timeout,
                }
            ).encode()
        else:
            payload = b"#!/bin/sh\n# synthetic script, never executed\n"
        (hookdir / name).write_bytes(payload)
        manifest.append(f"{hashlib.sha256(payload).hexdigest()}  {name}")
    (hookdir / "q4os-hooks-files.sha256").write_text(
        "\n".join(sorted(manifest)) + "\n", encoding="ascii"
    )
    return tmp_path


def _change(evidence, filename, mutator):
    file = evidence / filename
    data = yaml.safe_load(file.read_text(encoding="utf-8"))
    mutator(data)
    file.write_text(yaml.safe_dump(data), encoding="utf-8")


def test_inert_profile_preserves_full_native_graph_and_blocks_all_risky_writers(evidence):
    report = create_inert_calamares_profile(evidence)
    assert report["nativeExecJobsCount"] == 29
    assert report["nativeShowCount"] == 8
    assert report["nativeFullExecOrderVerified"] is True
    assert report["profileActivationAuthorized"] is False
    assert report["installationAuthorized"] is False
    assert report["windowsEspWriteAuthorized"] is False
    assert report["firmwareNvramWriteAuthorized"] is False
    assert report["calamaresJobEngineExecuted"] is False
    assert report["diskWrites"] == 0
    directory = evidence / "calamares-inert-profile"
    boot = yaml.safe_load(
        (directory / "etc/calamares/modules/bootloader.conf").read_text()
    )
    assert boot["efiBootLoader"] == "grub"
    assert boot["efiBootloaderId"] == "GasluxQ4OSLab"
    assert boot["installEFIFallback"] is False
    for binary in ("grubInstall", "grubMkconfig", "efiBootMgr"):
        assert boot[binary] == "/bin/false"
    packages = yaml.safe_load(
        (directory / "etc/calamares/modules/packages.conf").read_text()
    )
    assert packages["operations"] == []
    assert packages["skip_if_no_internet"] is True
    settings = yaml.safe_load(
        (directory / "etc/calamares/settings.conf").read_text()
    )
    assert settings["sequence"][1]["exec"] == list(JOBS)
    for hook in ("q4oshook2", "q4oshook3", "q4oshook5"):
        descriptor = yaml.safe_load(
            (directory / f"usr/lib/calamares/modules/{hook}/module.desc").read_text()
        )
        assert descriptor["command"] == "/bin/false"
    for relative, expected in report["generatedFileSha256"].items():
        assert hashlib.sha256((directory / relative).read_bytes()).hexdigest() == expected


def test_unknown_native_job_rejected_before_profile_written(evidence):
    _change(
        evidence,
        "etc__calamares__settings.conf",
        lambda cfg: cfg["sequence"][1]["exec"].append("untrusted-job"),
    )
    with pytest.raises(CalamaresRefusal, match="job graph"):
        create_inert_calamares_profile(evidence)
    assert not (evidence / "calamares-inert-profile").exists()


def test_unsafe_efi_fallback_semantics_change_rejected(evidence):
    _change(
        evidence,
        "etc__calamares__modules__bootloader.conf",
        lambda cfg: cfg.update({"installEFIFallback": False}),
    )
    with pytest.raises(CalamaresRefusal):
        create_inert_calamares_profile(evidence)


def test_hash_mismatch_in_native_hooks_blocks_overlay(evidence):
    (evidence / "native-hooks/usr__sbin__debian_adjust2.sh").write_text(
        "modified upstream command\n"
    )
    with pytest.raises(CalamaresRefusal, match="SHA-256 mismatch"):
        create_inert_calamares_profile(evidence)
    assert not (evidence / "calamares-inert-profile").exists()


def test_profile_output_collision_rejected_instead_of_overwriting(evidence):
    create_inert_calamares_profile(evidence)
    with pytest.raises(CalamaresRefusal, match="prior Calamares profile"):
        create_inert_calamares_profile(evidence)


def test_profile_output_symlink_rejected(evidence, tmp_path):
    (evidence / "calamares-inert-profile").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(CalamaresRefusal, match="prior Calamares profile"):
        create_inert_calamares_profile(evidence)
