"""Prevent Bazzite legacy lab from ever attaching a writable/foreign disk."""

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github/workflows/gaslux-bazzite-legacy-readonly-gpt.yml"


def workflow():
    return yaml.safe_load(WF.read_text(encoding="utf-8"))


def test_only_disposable_owned_raw_gpt_and_ovmf_var_file_are_writable():
    text = WF.read_text(encoding="utf-8")
    data = workflow()
    assert data["permissions"] == {"contents": "read"}
    vm = data["jobs"]["owned-ro-gpt-ovmf"]
    assert vm["needs"] == "contracts"
    assert vm["runs-on"] == "ubuntu-24.04"
    assert vm["if"] == "github.event_name != 'pull_request'"
    assert "github.event_name" in text
    assert "$RUNNER_TEMP/bazzite-synthetic-gpt-ro" in text
    assert "gaslux-owned-raw-gpt.img" in text
    assert 'truncate -s 68719476736 "$disk"' in text
    assert "37566E43-902A-4DF9-901E-25007AF638C2" in text
    assert "GASLUX-LAB-ESP" in text
    assert "GASLUX-LAB-DATA" in text
    assert 'sgdisk --verify "$disk"' in text
    assert 'chmod 0400 "$disk"' in text
    assert 'sha256sum "$disk"' in text
    assert text.count("sha256sum --check --strict pre-boot.sha256") >= 2
    assert "-nodefaults -machine q35,accel=kvm" in text
    assert "-sandbox on,obsolete=deny,elevateprivileges=deny," in text
    assert "spawn=deny,resourcecontrol=deny" in text
    assert "-nic none -monitor none" in text
    assert "readonly=on,file=$iso" in text
    assert "readonly=on,file=$disk" in text
    assert "-device virtio-blk-pci,drive=synthetic-ro" in text
    assert "serial=GASLUX-ROGPT-42" in text
    assert "OVMF_VARS.disposable.fd" in text
    assert '\"installationAuthorized\": False' in text
    assert '\"windowsEspWriteAuthorized\": False' in text
    assert '\"installerStorageWriteTested\": False' in text
    assert '\"guestDiskDetectedByInstaller\": None' in text
    assert text.count("click 1") == 3


def test_byte_integrity_before_and_after_and_fail_closed_provenance():
    text = WF.read_text(encoding="utf-8")
    assert "44443420174" in text
    assert "c7c808f6da61fca02f2dadb37f74d3bfa0de1166" in text
    assert "9c8d06cd8e57f2274678edeb14b4b13a79b8117c70571a65199919a66305b5c7" in text
    assert "7907770368" in text
    assert "GH_TOKEN:" in text
    steps = workflow()["jobs"]["owned-ro-gpt-ovmf"]["steps"]
    names = [step.get("name") for step in steps]
    assert names.index("Create exact runner-owned GPT raw image before sealing it read-only") < (
        names.index("Download and verify legacy ISO exact lab bytes before optical boot")
    )
    assert names.index("Download and verify legacy ISO exact lab bytes before optical boot") < (
        names.index("Observe native storage GUI with one synthetic read-only GPT device")
    )
    assert steps[-2]["name"] == "Validate sealed owned GPT image is byte-for-byte unchanged"
    assert steps[-2]["if"] == "always()"
    assert steps[-1]["if"] == "always()"
    assert "no ISO signing claim" in text
    assert "beginInstallationActivated" not in text


def test_guests_never_see_windows_or_other_disks_and_never_install():
    text = WF.read_text(encoding="utf-8")
    for forbidden in (
        "mkfs.",
        "wipefs ",
        "parted ",
        "bootc install",
        "efibootmgr ",
        "bcdedit ",
        "grub-install",
        "rpm-ostree",
        "pacstrap",
        "-hda ",
        "-hdb ",
        "/dev/sda",
        "/dev/nvme",
        "/dev/disk",
        "if=virtio,format=qcow2",
        "windows10.qcow2",
        "windows11.qcow2",
        "release-config.json",
        "dd if=",
        "qemu-img create",
    ):
        assert forbidden not in text, forbidden
    assert 'move "$dx" "$dy" click 1' in text
    assert "Begin Installation input" in text
    assert "diskPartitioningAttempted" not in text


def test_all_bash_sections_parse_without_running_any_storage_commands():
    for job in workflow()["jobs"].values():
        for step in job["steps"]:
            if "run" in step:
                result = subprocess.run(
                    ["bash", "-n"],
                    input=step["run"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                assert result.returncode == 0, (step.get("name"), result.stderr)
