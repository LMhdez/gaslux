"""Bazzite legacy GPT COW experiment: only guest overlay writes, never Windows."""

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github/workflows/gaslux-bazzite-legacy-synthetic-cow.yml"


def workflow():
    return yaml.safe_load(WF.read_text(encoding="utf-8"))


def test_owned_overlay_guest_only_and_immutable_backing():
    source = WF.read_text(encoding="utf-8")
    w = workflow()
    assert w["permissions"] == {"contents": "read"}
    assert w["jobs"]["owned-cow-gpt-ovmf"]["needs"] == "contracts"
    assert w["jobs"]["owned-cow-gpt-ovmf"]["runs-on"] == "ubuntu-24.04"
    assert w["jobs"]["owned-cow-gpt-ovmf"]["if"] == "github.event_name != 'pull_request'"
    assert "$RUNNER_TEMP/bazzite-synthetic-gpt-cow" in source
    assert 'truncate -s 68719476736 "$disk"' in source
    assert "37566E43-902A-4DF9-901E-25007AF638C2" in source
    assert "GASLUX-LAB-ESP" in source
    assert "GASLUX-LAB-DATA" in source
    assert 'chmod 0400 "$disk"' in source
    assert 'chmod 0600 "$cow"' in source
    assert 'qemu-img create -f qcow2 -F raw -b "$disk" "$cow"' in source
    assert 'and .["backing-filename"] == $disk' in source
    assert 'and .["backing-filename-format"] == "raw"' in source
    assert 'and .["virtual-size"] == 68719476736' in source
    assert "-nodefaults -machine q35,accel=kvm" in source
    assert "-sandbox on,obsolete=deny,elevateprivileges=deny," in source
    assert "spawn=deny,resourcecontrol=deny" in source
    assert "-nic none -monitor none" in source
    assert "readonly=on,file=$iso" in source
    assert "format=qcow2,readonly=off,file=$cow" in source
    assert "-device virtio-blk-pci,drive=synthetic-cow" in source
    assert "serial=GASLUX-COWGPT-42" in source
    assert "OVMF_VARS.disposable.fd" in source
    assert '"installationAuthorized": False' in source
    assert '"guestWritesConfinedToDisposableOwnedCow": True' in source
    assert '"windowsEspWriteAuthorized": False' in source
    assert '"installerStorageWriteTested": False' in source
    assert '"guestDiskDetectedByInstaller": None' in source
    assert source.count("click 1") == 3


def test_sha256_backing_preserved_and_owned_cow_discarded():
    s = WF.read_text(encoding="utf-8")
    assert "44443420174" in s
    assert "c7c808f6da61fca02f2dadb37f74d3bfa0de1166" in s
    assert "9c8d06cd8e57f2274678edeb14b4b13a79b8117c70571a65199919a66305b5c7" in s
    assert s.count("sha256sum --check --strict pre-boot.sha256") >= 3
    steps = workflow()["jobs"]["owned-cow-gpt-ovmf"]["steps"]
    names = [step.get("name") for step in steps]
    assert names.index("Create exact runner-owned GPT raw image before sealing it read-only") < (
        names.index("Create owned disposable QCOW2 above sealed synthetic GPT")
    )
    assert names.index("Create owned disposable QCOW2 above sealed synthetic GPT") < (
        names.index("Observe native storage GUI through disposable GPT COW overlay")
    )
    assert steps[-2]["name"] == "Verify immutable GPT and discard owned disposable QCOW2"
    assert steps[-2]["if"] == "always()"
    assert steps[-1]["if"] == "always()"
    assert '[[ ! -L "$cow" && "$(stat -c ' in s
    assert 'rm -- "$cow"' in s
    assert '[[ ! -e "$cow" && ! -L "$cow" ]]' in s


def test_guests_have_no_windows_or_physical_disk_and_no_install_input():
    source = WF.read_text(encoding="utf-8")
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
        "windows10.qcow2",
        "windows11.qcow2",
        "release-config.json",
        "dd if=",
    ):
        assert forbidden not in source, forbidden
    assert 'move "$dx" "$dy" click 1' in source
    assert "Begin Installation input" in source
    assert '"installationAuthorized": False' in source
    assert '"partitionWriteAuthorized": False' in source


def test_all_embedded_shell_sections_pass_bash_n():
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
