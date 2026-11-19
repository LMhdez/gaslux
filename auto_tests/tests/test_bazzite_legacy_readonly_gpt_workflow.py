"""No-write contract for Bazzite legacy read-only synthetic GPT in OVMF."""

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/gaslux-bazzite-legacy-readonly-gpt.yml"


def load():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_only_synthetic_private_cow_backed_disk_is_attached():
    source = WORKFLOW.read_text(encoding="utf-8")
    jobs = load()["jobs"]
    assert load()["permissions"] == {"contents": "read", "actions": "read"}
    job = jobs["readonly-gpt-stage3"]
    assert job["needs"] == ["contracts", "prior-blue-button"]
    assert job["if"] == "github.event_name != 'pull_request'"
    assert job["runs-on"] == "ubuntu-24.04"
    assert "-nodefaults -machine q35,accel=kvm" in source
    assert "-nic none -monitor none" in source
    assert "readonly=on,file=$iso" in source
    assert 'disk="$work/glx-synthetic-gpt.raw"' in source
    assert 'overlay="$work/glx-synthetic-gpt-overlay.qcow2"' in source
    assert '"$RUNNER_TEMP/bazzite-legacy-readonly-gpt"' in source
    assert "qemu-img create -f raw" in source
    assert 'qemu-img create -f qcow2 -F raw -b "$disk" "$overlay"' in source
    assert '-drive "if=none,id=glx-owned,format=qcow2,file=$overlay"' in source
    assert "readonly=on,file=$disk" not in source
    assert "-device virtio-blk-pci,drive=glx-owned,serial=GLXBAZRO001" in source
    assert "sgdisk --clear" in source
    assert "sgdisk --verify" in source
    assert "sgdisk --print" in source
    assert '[[ ! -e "$disk" && ! -L "$disk" ]]' in source
    assert "chmod 0400" in source
    assert "sha256sum --check --strict" in source
    assert "qemu-img info --output=json" in source
    assert '[[ ! -e "$overlay" && ! -L "$overlay" ]] || status=1' in source
    assert "guestDiskWritableCOWOverlay" in source
    assert "hostBackingImmutable" in source
    assert "trap audit_owned_base EXIT" in source
    assert "Synthetic GPT backing unchanged byte-for-byte" in source


def test_no_windows_storage_or_installer_mutation_code():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert source.count("click 1") == 3
    assert '"beginInstallationButtonClicked": False' in source
    assert '"installationAuthorized": False' in source
    assert '"partitionWriteAuthorized": False' in source
    assert '"windowsEspWriteAuthorized": False' in source
    assert '"guestDiskIdentityIndependentlyVerified": False' in source
    assert '"isoProvenanceSignatureVerified": False' in source
    for blocked in (
        "bcdedit ",
        "efibootmgr ",
        "wipefs ",
        "mkfs.",
        "mount /dev/",
        "sgdisk /dev/",
        "parted /dev/",
        "dd of=/dev/",
        "qemu-nbd",
        "windows10.qcow2",
        "windows11.qcow2",
        "bootc install",
        "rpm-ostree",
        "release-config.json",
        "-hda ",
        "-hdb ",
        "if=virtio,format=qcow2",
    ):
        assert blocked not in source, blocked


def test_original_guest_screen_gates_are_reused():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert "gh run download 44378715492" in source
    assert "bazzite_legacy_blue_button.py" in source
    assert "bazzite_legacy_destination_gate.py" in source
    assert source.index("--phase locale") < source.index('move "$lx" "$ly" click 1')
    assert source.index("blue-gate.json") < source.index('move "$cx" "$cy" click 1')
    assert source.index("destination-gate.json") < source.index('move "$dx" "$dy" click 1')
    assert "capture after-destination" in source


def test_every_embedded_bash_script_parses():
    for job in load()["jobs"].values():
        for step in job["steps"]:
            if "run" not in step:
                continue
            result = subprocess.run(
                ["bash", "-n"],
                input=step["run"],
                text=True,
                capture_output=True,
                check=False,
            )
            assert result.returncode == 0, (step.get("name"), result.stderr)
