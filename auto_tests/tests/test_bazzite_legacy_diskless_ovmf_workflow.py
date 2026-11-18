"""Fail-closed diskless Bazzite legacy ISO VM observation workflow contracts."""

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github/workflows/gaslux-bazzite-legacy-diskless-ovmf.yml"


def _get():
    return yaml.safe_load(WF.read_text(encoding="utf-8"))


def test_only_hosted_kvm_diskless_readonly_guest_is_allowed():
    source = WF.read_text(encoding="utf-8")
    wf = _get()
    assert wf["permissions"] == {"contents": "read"}
    assert "feature/bazzite-legacy-iso-scout-20261118" in str(wf.get("on", wf.get(True)))
    assert wf["jobs"]["legacy-ovmf-diskless"]["needs"] == "contracts"
    assert wf["jobs"]["legacy-ovmf-diskless"]["runs-on"] == "ubuntu-24.04"
    assert "-nodefaults -machine q35,accel=kvm" in source
    sandbox_option = "-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"
    assert sandbox_option in source
    assert "-nic none -monitor none" in source
    assert "readonly=on,file=$iso" in source
    assert "OVMF_VARS.disposable.fd" in source
    assert "8192" in source
    assert "-vnc 127.0.0.1:1" in source
    assert "guest-observation.json" in source
    assert '"installationAuthorized": False' in source
    assert '"windowsEspWriteAuthorized": False' in source
    for forbidden in (
        "qemu-img create",
        "mkfs.",
        "wipefs ",
        "sgdisk ",
        "parted ",
        "efibootmgr ",
        "bcdedit ",
        "bootc install",
        "rpm-ostree",
        "pacstrap",
        "-hda ",
        "-hdb ",
        "id=owned-target",
        "driver=host_device",
        "if=virtio,format=qcow2",
        "windows10.qcow2",
        "windows11.qcow2",
        "sudo dd ",
        "-drive file=/dev/",
        "vncdotool\" -s 127.0.0.1::5901 move",
    ):
        assert forbidden not in source, forbidden


def test_media_verified_before_any_qemu_and_no_auto_install():
    wf = _get()
    names = [
        step.get("name", "")
        for step in wf["jobs"]["legacy-ovmf-diskless"]["steps"]
    ]
    assert names.index("Download and verify exact unsigned legacy ISO lab bytes before boot") < (
        names.index("Quarantined OVMF boot: optical only, no disk, network or installer input")
    )
    source = WF.read_text(encoding="utf-8")
    assert "9c8d06cd8e57f2274678edeb14b4b13a79b8117c70571a65199919a66305b5c7" in source
    assert "7907770368" in source
    assert "sha256sum --check --strict" in source
    assert "officialGithubAttestationVerified" not in source
    assert '"isoCryptographicProvenanceVerified": False' in source
    assert '"nativeLegacyInstallerVerified": False' in source
    assert '"manualPartitioningInGuestVerified": False' in source
    assert '"partitionWriteAuthorized": False' in source
    assert "for phase in 1 2 3 4" in source
    assert wf["jobs"]["legacy-ovmf-diskless"]["steps"][-1]["if"] == "always()"


def test_all_shell_steps_parse_without_accessing_disks():
    for job in _get()["jobs"].values():
        for step in job["steps"]:
            if "run" in step:
                result = subprocess.run(
                    ["bash", "-n"],
                    input=step["run"],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                assert result.returncode == 0, (step.get("name", "?"), result.stderr)
