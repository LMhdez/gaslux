"""The legacy Bazzite stage2 VM has no disk/NIC or uncontrolled installer input."""

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github/workflows/gaslux-bazzite-legacy-diskless-navigation.yml"


def _workflow():
    return yaml.safe_load(WF.read_text(encoding="utf-8"))


def test_isolation_and_fail_closed_keyboard_mouse_scope():
    text = WF.read_text(encoding="utf-8")
    wf = _workflow()
    assert wf["permissions"] == {"contents": "read", "actions": "read"}
    assert wf["jobs"]["diskless-locale-stage2"]["needs"] == ["contracts", "prior-blue-button"]
    assert wf["jobs"]["prior-blue-button"]["needs"] == "contracts"
    assert wf["jobs"]["diskless-locale-stage2"]["if"] == "github.event_name != 'pull_request'"
    assert "9c8d06cd8e57f2274678edeb14b4b13a79b8117c70571a65199919a66305b5c7" in text
    assert "7907770368" in text
    assert "-nodefaults -machine q35,accel=kvm" in text
    assert "-sandbox on,obsolete=deny,elevateprivileges=deny," in text
    assert "spawn=deny,resourcecontrol=deny" in text
    assert "readonly=on,file=$iso" in text
    assert "-nic none -monitor none" in text
    assert "-vnc 127.0.0.1:1" in text
    assert "disposable-ovmf-vars.fd" in text
    assert text.count("click 1") == 3
    assert "locale-coordinate" in text
    assert "continue-coordinate" in text
    assert "destination-coordinate" in text
    assert "noDisksSelectedTextVerified" in text
    assert '"beginInstallationButtonClicked": False' in text
    assert '"partitionStyleObserved": None' in text
    assert '"installationAuthorized": False' in text
    assert '"windowsEspWriteAuthorized": False' in text
    for forbidden in (
        "qemu-img",
        "mkfs.",
        "parted ",
        "sgdisk ",
        "wipefs ",
        "bcdedit ",
        "efibootmgr ",
        "bootc install",
        "rpm-ostree",
        "pacstrap",
        "windows10.qcow2",
        "windows11.qcow2",
        "if=virtio,format=qcow2",
        "-hda",
        "-hdb",
        "-drive file=/dev/",
        "release-config.json",
    ):
        assert forbidden not in text, forbidden


def test_clicks_follow_ocr_checks_not_hardcoded_targets():
    content = WF.read_text(encoding="utf-8")
    assert content.index("--phase locale") < content.index("locale-coordinate")
    assert content.index("auto_tests/bazzite_legacy_blue_button.py") < content.rindex("--coords")
    assert "gh run download 44375068915" in content
    assert "blueContinueTextVerified" in content
    assert "blueContinueGeometryVerified" in content
    assert "prior-blue-button" in content
    assert 'if [[ -s "$work/continue-coordinate" ]]' in content
    assert content.count('move "$lx" "$ly" click 1') == 1
    assert content.count('move "$cx" "$cy" click 1') == 1
    assert content.count('move "$dx" "$dy" click 1') == 1
    assert "gh run download 44378715492" in content
    assert ".head_sha == \"5ebe64d41beeeeec82fc74bfb9e30bcfa934adfa\"" in content
    assert content.index("capture after-continue") < content.index(
        "--png bazzite-legacy-stage2-evidence/after-continue.png"
    )
    assert content.index("auto_tests/bazzite_legacy_destination_gate.py") < content.index(
        'move "$dx" "$dy" click 1'
    )
    assert content.index('move "$dx" "$dy" click 1') < content.index("capture after-destination")
    assert "no guest hard disk" in content.lower()


def test_embedded_shell_scripts_syntax():
    for job in _workflow()["jobs"].values():
        for step in job["steps"]:
            if "run" in step:
                proc = subprocess.run(
                    ["bash", "-n"],
                    input=step["run"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                assert proc.returncode == 0, (step.get("name"), proc.stderr)
