"""No ISO download, disk mutation or implicit trust in the legacy metadata scout."""

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github/workflows/gaslux-bazzite-legacy-iso-scout.yml"


def test_no_iso_download_or_guest_mutation_in_workflow():
    content = WF.read_text(encoding="utf-8")
    workflow = yaml.safe_load(content)
    assert workflow["permissions"] == {"contents": "read"}
    assert "feature/bazzite-legacy-iso-scout-20261118" in str(
        workflow.get("on", workflow.get(True))
    )
    jobs = workflow["jobs"]
    assert jobs["legacy-cdn-discovery"]["needs"] == "contracts"
    for term in (
        "qemu-system", "qemu-img create", "losetup ", "mkfs.", "parted ",
        "sgdisk ", "wipefs ", "bootc install", "efibootmgr ", "bcdedit ",
        "dd if=", "windows10.qcow2", "windows11.qcow2",
        "curl --get", "curl -o iso", "installationAuthorized=true",
    ):
        assert term not in content, term
    assert "curl --head" in content
    assert "--max-filesize 4096" in content
    assert "bazzite-stable-amd64.iso" in content
    assert "bazzite-stable-live-amd64.iso" not in content
    assert "always()" in content


def test_all_shell_steps_parse():
    workflow = yaml.safe_load(WF.read_text(encoding="utf-8"))
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if "run" in step:
                result = subprocess.run(
                    ["bash", "-n"], input=step["run"], capture_output=True,
                    text=True, check=False
                )
                assert result.returncode == 0, (step.get("name"), result.stderr)
