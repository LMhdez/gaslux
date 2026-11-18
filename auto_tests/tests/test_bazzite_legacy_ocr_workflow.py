"""Safe read-only follow-up for existing diskless Bazzite Actions screenshot evidence."""

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github/workflows/gaslux-bazzite-legacy-ocr-audit.yml"


def test_source_run_is_pinned_and_no_new_iso_or_vm():
    source = WF.read_text(encoding="utf-8")
    workflow = yaml.safe_load(source)
    assert workflow["permissions"] == {"contents": "read", "actions": "read"}
    assert "feature/bazzite-legacy-iso-scout-20261118" in str(
        workflow.get("on", workflow.get(True))
    )
    assert "44364282815" in source
    assert "44255598cb88c6a93d7beae58fc6a4aa28622d36" in source
    assert ".head_repository.full_name" in source
    assert '.conclusion == "success"' in source
    assert "gh run download" in source
    assert "auto_tests/bazzite_legacy_ocr_audit.py" in source
    for forbidden in (
        "curl ",
        "qemu-system",
        "qemu-img",
        "mkfs.",
        "sgdisk ",
        "parted ",
        "efibootmgr ",
        "bcdedit ",
        "bootc install",
        "release-config.json",
        "/dev/sd",
        "dd if=",
    ):
        assert forbidden not in source


def test_embedded_shell_scripts_parse():
    workflow = yaml.safe_load(WF.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["independent-ocr-review"]["steps"]
    for step in steps:
        if "run" in step:
            result = subprocess.run(
                ["bash", "-n"],
                input=step["run"],
                text=True,
                capture_output=True,
                check=False,
            )
            assert result.returncode == 0, (step.get("name"), result.stderr)
