"""Read-only contracts for pinned Bazzite legacy ISO bytes workflow."""

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github/workflows/gaslux-bazzite-legacy-pinned-media.yml"


def test_workflow_is_isolated_and_never_grants_install():
    content = WF.read_text(encoding="utf-8")
    wf = yaml.safe_load(content)
    assert wf["permissions"] == {"contents": "read", "attestations": "read"}
    assert "feature/bazzite-legacy-iso-scout-20261118" in str(wf.get("on", wf.get(True)))
    assert wf["jobs"]["pinned-media-bytes"]["needs"] == "contracts"
    assert wf["jobs"]["pinned-media-bytes"]["if"] == "github.event_name != 'pull_request'"
    assert "9c8d06cd8e57f2274678edeb14b4b13a79b8117c70571a65199919a66305b5c7" in content
    assert "7907770368" in content
    assert "https://download.bazzite.gg/bazzite-stable-amd64.iso" in content
    assert "sha256sum" in content
    assert "xorriso -indev" in content
    assert "gh attestation verify" in content
    assert '"installationAuthorized": False' in content
    assert '"windowsEspWriteAuthorized": False' in content
    assert '"catalogPinAuthorized": False' in content
    for forbidden in (
        "qemu-system",
        "qemu-img create",
        "mkfs.",
        "wipefs ",
        "sgdisk ",
        "parted ",
        "efibootmgr ",
        "bcdedit ",
        "/dev/sda",
        "windows10.qcow2",
        "windows11.qcow2",
        "bootc install",
        "rpm-ostree deploy",
        "cosign sign",
        "git push",
        "release-config.json",
    ):
        assert forbidden not in content, forbidden


def test_ordering_sha_before_read_only_iso_inspection():
    job = yaml.safe_load(WF.read_text(encoding="utf-8"))["jobs"]["pinned-media-bytes"]
    names = [step.get("name", "") for step in job["steps"]]
    assert names.index("Verify the historical official CDN metadata still matches the lab pin") < (
        names.index("Download exact candidate bytes and verify pinned SHA-256 (no execution)")
    )
    assert job["steps"][-1]["if"] == "always()"


def test_bash_steps_are_valid():
    wf = yaml.safe_load(WF.read_text(encoding="utf-8"))
    for job in wf["jobs"].values():
        for step in job["steps"]:
            if "run" in step:
                result = subprocess.run(
                    ["bash", "-n"], input=step["run"], capture_output=True, text=True, check=False
                )
                assert result.returncode == 0, (step.get("name"), result.stderr)
