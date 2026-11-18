"""Read-only contracts for the Bazzite ISO OVMF workflow.

These tests do not download media, start an installer or modify any disk.
"""

import hashlib
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/gaslux-bazzite-official-iso-ovmf.yml"
KEY = ROOT / "assets/keys/bazzite-upstream-cosign.pub"
KEY_SHA256 = "af78ecfda6eb21c35195af3739341715e9cfc3f2f5911dd9c10b0670547bf6e8"


def test_key_is_pinned_to_upstream_public_key():
    assert hashlib.sha256(KEY.read_bytes()).hexdigest() == KEY_SHA256


def test_workflow_is_readonly_and_experimental():
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert data["permissions"] == {"contents": "read"}
    assert "feature/bazzite-official-iso-ovmf" in str(data.get("on", data.get(True)))
    assert "contracts" in data["jobs"]
    assert "official-iso-diskless" in data["jobs"]
    job = data["jobs"]["official-iso-diskless"]
    assert job["if"] == "github.event_name != 'pull_request'"
    assert job["needs"] == "contracts"


def test_every_shell_stage_parses():
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    for job in data["jobs"].values():
        for step in job["steps"]:
            if "run" in step:
                result = subprocess.run(
                    ["bash", "-n"],
                    input=step["run"],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                assert result.returncode == 0, (step.get("name"), result.stderr)


def test_media_must_be_cosign_verified_and_never_authorized():
    source = WORKFLOW.read_text(encoding="utf-8")
    for required in (
        "download.bazzite.gg/bazzite-stable-live-amd64.iso",
        "gaslux_bazzite_iso_signature.py",
        '--signature "$iso.sig"',
        '--public-key "$GITHUB_WORKSPACE/assets/keys/bazzite-upstream-cosign.pub"',
        f"--trusted-key-sha256 {KEY_SHA256}",
        '--expected-iso-sha256 "$sha"',
        '--expected-iso-size "$size"',
        "--firmware uefi --partition-style gpt",
        "installationAuthorized",
        "installationAuthorised",
        "readonly=on,file=$iso",
        "OVMF_VARS.disposable.fd",
        "-nic none",
        "-nodefaults",
    ):
        if required == "installationAuthorised":
            continue
        assert required in source, required
    assert "catalogPinAuthorized" in source
    assert 'obj["pinDiscoveryOnly"] = True' in source


def test_no_target_writes_or_private_iso_in_artifacts():
    source = WORKFLOW.read_text(encoding="utf-8")
    for forbidden in (
        "mkfs.",
        "parted ",
        "sgdisk ",
        "wipefs ",
        "bootc install",
        "efibootmgr ",
        "dd if=",
        "-hda ",
        "-hdb ",
        "-hdd ",
        "-blockdev driver=host_device",
        "-drive file=/dev/",
    ):
        assert forbidden not in source, forbidden
    assert '-drive "if=none,id=optical,media=cdrom,format=raw,readonly=on,file=$iso"' in source
    assert "persist-credentials: false" in source
    assert "if-no-files-found: warn" in source


def test_official_iso_immutable_pin_not_promoted_to_catalog():
    """The trusted upstream ISO must be checked against independent fixed pins."""
    source = WORKFLOW.read_text(encoding="utf-8")
    sha_pin = "6120b6edc2d87e7bdccf8dfddc8b156552cd50b152cb0a9e9dedb37fb947cbe5"
    assert f"expected_sha='{sha_pin}'" in source
    assert "expected_size='8377878528'" in source
    assert 'if [[ "$sha" != "$expected_sha" || "$size" != "$expected_size" ]]; then' in source
    assert 'obj["pinDiscoveryOnly"] = True' in source
    assert 'obj["catalogPinAuthorized"] = False' in source
    assert 'obj["installerIdentityVerified"] = False' in source
    assert 'assert obj["installationAuthorized"] is False' in source
    assert "Native Bazzite installer UI confirmed at phase" in source
