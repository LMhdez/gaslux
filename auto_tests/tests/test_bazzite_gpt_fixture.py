"""Real GPT fixture contracts for Bazzite's isolated installer lab."""

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))

from bazzite_gpt_fixture import Refusal, audit, prepare  # noqa: E402


@pytest.mark.skipif(
    shutil.which("sgdisk") is None or shutil.which("qemu-img") is None,
    reason="gdisk and qemu-utils are required",
)
def test_real_gpt_fixture_has_only_synthetic_partition_types_and_discardable_cow(
    tmp_path,
):
    root = tmp_path / "bazzite-gpt-fixture"
    plan = prepare(root, tmp_path)
    assert plan["partitionTable"] == "gpt"
    assert plan["containsWindowsInstallation"] is False
    assert plan["containsFilesystems"] is False
    assert plan["installationAuthorized"] is False
    assert [p["typeGuid"] for p in plan["partitions"]] == [
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE",
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    ]
    assert [(p["firstSector"], p["lastSector"]) for p in plan["partitions"]] == [
        (2048, 616447),
        (616448, 649215),
        (649216, 50980863),
    ]
    result = audit(root, tmp_path, discard=True)
    assert result["gptVerified"] is True
    assert result["baseUnchanged"] is True
    assert result["overlayDiscarded"] is True
    assert (root / "windows-layout-no-os.raw").exists()
    assert not (root / "gpt-layout-scratch.qcow2").exists()


@pytest.mark.skipif(
    shutil.which("sgdisk") is None or shutil.which("qemu-img") is None,
    reason="gdisk and qemu-utils are required",
)
def test_modified_manifest_refuses_to_discard_overlay(tmp_path):
    root = tmp_path / "bazzite-gpt-fixture"
    prepare(root, tmp_path)
    path = root / "manifest.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["containsWindowsInstallation"] = True
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(Refusal, match="Untrusted"):
        audit(root, tmp_path, discard=True)
    assert (root / "gpt-layout-scratch.qcow2").exists()


@pytest.mark.skipif(
    shutil.which("sgdisk") is None or shutil.which("qemu-img") is None,
    reason="gdisk and qemu-utils are required",
)
def test_mutated_allocated_extent_refuses_overlay_discard(tmp_path):
    root = tmp_path / "bazzite-gpt-fixture"
    prepare(root, tmp_path)
    image = root / "windows-layout-no-os.raw"
    os.chmod(image, 0o644)
    with image.open("r+b") as stream:
        stream.seek(2 * 1024**3)
        stream.write(b"changed")
    os.chmod(image, 0o444)
    with pytest.raises(Refusal, match="base hash changed"):
        audit(root, tmp_path, discard=True)
    assert (root / "gpt-layout-scratch.qcow2").exists()


def test_fixture_requires_exact_private_temp_child(tmp_path):
    with pytest.raises(Refusal, match="direct child"):
        prepare(tmp_path / "foreign", tmp_path)
