"""Safety contracts for private Bazzite lab QCOW2 target (never real disks)."""

import json
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))

from bazzite_owned_qcow2 import LabRefusal, SIZE_GIB, audit, prepare  # noqa: E402


def test_requires_exact_private_temp_child(tmp_path):
    with pytest.raises(LabRefusal, match="direct child"):
        prepare(tmp_path / "foreign-target", tmp_path)
    with pytest.raises(LabRefusal, match="direct child"):
        prepare(tmp_path.parent / "bazzite-owned-qcow2", tmp_path)


def test_rejects_reused_or_symlink_directory(tmp_path):
    root = tmp_path / "bazzite-owned-qcow2"
    root.mkdir()
    with pytest.raises(LabRefusal, match="reuse"):
        prepare(root, tmp_path)
    root.rmdir()
    root.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(LabRefusal, match="Symlink"):
        prepare(root, tmp_path)


@pytest.mark.skipif(shutil.which("qemu-img") is None, reason="qemu-img not installed")
def test_real_qemu_backing_chain_is_immutable_and_discardable(tmp_path):
    root = tmp_path / "bazzite-owned-qcow2"
    plan = prepare(root, tmp_path)
    assert plan["guestDiskCount"] == 1
    assert plan["virtualSizeBytes"] == SIZE_GIB * 1024**3
    assert plan["storageInspectionOnly"] is True
    assert plan["installationAuthorized"] is False
    assert plan["windowsGuestAttached"] is False
    assert (root / "blank-base.qcow2").stat().st_mode & 0o222 == 0
    assert audit(root, tmp_path, discard=False)["blankBackingUnchanged"]
    result = audit(root, tmp_path, discard=True)
    assert result["overlayDiscarded"] is True
    assert result["windowsDualBootVerified"] is False
    assert (root / "blank-base.qcow2").exists()
    assert not (root / "scratch-overlay.qcow2").exists()


@pytest.mark.skipif(shutil.which("qemu-img") is None, reason="qemu-img not installed")
def test_changed_disk_plan_refused_before_any_discard(tmp_path):
    root = tmp_path / "bazzite-owned-qcow2"
    prepare(root, tmp_path)
    path = root / "manifest.json"
    data = json.loads(path.read_text())
    data["windowsGuestAttached"] = True
    path.write_text(json.dumps(data))
    with pytest.raises(LabRefusal, match="Untrusted"):
        audit(root, tmp_path, discard=True)
    assert (root / "scratch-overlay.qcow2").exists()


@pytest.mark.skipif(shutil.which("qemu-img") is None, reason="qemu-img not installed")
def test_replaced_overlay_symlink_refused_without_deleting_foreign_file(tmp_path):
    root = tmp_path / "bazzite-owned-qcow2"
    prepare(root, tmp_path)
    overlay = root / "scratch-overlay.qcow2"
    overlay.unlink()
    foreign = tmp_path / "foreign.qcow2"
    foreign.write_bytes(b"foreign-owned")
    overlay.symlink_to(foreign)
    with pytest.raises(LabRefusal, match="Symlink"):
        audit(root, tmp_path, discard=True)
    assert foreign.read_bytes() == b"foreign-owned"


@pytest.mark.skipif(shutil.which("qemu-img") is None, reason="qemu-img not installed")
def test_mutated_base_refused_and_overlay_kept(tmp_path):
    root = tmp_path / "bazzite-owned-qcow2"
    prepare(root, tmp_path)
    backing = root / "blank-base.qcow2"
    os.chmod(backing, stat.S_IRUSR | stat.S_IWUSR)
    with pytest.raises(LabRefusal, match="read-only"):
        audit(root, tmp_path, discard=True)
    assert (root / "scratch-overlay.qcow2").exists()
