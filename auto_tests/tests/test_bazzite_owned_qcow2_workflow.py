"""Fail-closed contracts for Bazzite first blank-QCOW2 storage discovery.

These tests never boot a VM or mutate any Windows disk.
"""

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github/workflows/gaslux-bazzite-owned-qcow2.yml"


def _workflow():
    return yaml.safe_load(WF.read_text(encoding="utf-8"))


def test_permissions_and_vm_only_on_branch_push():
    wf = _workflow()
    assert wf["permissions"] == {"contents": "read"}
    jobs = wf["jobs"]
    assert "contracts" in jobs
    assert "owned-qcow2-storage-discovery" in jobs
    assert jobs["owned-qcow2-storage-discovery"]["needs"] == "contracts"
    assert jobs["owned-qcow2-storage-discovery"]["if"] == "github.event_name != 'pull_request'"
    assert jobs["owned-qcow2-storage-discovery"]["runs-on"] == "ubuntu-24.04"
    assert "feature/bazzite-owned-qcow2-storage-discovery" in str(wf.get("on", wf.get(True)))


def test_signed_real_iso_is_always_verified_before_guest_disk_is_attached():
    wf = _workflow()
    job = wf["jobs"]["owned-qcow2-storage-discovery"]
    names = [step.get("name", "") for step in job["steps"]]
    signed = next(i for i, name in enumerate(names) if "detached upstream signature" in name)
    prepared = next(i for i, name in enumerate(names) if "Prepare newly created" in name)
    guest = next(i for i, name in enumerate(names) if "Boot official ISO" in name)
    discard = next(i for i, name in enumerate(names) if "discard COW" in name)
    assert signed < prepared < guest < discard
    assert job["steps"][discard]["if"] == "always()"
    source = WF.read_text(encoding="utf-8")
    assert "6120b6edc2d87e7bdccf8dfddc8b156552cd50b152cb0a9e9dedb37fb947cbe5" in source
    assert "8377878528" in source
    assert "af78ecfda6eb21c35195af3739341715e9cfc3f2f5911dd9c10b0670547bf6e8" in source
    assert "gaslux_bazzite_iso_signature.py" in source


def test_only_one_blank_private_qcow2_and_no_windows_image_or_disk_writers():
    source = WF.read_text(encoding="utf-8")
    assert "bazzite_owned_qcow2.py prepare" in source
    assert "bazzite_owned_qcow2.py discard" in source
    assert source.count('-device "virtio-blk-pci,drive=owned-target,serial=$serial"') == 1
    assert source.count("id=owned-target,format=qcow2,file=$owned/scratch-overlay.qcow2") == 1
    assert "readonly=on,file=$iso" in source
    assert "-nic none" in source
    assert "-nodefaults" in source
    assert 'assert plan["windowsGuestAttached"] is False' in source
    assert 'assert plan["installationAuthorized"] is False' in source
    for forbidden in (
        "mkfs.",
        "parted ",
        "sgdisk ",
        "wipefs ",
        "bootc install",
        "efibootmgr ",
        "bcdedit ",
        "dd if=",
        "-hda ",
        "-hdb ",
        "-drive file=/dev/",
        "driver=host_device",
        "windows10.qcow2",
        "windows11.qcow2",
        "qemu-img commit",
        "qemu-img rebase",
    ):
        assert forbidden not in source, forbidden


def test_scripted_input_stops_at_storage_page_before_install_review():
    source = WF.read_text(encoding="utf-8")
    assert "elif (( phase == 5 )); then" in source
    assert "Storage page OBSERVED." in source
    assert "no disk selection or install" in source.lower()
    assert "Welcome. Let's install Bazzite now." in source
    assert "Expected Virtio target not displayed" in source
    assert "Ambiguous installer disk count" in source
    assert "Guest target size mismatch for 70 GiB QCOW2" in source
    assert "75.2 GB disk" in source
    assert "Use entire disk" in source
    assert "Storage page not confirmed" in source
    assert source.count("move 407 712 click 1") == 3
    assert "phase in 1 2 3 4 5" in source
    assert "persist-credentials: false" in source


def test_all_bash_runs_pass_syntax():
    for job in _workflow()["jobs"].values():
        for step in job["steps"]:
            if "run" not in step:
                continue
            parsed = subprocess.run(
                ["bash", "-n"],
                input=step["run"],
                text=True,
                capture_output=True,
                check=False,
            )
            assert parsed.returncode == 0, (step.get("name"), parsed.stderr)
