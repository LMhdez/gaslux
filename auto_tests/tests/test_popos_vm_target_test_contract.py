"""Contract guards for the VM-only native Pop!_OS partition-stage trial."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests/tools"))
from gaslux_popos_guest_serial import TARGET_PASSED  # noqa: E402

RUNNER = ROOT / "auto_tests/tools/gaslux_candidate_live_boot.sh"
GUEST = ROOT / "auto_tests/tools/gaslux_popos_vm_target_test.sh"
WORKFLOW = ROOT / ".github/workflows/gaslux-popos-official-iso.yml"


def test_vm_disk_is_ephemeral_and_protected_windows_regions_are_hashed():
    content = RUNNER.read_text(encoding="utf-8")
    assert 'truncate -s 32G "$work/pop-target.raw"' in content
    assert "GASLUX-MOCK-WIN-ESP" in content
    assert "GASLUX-MOCK-WIN-NTFS" in content
    assert "GASLUX-OWNED-ROOT" in content
    assert "serial=GASLUXPOPTARGET" in content
    assert "target-protected.before.sha256" in content
    assert "target-protected.after.sha256" in content
    assert "target.gpt.before" in content
    assert "target.gpt.after" in content
    assert "GASLUX_POP_MOCK_WINDOWS_PARTITIONS_UNCHANGED=1" in content


def test_guest_native_agent_and_target_identity_are_fail_closed():
    content = GUEST.read_text(encoding="utf-8")
    assert "systemd-detect-virt --vm" in content
    assert "sha256sum /usr/bin/distinst" in content
    assert "virtio-GASLUXPOPTARGET" in content
    assert "blockdev --getsize64" in content
    assert "34359738368" in content
    assert "filesystem.manifest-remove" in content
    assert "--test --no-efi-vars" in content
    assert ":1:reuse:mount=/boot/efi" in content
    assert ":3:ext4:mount=/" in content
    for forbidden in ("--new-table", " --delete", " --move", " --modify-boot"):
        assert forbidden not in content
    assert TARGET_PASSED.search(b"\r\nGASLUX_POP_DISTINST_VM_TARGET_TEST_PASS=1\r\n")
    assert not TARGET_PASSED.search(
        b"printf 'GASLUX_POP_DISTINST_VM_TARGET_TEST_PASS=1'"
    )


def test_workflow_scopes_writes_to_vm_only():
    content = WORKFLOW.read_text(encoding="utf-8")
    assert "GASLUX_POP_GUEST_DISTINST_TARGET_TEST: '1'" in content
    assert "GASLUX_POP_ISO_FILE" in content
    assert "GASLUX_POP_NATIVE_DISTINST_SHA256" in content
    assert "ntfs-3g" in content
