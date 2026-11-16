"""Negative tests for Pop native CLI execution in a disposable, isolated QEMU guest."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests/tools"))
from gaslux_popos_guest_serial import (  # noqa: E402
    FAILED,
    LOGIN,
    PASSED,
    PASSWORD,
    READY,
    SHA,
    normalized,
)

RUNNER = ROOT / "auto_tests/tools/gaslux_candidate_live_boot.sh"
GUEST = ROOT / "auto_tests/tools/gaslux_popos_vm_guest_probe.sh"
WORKFLOW = ROOT / ".github/workflows/gaslux-popos-official-iso.yml"


def test_serial_proof_rejects_echoes_and_wrong_hash():
    assert LOGIN.search(b"\r\npop-os login: ")
    assert PASSWORD.search(b"\nPassword: ")
    assert not PASSWORD.search(b"printf 'Password:'")
    assert READY.search(b"\nGASLUX_POP_LIVE_SHELL_READY\n")
    assert not READY.search(b"printf 'GASLUX_POP_LIVE_SHELL_READY\\n'")
    assert PASSED.search(b"\nGASLUX_POP_DISTINST_GUEST_READONLY_PASS=1\r\n")
    assert not PASSED.search(b"printf 'GASLUX_POP_DISTINST_GUEST_READONLY_PASS=1'")
    assert FAILED.search(b"GASLUX_POP_GUEST_DISTINST_FAILURE: no agent")
    assert normalized(b"\x1b[31mhello\r\n") == b"hello\n"
    assert SHA.fullmatch("a" * 64)
    assert not SHA.fullmatch("a" * 63 + ";")


def test_guest_probe_is_read_only_and_checks_identity():
    content = GUEST.read_text(encoding="utf-8")
    assert "systemd-detect-virt --vm" in content
    assert 'ID:-}" == pop' in content
    assert 'VERSION_ID:-}" == 24.04' in content
    assert "sha256sum /usr/bin/distinst" in content
    assert "findmnt" in content
    assert "vfat" in content
    assert "grep -qx ro" in content
    assert "/usr/bin/distinst --help" in content
    for forbidden in ("--new-table", "--modify-boot", " --delete", " --move", "mkfs.", "sgdisk "):
        assert forbidden not in content


def test_guest_script_source_is_pinned_and_no_physical_target_attached():
    runner = RUNNER.read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "GASLUX_POP_GUEST_DISTINST_PROBE" in runner
    assert 'mcopy -i "$work/efi-part.img"' in runner
    assert "gaslux_popos_guest_serial.py" in runner
    assert "GASLUX_POP_NATIVE_DISTINST_SHA256" in workflow
    assert re.search(r"readonly=on,format=raw,file=\$iso", runner)
    assert '" -net none"' not in runner
    assert "-net none" in runner
    assert "GASLUX_POP_NATIVE_DISTINST_SHA256" in runner
