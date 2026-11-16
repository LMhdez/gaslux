"""Protect read-only identity linkage of the official Pop!_OS distinst agent."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/gaslux-popos-official-iso.yml"


def test_native_installer_is_read_not_executed_or_installed():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "selected_squash=" in workflow
    assert 'unsquashfs -cat "$selected_squash" usr/bin/distinst' in workflow
    assert 'readelf -h "$agent"' in workflow
    assert 'sha256sum "$agent"' in workflow
    assert "native-installer-provenance.txt" in workflow
    assert "executed=false" in workflow
    assert "distinst --test" not in workflow
    assert "distinst --new-table" not in workflow
    assert "distinst --force-efi" not in workflow
    assert "distinst --modify-boot" not in workflow


def test_provenance_requires_the_same_iso_identity_as_live_os():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert 'selected_squash="$squash"' in workflow
    assert "grep -Eq '^ID=\"?pop\"?
" in workflow
    assert "grep -Eq '^VERSION_ID=\"?24.04\"?
" in workflow
    assert "printf 'isoSha256=%s\\n'" in workflow
