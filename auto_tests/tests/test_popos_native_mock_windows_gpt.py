"""Fail-closed mock Windows GPT/whole-volume evidence tests."""

import copy
import struct
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests/tools"))
from gaslux_popos_native_mock_windows_gpt_reconcile import (  # noqa: E402
    ESP_TYPE,
    NTFS_TYPE,
    POP_ESP_END,
    POP_ESP_START,
    POP_ROOT_END,
    POP_ROOT_START,
    ROOT_TYPE,
    WINDOWS_ESP_END,
    WINDOWS_ESP_START,
    WINDOWS_NTFS_END,
    WINDOWS_NTFS_START,
    GptRefusal,
    reconcile_mock_windows,
)


def entry(kind, guid, first, last, name="", attrs=0):
    return (
        bytes.fromhex(kind)
        + uuid.UUID(int=guid).bytes_le
        + struct.pack("<QQQ", first, last, attrs)
        + name.encode("utf-16-le").ljust(72, b"\\x00")
    ).hex()


def fixtures():
    parts = ["00" * 128 for _ in range(128)]
    parts[:4] = [
        entry(ESP_TYPE, 1, WINDOWS_ESP_START, WINDOWS_ESP_END, "MOCK-WINDOWS-ESP"),
        entry(NTFS_TYPE, 2, WINDOWS_NTFS_START, WINDOWS_NTFS_END, "MOCK-WINDOWS-NTFS"),
        entry(ESP_TYPE, 3, POP_ESP_START, POP_ESP_END, "GASLUX-OWNED-ESP"),
        entry(ROOT_TYPE, 4, POP_ROOT_START, POP_ROOT_END, "GASLUX-OWNED-ROOT"),
    ]
    before = {
        "mbrSha256": "a" * 64,
        "primary": {"diskGuid": "ab" * 16, "current": 1},
        "backup": {"diskGuid": "ab" * 16, "current": 67108863},
        "entries": parts,
        "mockWindowsEspSha256": "b" * 64,
        "mockWindowsNtfsSha256": "c" * 64,
    }
    after = copy.deepcopy(before)
    after["entries"][3] = entry(ROOT_TYPE, 5, POP_ROOT_START, POP_ROOT_END - 1)
    return before, after


def test_mock_windows_preserved_and_root_reconciled():
    before, after = fixtures()
    result = reconcile_mock_windows(before, after)
    assert result["rootPartuuidAfter"] == str(uuid.UUID(int=5))
    assert result["mockWindowsEspBytesIdentical"]
    assert result["mockWindowsNtfsBytesIdentical"]
    assert result["mockWindowsGptEntriesIdentical"]
    assert result["productionInstallationAuthorized"] is False
    assert result["windowsDualBootProven"] is False


@pytest.mark.parametrize(
    "mutant",
    ["windows_esp_content", "windows_ntfs_content", "windows_esp_entry",
     "windows_ntfs_entry", "owned_esp_entry", "root_start", "root_end",
     "root_type", "root_attrs", "other_partition", "mbr", "disk",
     "missing_evidence", "bad_digest", "wrong_windows_type"],
)
def test_mock_windows_tampering_fails_closed(mutant):
    before, after = fixtures()
    if mutant == "windows_esp_content":
        after["mockWindowsEspSha256"] = "e" * 64
    elif mutant == "windows_ntfs_content":
        after["mockWindowsNtfsSha256"] = "d" * 64
    elif mutant == "windows_esp_entry":
        after["entries"][0] = entry(ESP_TYPE, 99, WINDOWS_ESP_START, WINDOWS_ESP_END, "MOCK-WINDOWS-ESP")
    elif mutant == "windows_ntfs_entry":
        after["entries"][1] = entry(NTFS_TYPE, 99, WINDOWS_NTFS_START, WINDOWS_NTFS_END, "MOCK-WINDOWS-NTFS")
    elif mutant == "owned_esp_entry":
        after["entries"][2] = entry(ESP_TYPE, 99, POP_ESP_START, POP_ESP_END, "GASLUX-OWNED-ESP")
    elif mutant == "root_start":
        after["entries"][3] = entry(ROOT_TYPE, 5, POP_ROOT_START + 1, POP_ROOT_END - 1)
    elif mutant == "root_end":
        after["entries"][3] = entry(ROOT_TYPE, 5, POP_ROOT_START, POP_ROOT_END - 2)
    elif mutant == "root_type":
        after["entries"][3] = entry(ESP_TYPE, 5, POP_ROOT_START, POP_ROOT_END - 1)
    elif mutant == "root_attrs":
        after["entries"][3] = entry(ROOT_TYPE, 5, POP_ROOT_START, POP_ROOT_END - 1, attrs=1)
    elif mutant == "other_partition":
        after["entries"][4] = entry(ROOT_TYPE, 6, POP_ROOT_END + 1, POP_ROOT_END + 100)
    elif mutant == "mbr":
        after["mbrSha256"] = "e" * 64
    elif mutant == "disk":
        after["primary"]["diskGuid"] = "cd" * 16
    elif mutant == "missing_evidence":
        after.pop("mockWindowsNtfsSha256")
    elif mutant == "bad_digest":
        before["mockWindowsEspSha256"] = "incorrect"
    elif mutant == "wrong_windows_type":
        after["entries"][1] = entry(ROOT_TYPE, 2, WINDOWS_NTFS_START, WINDOWS_NTFS_END, "MOCK-WINDOWS-NTFS")
    with pytest.raises(GptRefusal):
        reconcile_mock_windows(before, after)


def test_linux_only_vm_regression_unmodified():
    source = (ROOT / "auto_tests/tools/gaslux_popos_native_full_firstboot_vm.sh").read_text()
    assert "isolated-linux-only" in source
    assert "gaslux_popos_native_gpt_reconcile.py" in source


def test_mock_windows_native_install_never_selects_protected_partitions():
    guest = (ROOT / "auto_tests/tools/gaslux_popos_mock_windows_full_install_guest.sh").read_text()
    assert '--use "$disk:3:reuse:mount=/boot/efi"' in guest
    assert '--use "$disk:4:ext4:mount=/"' in guest
    assert '--use "$disk:1:' not in guest
    assert '--use "$disk:2:' not in guest
    assert "GASLUXPOPMOCKVM" in guest
    runner = (ROOT / "auto_tests/tools/gaslux_popos_native_mock_windows_firstboot_vm.sh").read_text()
    assert 'GASLUX_POP_NATIVE_MOCK_WINDOWS_VM:-0' in runner
    assert "-net none" in runner
    assert "owned-gpt-postboot.json" in runner
    assert "GASLUX_POP_MOCK_WINDOWS_PROTECTED_THROUGH_FIRSTBOOT=1" in runner
