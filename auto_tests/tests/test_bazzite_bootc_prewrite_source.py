"""Negative contracts for pinned bootc v1.17.1 Rust source review, no native install."""

from __future__ import annotations

import copy
import hashlib
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))

from bazzite_bootc_prewrite_source import (  # noqa: E402
    NO_AUTHORITY,
    Refusal,
    _read_source,
    _require_fragments,
    assess_candidate,
    git_blob_id,
)

WINDOWS = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
LINUX_ESP = "11111111-2222-4333-8444-555555555555"
DISK = "33333333-4444-4555-8666-777777777777"


def candidate():
    return {
        "firmware": "uefi",
        "partitionTable": "gpt",
        "planComplete": True,
        "transactionId": "BZD-PREWRITE-TEST-01",
        "planTransactionId": "BZD-PREWRITE-TEST-01",
        "approvedDiskGuid": DISK,
        "selectedDiskGuid": DISK,
        "windowsEspPartuuid": WINDOWS,
        "linuxEspPartuuid": LINUX_ESP,
        "selectedEspPartuuid": LINUX_ESP,
        "plannedBootloader": "grub",
        "requestedBootloader": "grub",
        "replaceMode": "none",
    }


def test_structurally_coherent_claim_still_never_authorizes():
    report = assess_candidate(candidate())
    assert report["decision"] == "PREWRITE_UNPROVEN"
    assert report["destinationIdentityAuthenticated"] is False
    assert report["espContentsAndBootloaderWriteSetVerified"] is False
    assert all(report[key] is False for key in NO_AUTHORITY)


@pytest.mark.parametrize(
    ("field", "changed", "reason"),
    [
        ("selectedEspPartuuid", WINDOWS, "WINDOWS_ESP_OR_FOREIGN_ESP_SELECTED"),
        ("selectedEspPartuuid", DISK, "WINDOWS_ESP_OR_FOREIGN_ESP_SELECTED"),
        ("selectedDiskGuid", LINUX_ESP, "FOREIGN_DESTINATION"),
        ("requestedBootloader", "systemd-boot", "UNPLANNED_BOOTLOADER"),
        ("requestedBootloader", "grub-bios", "UNPLANNED_BOOTLOADER"),
        ("firmware", "bios", "BIOS_MBR_UNSUPPORTED"),
        ("partitionTable", "mbr", "BIOS_MBR_UNSUPPORTED"),
        ("planTransactionId", "other-transaction", "FOREIGN_TRANSACTION"),
        ("transactionId", "", "FOREIGN_TRANSACTION"),
        ("planComplete", False, "PARTIAL_PLAN"),
        ("planComplete", 1, "PARTIAL_PLAN"),
        ("replaceMode", "alongside", "DESTRUCTIVE_REPLACE_MODE_REFUSED"),
        ("replaceMode", "wipe", "DESTRUCTIVE_REPLACE_MODE_REFUSED"),
        ("approvedDiskGuid", "bad", "INVALID_DISK_OR_PARTITION_GUID"),
        ("selectedEspPartuuid", None, "INVALID_DISK_OR_PARTITION_GUID"),
    ],
)
def test_prewrite_plan_fail_closed(field, changed, reason):
    value = candidate()
    value[field] = changed
    with pytest.raises(Refusal, match=reason):
        assess_candidate(value)


@pytest.mark.parametrize("field", ("firmware", "selectedDiskGuid", "planTransactionId"))
def test_missing_required_plan_fields_denied(field):
    value = candidate()
    del value[field]
    with pytest.raises(Refusal, match="PARTIAL_OR_UNKNOWN_PLAN"):
        assess_candidate(value)


def test_unexpected_writer_or_claimed_evidence_not_accepted():
    value = candidate()
    value["installationAuthorized"] = True
    with pytest.raises(Refusal, match="PARTIAL_OR_UNKNOWN_PLAN"):
        assess_candidate(value)


def test_partial_no_plan_and_ambiguous_guids_rejected():
    for invalid in (None, {}, [], "x", True):
        with pytest.raises(Refusal):
            assess_candidate(invalid)
    same_esp = candidate()
    same_esp["linuxEspPartuuid"] = WINDOWS
    with pytest.raises(Refusal, match="WINDOWS_ESP"):
        assess_candidate(same_esp)


def test_git_blob_framing_uses_nul_not_literal_backslash_zero():
    content = b"actual upstream pinned source bytes"
    expected = hashlib.sha1(
        b"blob 35\0" + content, usedforsecurity=False
    ).hexdigest()
    assert len(content) == 35
    assert git_blob_id(content) == expected


def test_reader_refuses_modified_git_blob(tmp_path):
    path = tmp_path / "install.rs"
    path.write_bytes(b"first")
    expected = git_blob_id(b"first")
    with pytest.raises(Refusal, match="BLOB_MISMATCH"):
        _read_source(path, git_blob_id(b"other"))
    content, measurement = _read_source(path, expected)
    assert content == "first"
    assert measurement["gitBlob"] == expected
    assert measurement["sha256"] == hashlib.sha256(b"first").hexdigest()


def test_reader_refuses_symlink_and_hardlink(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"real")
    alias = tmp_path / "alias"
    alias.symlink_to(source)
    with pytest.raises((Refusal, OSError)):
        _read_source(alias, git_blob_id(b"real"))

    hardlink = tmp_path / "hard"
    os.link(source, hardlink)
    with pytest.raises(Refusal, match="FOREIGN_OR_UNBOUNDED"):
        _read_source(source, git_blob_id(b"real"))


def test_reader_refuses_unbounded_and_empty_sources(tmp_path):
    path = tmp_path / "source"
    for data in (b"", b"x" * (512 * 1024 + 1)):
        path.write_bytes(data)
        with pytest.raises(Refusal, match="FOREIGN_OR_UNBOUNDED"):
            _read_source(path, git_blob_id(data))


def test_dangerous_upstream_call_chain_anchor_must_remain():
    actual = (
        'fn clean_esp_bootloader_dirs(efidir: &Dir) {'
        'for name in ["EFI", "loader"] {'
        'remove_dir_no_xdev(efidir, name, false);'
        '} }'
    )
    _require_fragments(
        actual,
        ('fn clean_esp_bootloader_dirs(', 'for name in ["EFI", "loader"]', "remove_dir_no_xdev("),
        "ESP",
    )
    replaced = actual.replace('["EFI", "loader"]', '["EFI/BOOT"]')
    with pytest.raises(Refusal, match="CONTROL_FLOW_ESP"):
        _require_fragments(replaced, ('for name in ["EFI", "loader"]',), "ESP")


def test_candidate_result_does_not_self_promote_after_mutation():
    value = copy.deepcopy(candidate())
    first = assess_candidate(value)
    value["plannedBootloader"] = "systemd-boot"
    with pytest.raises(Refusal, match="UNPLANNED_BOOTLOADER"):
        assess_candidate(value)
    assert all(first[key] is False for key in NO_AUTHORITY)
