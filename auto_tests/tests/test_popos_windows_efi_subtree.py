"""Synthetic tests for the lab-only shared-ESP Microsoft EFI integrity gate."""

import copy
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from gaslux_popos_gpt_ownership import GptRefusal  # noqa: E402
from gaslux_popos_windows_efi_subtree import (  # noqa: E402
    _files_in_microsoft_tree,
    _owned_image,
    verify,
)


def snapshot():
    return {
        "version": 1,
        "diskGuid": "a" * 32,
        "espPartuuid": "12345678-1234-1234-1234-123456789abc",
        "espSha256": "a" * 64,
        "windowsFiles": [
            {"path": "Boot/BCD", "size": 6, "sha256": hashlib.sha256(b"canary").hexdigest()},
            {
                "path": "Boot/bootmgfw.efi",
                "size": 8,
                "sha256": hashlib.sha256(b"mock-efi").hexdigest(),
            },
        ],
    }


def test_allow_pop_files_elsewhere_on_shared_esp_but_never_claim_boot():
    before = snapshot()
    after = copy.deepcopy(before)
    after["espSha256"] = "b" * 64
    result = verify(before, after)
    assert result == {
        "microsoftEfiFilesIdentical": True,
        "espWholePartitionBytesIdentical": False,
        "windowsDualBootProven": False,
        "productionInstallationAuthorized": False,
    }


@pytest.mark.parametrize(
    "change",
    [
        "bcd",
        "bootmgfw",
        "foreign_microsoft_file",
        "remove_bcd",
        "remove_loader",
        "disk_guid",
        "esp_guid",
        "bad_hash",
        "missing_field",
        "version",
        "non_list",
        "duplicate_file",
        "zero_size",
    ],
)
def test_windows_efi_tampering_refused(change):
    before = snapshot()
    after = copy.deepcopy(before)
    if change == "bcd":
        after["windowsFiles"][0]["sha256"] = "0" * 64
    elif change == "bootmgfw":
        after["windowsFiles"][1]["sha256"] = "0" * 64
    elif change == "foreign_microsoft_file":
        after["windowsFiles"].append({"path": "Boot/new.efi", "size": 1, "sha256": "a" * 64})
    elif change == "remove_bcd":
        after["windowsFiles"].pop(0)
    elif change == "remove_loader":
        after["windowsFiles"].pop(1)
    elif change == "disk_guid":
        after["diskGuid"] = "b" * 32
    elif change == "esp_guid":
        after["espPartuuid"] = "33333333-1234-1234-1234-123456789abc"
    elif change == "bad_hash":
        after["espSha256"] = "z"
    elif change == "missing_field":
        after.pop("espPartuuid")
    elif change == "version":
        after["version"] = 2
    elif change == "non_list":
        after["windowsFiles"] = None
    elif change == "duplicate_file":
        after["windowsFiles"].append(dict(after["windowsFiles"][0]))
    elif change == "zero_size":
        after["windowsFiles"][0]["size"] = 0
    with pytest.raises(GptRefusal):
        verify(before, after)


def test_no_real_disk_or_unowned_image(monkeypatch, tmp_path):
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GASLUX_POP_SHARED_ESP_AUDIT", "1")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    image = tmp_path / "disk.raw"
    image.write_bytes(b"not a VM")
    with pytest.raises(GptRefusal):
        _owned_image(image)


def test_windows_subtree_exact_files(tmp_path):
    root = tmp_path / "Microsoft" / "Boot"
    root.mkdir(parents=True)
    (root / "BCD").write_bytes(b"canary")
    (root / "bootmgfw.efi").write_bytes(b"mock-efi")
    files = _files_in_microsoft_tree(tmp_path)
    assert [item["path"] for item in files] == ["Boot/BCD", "Boot/bootmgfw.efi"]


def test_symlink_in_extracted_tree_refused(tmp_path):
    root = tmp_path / "Microsoft" / "Boot"
    root.mkdir(parents=True)
    (root / "BCD").write_bytes(b"canary")
    (root / "bootmgfw.efi").write_bytes(b"mock-efi")
    (root / "link").symlink_to(root / "BCD")
    with pytest.raises(GptRefusal):
        _files_in_microsoft_tree(tmp_path)
