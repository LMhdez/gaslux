"""Negative and positive synthetic GPT ownership tests for a disposable Pop VM."""

import copy
import struct
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests/tools"))
from gaslux_popos_gpt_ownership import (  # noqa: E402
    ROOT_FIRST,
    ROOT_LAST,
    GptRefusal,
    validate_delta,
)

ROOT_KIND = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
ESP_KIND = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
NTFS_KIND = uuid.UUID("e3c9e316-0b5c-4db8-817d-f92df00215ae")


def entry(kind, part_guid, first, last, name="", attrs=0):
    raw_name = name.encode("utf-16-le")
    assert len(raw_name) <= 72
    return (
        kind.bytes_le
        + part_guid.bytes_le
        + struct.pack("<QQQ", first, last, attrs)
        + raw_name.ljust(72, b"\0")
    ).hex()


def fixture_pair():
    entries = ["00" * 128 for _ in range(128)]
    entries[0] = entry(ESP_KIND, uuid.UUID(int=1), 2048, 1050623, "GASLUX-MOCK-WIN-ESP")
    entries[1] = entry(NTFS_KIND, uuid.UUID(int=2), 1050624, 2099199, "GASLUX-MOCK-WIN-NTFS")
    entries[2] = entry(ROOT_KIND, uuid.UUID(int=3), ROOT_FIRST, ROOT_LAST, "GASLUX-OWNED-ROOT")
    before = {
        "mbrSha256": "a" * 64,
        "primary": {"diskGuid": "bb" * 16, "current": 1, "entriesLba": 2},
        "backup": {"diskGuid": "bb" * 16, "current": 67108863, "entriesLba": 67108831},
        "entries": entries,
    }
    after = copy.deepcopy(before)
    after["entries"][2] = entry(ROOT_KIND, uuid.UUID(int=4), ROOT_FIRST, ROOT_LAST - 1, "")
    return before, after


def test_only_owned_root_guid_name_and_single_sector_may_change():
    before, after = fixture_pair()
    proof = validate_delta(before, after)
    assert proof["foreignEntriesByteIdentical"] is True
    assert proof["protectiveMbrIdentical"] is True
    assert proof["diskGuidAndGeometryIdentical"] is True
    assert proof["requiresPostCommitPlanRevalidation"] is True
    assert proof["productionInstallationAuthorized"] is False
    assert proof["rootEndSectorAfter"] == ROOT_LAST - 1


@pytest.mark.parametrize(
    "change",
    [
        "windows_esp",
        "windows_ntfs",
        "disk_guid",
        "mbr",
        "root_start",
        "root_end",
        "root_type",
        "root_attrs",
        "root_name",
    ],
)
def test_foreign_changes_and_unexpected_root_mutations_are_refused(change):
    before, after = fixture_pair()
    if change == "windows_esp":
        after["entries"][0] = "00" * 128
    elif change == "windows_ntfs":
        after["entries"][1] = "00" * 128
    elif change == "disk_guid":
        after["backup"]["diskGuid"] = "cd" * 16
    elif change == "mbr":
        after["mbrSha256"] = "b" * 64
    elif change == "root_start":
        after["entries"][2] = entry(ROOT_KIND, uuid.UUID(int=4), ROOT_FIRST + 1, ROOT_LAST - 1)
    elif change == "root_end":
        after["entries"][2] = entry(ROOT_KIND, uuid.UUID(int=4), ROOT_FIRST, ROOT_LAST - 2)
    elif change == "root_type":
        after["entries"][2] = entry(ESP_KIND, uuid.UUID(int=4), ROOT_FIRST, ROOT_LAST - 1)
    elif change == "root_attrs":
        after["entries"][2] = entry(ROOT_KIND, uuid.UUID(int=4), ROOT_FIRST, ROOT_LAST - 1, attrs=1)
    elif change == "root_name":
        after["entries"][2] = entry(
            ROOT_KIND, uuid.UUID(int=4), ROOT_FIRST, ROOT_LAST - 1, "FOREIGN"
        )
    with pytest.raises(GptRefusal):
        validate_delta(before, after)


def test_extra_or_missing_evidence_rejected():
    before, after = fixture_pair()
    after["unknown"] = True
    with pytest.raises(GptRefusal):
        validate_delta(before, after)
