"""Fail-closed Bazzite Atomic target proposal; no install authorization."""

import copy
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))
from bazzite_atomic_destination_plan import inspect, propose  # noqa: E402
from bazzite_gpt_fixture import PARTITIONS, Refusal, audit, prepare  # noqa: E402


def fixture_manifest():
    return {
        "labOnly": True,
        "firmware": "uefi",
        "partitionTable": "gpt",
        "fixtureOnly": True,
        "containsWindowsInstallation": False,
        "containsFilesystems": False,
        "storageInspectionOnly": True,
        "installationAuthorized": False,
        "virtualSizeBytes": 70 * 1024**3,
        "partitions": [
            {"number": n, "typeGuid": guid, "name": name, "firstSector": first, "lastSector": last}
            for n, guid, name, first, last in PARTITIONS
        ],
    }


def snapshot():
    return {
        "diskGuid": "11111111-2222-4333-8444-555555555555",
        "sectorBytes": 512,
        "partitions": [
            {
                "number": n,
                "typeGuid": guid,
                "name": name,
                "firstSector": first,
                "lastSector": last,
                "partuuid": f"0000000{n}-2222-4333-8444-555555555555",
            }
            for n, guid, name, first, last in PARTITIONS
        ],
        "largestFreeFirstSector": 50980864,
        "largestFreeLastSector": 146800606,
    }


def test_owned_future_partition_plan_never_grants_write_or_esp_access():
    plan = propose(fixture_manifest(), snapshot())
    assert [p["number"] for p in plan["candidateNewPartitions"]] == [4, 5, 6]
    assert [(p["filesystem"], p["mountPoint"]) for p in plan["candidateNewPartitions"]] == [
        ("vfat", "/boot/efi"),
        ("ext4", "/boot"),
        ("btrfs", "/"),
    ]
    assert plan["btrfsSubvolumesProposed"] == ["/", "/var", "/var/home"]
    assert plan["windowsEspReuseProposed"] is False
    assert plan["windowsEspFormatProposed"] is False
    assert plan["gptHeadersAndPartitionTablesWouldChange"] is True
    assert plan["requiresAnacondaBlivetExactActionDiff"] is True
    assert plan["nativeInstallerWriteSetObserved"] is False
    assert plan["legacyIso42IndependentSignatureVerified"] is False
    assert all(
        plan[k] is False
        for k in (
            "installationAuthorized",
            "partitionWriteAuthorized",
            "gptMetadataWriteAuthorized",
            "windowsEspWriteAuthorized",
            "nvramWriteAuthorized",
            "secureBootEnrollmentAuthorized",
            "stableCatalogAuthorized",
        )
    )
    existing_end = PARTITIONS[-1][4]
    for part in plan["candidateNewPartitions"]:
        assert existing_end < part["firstSector"] <= part["lastSector"]
        existing_end = part["lastSector"]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("firmware", "bios"),
        ("partitionTable", "mbr"),
        ("containsWindowsInstallation", True),
        ("containsFilesystems", True),
        ("installationAuthorized", True),
        ("labOnly", False),
        ("fixtureOnly", False),
        ("storageInspectionOnly", False),
    ],
)
def test_refuses_every_non_disposable_or_non_uefi_gpt_configuration(key, value):
    manifest = fixture_manifest()
    manifest[key] = value
    with pytest.raises(Refusal, match="synthetic"):
        propose(manifest, snapshot())


def test_protects_existing_partitions_and_partuuid_identity():
    for field, bad in (
        ("firstSector", 2049),
        ("lastSector", 616446),
        ("typeGuid", "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"),
        ("name", "WINDOWS-RECOVERY"),
        ("partuuid", "00000000-0000-0000-0000-000000000000"),
    ):
        data = snapshot()
        data["partitions"][0][field] = bad
        with pytest.raises(Refusal):
            propose(fixture_manifest(), data)


def test_refuses_extra_partition_and_mismatched_manifest():
    data = snapshot()
    data["partitions"].append(copy.deepcopy(data["partitions"][-1]))
    with pytest.raises(Refusal, match="count"):
        propose(fixture_manifest(), data)
    manifest = fixture_manifest()
    manifest["partitions"][2]["name"] = "FOREIGN"
    with pytest.raises(Refusal, match="Protected"):
        propose(manifest, snapshot())


def test_refuses_duplicate_guids_and_bad_sector_geometry():
    for data in (
        {**snapshot(), "diskGuid": snapshot()["partitions"][0]["partuuid"]},
        {**snapshot(), "sectorBytes": 4096},
        {**snapshot(), "largestFreeFirstSector": 649216},
        {**snapshot(), "largestFreeLastSector": 146800639},
        {**snapshot(), "largestFreeLastSector": 60000000},
    ):
        with pytest.raises(Refusal):
            propose(fixture_manifest(), data)


def test_windows_real_disk_or_foreign_target_never_accepted():
    manifest = fixture_manifest()
    manifest["containsWindowsInstallation"] = True
    with pytest.raises(Refusal):
        propose(manifest, snapshot())
    data = snapshot()
    data["partitions"][2]["lastSector"] = 120000000
    with pytest.raises(Refusal):
        propose(fixture_manifest(), data)


def test_malformed_gpt_evidence_fails_closed():
    for data in (None, {}, {"diskGuid": "forged"}, {"sectorBytes": True}):
        with pytest.raises(Refusal):
            propose(fixture_manifest(), data)


@pytest.mark.skipif(
    shutil.which("sgdisk") is None or shutil.which("qemu-img") is None,
    reason="Requires real sgdisk and qemu-img from disposable GitHub runner",
)
def test_real_gpt_readonly_proposal_and_immutable_backing(tmp_path):
    root = tmp_path / "bazzite-gpt-fixture"
    prepare(root, tmp_path)
    output = inspect(root, tmp_path)
    assert len(output["protectedExistingPartitions"]) == 3
    assert output["protectedExistingPartitions"][0]["partuuid"]
    assert output["diskGuid"]
    assert output["installationAuthorized"] is False
    assert output["partitionWriteAuthorized"] is False
    assert output["candidateNewPartitions"][-1]["lastSector"] < 70 * 1024**3 // 512 - 33
    assert json.loads(json.dumps(output)) == output
    proof = audit(root, tmp_path, discard=True)
    assert proof["baseUnchanged"] is True
    assert proof["overlayDiscarded"] is True
