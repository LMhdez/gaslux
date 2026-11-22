"""Adversarial Bazzite legacy ISO and Anaconda/Blivet action boundary tests.

All observations are deliberately synthetic. None prove real installer behavior.
"""

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))
from bazzite_anaconda_write_set_gate import (  # noqa: E402
    LEGACY_LAB_BYTES,
    LEGACY_LAB_SHA256,
    LEGACY_URL,
    Refusal,
    assess_legacy_media,
    compare,
    assess_signed_iso45_native_route,
    expected_actions,
)
from bazzite_atomic_destination_plan import propose  # noqa: E402
from bazzite_gpt_fixture import PARTITIONS  # noqa: E402


def proposal():
    manifest = {
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
            {
                "number": n,
                "typeGuid": t,
                "name": name,
                "firstSector": first,
                "lastSector": last,
            }
            for n, t, name, first, last in PARTITIONS
        ],
    }
    observed = {
        "diskGuid": "11111111-2222-4333-8444-555555555555",
        "sectorBytes": 512,
        "partitions": [
            {
                "number": n,
                "typeGuid": t,
                "name": name,
                "firstSector": first,
                "lastSector": last,
                "partuuid": f"0000000{n}-2222-4333-8444-555555555555",
            }
            for n, t, name, first, last in PARTITIONS
        ],
        "largestFreeFirstSector": 50980864,
        "largestFreeLastSector": 146800606,
    }
    return propose(manifest, observed)


def example_observation(plan):
    actions = expected_actions(plan)
    return {
        "schemaVersion": 1,
        "origin": "synthetic-contract-replay",
        "firmware": "uefi",
        "partitionTable": "gpt",
        "secureBootEnabled": False,
        "diskGuid": plan["diskGuid"],
        "logicalSectorBytes": 512,
        "diskSerial": "GLXBAZRO001",
        "protectedExistingPartitions": copy.deepcopy(plan["protectedExistingPartitions"]),
        "storageActions": copy.deepcopy(actions["operations"]),
        "metadataWrites": copy.deepcopy(actions["metadataWrites"]),
        "efiWrites": copy.deepcopy(actions["efiWrites"]),
        "nvramOperations": [],
        "installer": {
            "isoUrl": LEGACY_URL,
            "isoSha256": LEGACY_LAB_SHA256,
            "isoSizeBytes": LEGACY_LAB_BYTES,
            "locallyCalculatedSha256": LEGACY_LAB_SHA256,
            "independentIsoSignatureVerified": False,
            "payloadDigest": None,
            "payloadBoundToIso": False,
            "anacondaVersion": None,
            "blivetVersion": None,
        },
        "atomicDeployment": {
            "payloadInstallObserved": False,
            "deploymentUpdateVerified": False,
            "rollbackVerified": False,
        },
    }


def test_matching_synthetic_replay_is_always_non_authoritative():
    plan = proposal()
    result = compare(plan, example_observation(plan))
    assert result["syntheticActionGraphMatchesProposal"] is True
    assert result["realAnacondaActionGraphAuthenticated"] is False
    assert result["nativeInstallerWriteSetVerified"] is False
    assert result["isoIdentityDiagnostic"]["historicalChecksumIndependentlyAuthenticated"] is False
    assert result["installationAuthorized"] is False
    assert result["partitionWriteAuthorized"] is False
    assert result["windowsEspWriteAuthorized"] is False
    assert result["nvramWriteAuthorized"] is False


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("installer", "isoSha256"), "0" * 64),
        (("installer", "locallyCalculatedSha256"), "f" * 64),
        (("installer", "isoSizeBytes"), LEGACY_LAB_BYTES + 1),
        (("installer", "isoUrl"), "https://evil.invalid/fake.iso"),
        (("installer", "independentIsoSignatureVerified"), True),
        (("installer", "independentIsoSignatureVerified"), None),
        (("installer", "payloadDigest"), "sha256:" + "1" * 64),
        (("installer", "payloadBoundToIso"), True),
        (("firmware",), "bios"),
        (("partitionTable",), "mbr"),
        (("secureBootEnabled",), True),
        (("diskSerial",), "FOREIGN"),
        (("diskGuid",), "22222222-2222-4333-8444-555555555555"),
        (("logicalSectorBytes",), 4096),
        (("logicalSectorBytes",), True),
        (("origin",), "anaconda-dbus-readonly-untrusted"),
        (("origin",), "ocr-screen"),
    ],
)
def test_unsafe_media_firmware_source_and_target_are_refused(path, value):
    plan = proposal()
    observed = example_observation(plan)
    part = observed
    for key in path[:-1]:
        part = part[key]
    part[path[-1]] = value
    with pytest.raises(Refusal):
        compare(plan, observed)


def test_legacy_source_never_proves_atomic_payload_or_signature():
    record = example_observation(proposal())["installer"]
    audit = assess_legacy_media(record)
    assert audit["reportedLocalHashMatchesHistoricalPin"] is True
    assert audit["historicalChecksumIndependentlyAuthenticated"] is False
    assert audit["payloadBoundToIso"] is False
    assert audit["installationAuthorized"] is False


@pytest.mark.parametrize(
    "field",
    ("storageActions", "metadataWrites", "efiWrites", "protectedExistingPartitions"),
)
def test_missing_observation_actions_or_protected_partitions_are_refused(field):
    plan = proposal()
    observed = example_observation(plan)
    observed[field] = []
    with pytest.raises(Refusal):
        compare(plan, observed)


def test_unknown_implicit_write_or_resize_is_refused():
    plan = proposal()
    observed = example_observation(plan)
    observed["metadataWrites"].append({"kind": "gpt-primary", "firstSector": 1, "lastSector": 40})
    with pytest.raises(Refusal, match="GPT/PMBR"):
        compare(plan, observed)
    observed = example_observation(plan)
    observed["storageActions"].append({"kind": "resize", "number": 3})
    with pytest.raises(Refusal, match="storage"):
        compare(plan, observed)


def test_efi_microsoft_or_existing_windows_esp_selected_is_refused():
    plan = proposal()
    observed = example_observation(plan)
    observed["efiWrites"][0]["partitionNumber"] = 1
    with pytest.raises(Refusal, match="EFI"):
        compare(plan, observed)
    observed = example_observation(plan)
    observed["efiWrites"][0]["path"] = "/EFI/Microsoft/Boot/bootmgfw.efi"
    with pytest.raises(Refusal, match="EFI"):
        compare(plan, observed)
    observed = example_observation(plan)
    observed["storageActions"][1]["number"] = 1
    with pytest.raises(Refusal, match="storage"):
        compare(plan, observed)


def test_any_nvram_bootorder_action_is_refused():
    plan = proposal()
    observed = example_observation(plan)
    observed["nvramOperations"] = [{"kind": "boot-order", "bootId": "0001"}]
    with pytest.raises(Refusal, match="NVRAM"):
        compare(plan, observed)


def test_protected_partition_mutation_and_duplicate_actions_are_refused():
    plan = proposal()
    observed = example_observation(plan)
    observed["protectedExistingPartitions"][0]["lastSector"] += 1
    with pytest.raises(Refusal, match="protected partition"):
        compare(plan, observed)
    observed = example_observation(plan)
    observed["storageActions"][1] = copy.deepcopy(observed["storageActions"][0])
    with pytest.raises(Refusal, match="storage"):
        compare(plan, observed)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("payloadInstallObserved", True),
        ("deploymentUpdateVerified", True),
        ("rollbackVerified", True),
    ],
)
def test_no_atomic_install_update_or_rollback_can_be_claimed(key, value):
    plan = proposal()
    observed = example_observation(plan)
    observed["atomicDeployment"][key] = value
    with pytest.raises(Refusal, match="Atomic"):
        compare(plan, observed)


def test_incomplete_plan_and_unknown_fields_refused():
    plan = proposal()
    plan.pop("virtualSizeBytes")
    with pytest.raises(Refusal):
        compare(plan, example_observation(proposal()))
    plan = proposal()
    observed = example_observation(plan)
    observed["unreviewed"] = "permission"
    with pytest.raises(Refusal, match="fields"):
        compare(plan, observed)
    observed = example_observation(plan)
    observed["installer"]["unreviewed"] = "extra"
    with pytest.raises(Refusal, match="fields"):
        compare(plan, observed)


def test_no_real_capture_accepted_merely_by_claiming_dbus_origin():
    plan = proposal()
    observed = example_observation(plan)
    observed["origin"] = "anaconda-dbus-readonly-untrusted"
    with pytest.raises(Refusal, match="lacks independent"):
        compare(plan, observed)


@pytest.mark.parametrize(
    ("flag", "bad_value"),
    [
        ("windowsEspReuseProposed", True),
        ("windowsEspFormatProposed", True),
        ("nvramWriteAuthorized", True),
        ("secureBootEnrollmentAuthorized", True),
        ("stableCatalogAuthorized", True),
        ("gptHeadersAndPartitionTablesWouldChange", False),
        ("protectiveMbrWouldRequirePrePostEvidence", False),
        ("requiresRecoverySnapshotAndWindowsBootProof", False),
        ("requiresGptMetadataBackupAndPostwriteVerification", False),
        ("requiresIndependentIsoAndPayloadAttestation", False),
    ],
)
def test_proposal_security_flags_fail_closed(flag, bad_value):
    plan = proposal()
    plan[flag] = bad_value
    with pytest.raises(Refusal, match="protection gates"):
        expected_actions(plan)
    plan = proposal()
    del plan[flag]
    with pytest.raises(Refusal, match="protection gates"):
        expected_actions(plan)


@pytest.mark.parametrize(
    ("partition", "attribute", "bad_value"),
    [
        (0, "role", "windows-esp"),
        (1, "role", "unmanaged"),
        (2, "role", "windows-root"),
        (0, "lastSector", 1),
        (1, "lastSector", 1),
        (2, "lastSector", 1),
    ],
)
def test_proposal_fstype_role_size_and_free_extent_are_bound(partition, attribute, bad_value):
    plan = proposal()
    plan["candidateNewPartitions"][partition][attribute] = bad_value
    with pytest.raises(Refusal, match="candidate partition"):
        expected_actions(plan)


# The 2026-11-20 readback is a genuine prior signed-ISO CI experiment.
# Its JSON ledger is not a new signature and never grants authority.
def signed_iso45_ledger():
    import json

    return json.loads(
        (ROOT / "auto_tests" / "bazzite_official_iso_candidate_20261117.json").read_text(
            encoding="utf-8"
        )
    )


def test_signed_iso45_manual_gpt_4_6_incompatible_with_modern_installer():
    result = assess_signed_iso45_native_route(proposal(), signed_iso45_ledger())
    assert result["status"] == "REFUSED_SIGNED_ISO45_NO_VERIFIED_CUSTOM_GPT_4_6_ROUTE"
    assert result["provenanceEvidenceRun"] == 44759529218
    assert result["provenanceReverifiedInThisInvocation"] is False
    assert result["documentedModernIsoManualPartitioning"] is False
    assert result["gptPrimaryAndBackupWritesWouldBeRequired"] is True
    for field in (
        "installationAuthorized",
        "partitionWriteAuthorized",
        "gptMetadataWriteAuthorized",
        "windowsEspWriteAuthorized",
        "nvramWriteAuthorized",
        "secureBootEnrollmentAuthorized",
        "nativeInstallerWriteSetVerified",
        "realAnacondaActionsCaptured",
    ):
        assert result[field] is False


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("artifact", "sha256"), "0" * 64),
        (("artifact", "sizeBytes"), 1),
        (("artifact", "version"), "42.20250513"),
        (("artifact", "signature", "publicReadbackVerified"), False),
        (("artifact", "signature", "verifiedAgainstLocalIsoBytes"), False),
        (("artifact", "provenance", "sourceCommit"), "0" * 40),
        (("artifact", "provenance", "verifiedAgainstLocalIsoBytes"), False),
        (("payload", "digest"), "sha256:" + "0" * 64),
        (("payload", "version"), "45.20261118.1"),
        (("payload", "cosignSignatureVerifiedAgainstImmutableDigest"), False),
        (("payload", "githubAttestationVerifiedAgainstImmutableDigest"), False),
        (("relationship", "embeddedOciManifestReadBackVerified"), False),
        (("relationship", "cryptographicIsoToPayloadBindingVerified"), False),
        (("publicReadback", "workflowRunId"), 1),
        (("publicReadback", "isoCosignVerified"), False),
        (("publicReadback", "isoAttestationVerified"), False),
        (("publicReadback", "payloadCosignVerified"), False),
        (("publicReadback", "payloadAttestationVerified"), False),
        (("publicReadback", "embeddedManifestBytesVerified"), False),
        (("publicReadback", "payloadConfigBlobVerified"), False),
        (("publicReadback", "terminalRunExitCode"), 1),
        (("trust", "subjectPublicKeyInfoSha256"), "0" * 64),
        (("support", "firmware"), ["bios"]),
        (("support", "partitionTables"), ["mbr"]),
        (("support", "gasluxSupport"), "stable"),
        (("installationAuthorized",), True),
    ],
)
def test_signed_iso45_wrong_artifact_payload_signer_or_compatibility_refused(
    path, replacement
):
    ledger = signed_iso45_ledger()
    target = ledger
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    with pytest.raises(Refusal, match="ledger identity or safety"):
        assess_signed_iso45_native_route(proposal(), ledger)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("number", 3),
        ("firstSector", 2048),
        ("lastSector", 2048),
        ("filesystem", "ntfs"),
        ("mountPoint", "/boot/efi"),
    ],
)
def test_signed_iso45_rejects_modified_gpt_candidate(field, replacement):
    plan = proposal()
    plan["candidateNewPartitions"][1][field] = replacement
    with pytest.raises(Refusal):
        assess_signed_iso45_native_route(plan, signed_iso45_ledger())


def test_signed_iso45_refuses_windows_esp_and_false_gpt_immutability():
    plan = proposal()
    plan["windowsEspReuseProposed"] = True
    with pytest.raises(Refusal):
        assess_signed_iso45_native_route(plan, signed_iso45_ledger())
    plan = proposal()
    plan["gptHeadersAndPartitionTablesWouldChange"] = False
    with pytest.raises(Refusal):
        assess_signed_iso45_native_route(plan, signed_iso45_ledger())


def test_signed_iso45_absent_or_self_asserted_signature_refused():
    ledger = signed_iso45_ledger()
    del ledger["artifact"]["signature"]
    with pytest.raises(Refusal):
        assess_signed_iso45_native_route(proposal(), ledger)
    ledger = signed_iso45_ledger()
    ledger["artifact"]["signature"]["verifiedAgainstLocalIsoBytes"] = "true"
    with pytest.raises(Refusal):
        assess_signed_iso45_native_route(proposal(), ledger)
