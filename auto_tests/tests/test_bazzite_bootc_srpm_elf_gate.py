"""Fail-closed tests for Fedora SRPM source/ELF/Windows ESP provenance."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))

from bazzite_bootc_srpm_elf_gate import (  # noqa: E402
    EXPECTED_BUILD_ID,
    EXPECTED_ELF_SHA256,
    EXPECTED_F45_FINGERPRINT,
    EXPECTED_GIT,
    EXPECTED_RPM,
    EXPECTED_SOURCE,
    EXPECTED_SRPM_SHA256,
    EXPECTED_TARBALL_SHA256,
    NO_ACCESS,
    Refusal,
    analyze_spec,
    assess_source_elf_binding,
    minimal_unproven_record,
)


def candidate() -> dict:
    return {
        "firmware": "uefi",
        "partitionTable": "gpt",
        "planComplete": True,
        "transactionId": "BZD-SRPM-01",
        "planTransactionId": "BZD-SRPM-01",
        "approvedDiskGuid": "33333333-4444-4555-8666-777777777777",
        "selectedDiskGuid": "33333333-4444-4555-8666-777777777777",
        "windowsEspPartuuid": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
        "linuxEspPartuuid": "11111111-2222-4333-8444-555555555555",
        "selectedEspPartuuid": "11111111-2222-4333-8444-555555555555",
        "plannedBootloader": "grub",
        "requestedBootloader": "grub",
        "replaceMode": "none",
    }


def source() -> dict:
    return {
        "sourceRpmName": EXPECTED_SOURCE,
        "rpmNevra": EXPECTED_RPM,
        "elfSha256": EXPECTED_ELF_SHA256,
        "elfBuildId": EXPECTED_BUILD_ID,
        "fedoraKeyFingerprint": EXPECTED_F45_FINGERPRINT,
        "srpmSha256": EXPECTED_SRPM_SHA256,
        "srpmSignatureVerified": True,
        "srpmPayloadVerified": True,
        "sourceTarSha256": EXPECTED_TARBALL_SHA256,
        "sourceCommit": EXPECTED_GIT,
        "sourceFilesCompared": True,
        "specPatchNames": [],
        "specPrepModificationsProvenAbsent": True,
        "reproducibleBuildVerified": True,
        "buildRecordAuthenticated": True,
        "elfRebuildSha256": EXPECTED_ELF_SHA256,
    }


def test_structural_all_true_claim_does_not_prove_source_or_authorize():
    result = assess_source_elf_binding(source(), candidate())
    assert result["decision"] == "SOURCE_ELF_UNPROVEN"
    assert result["authorization"] == "DENY_NO_WRITER"
    assert result["sourceToElfCryptographicBindingVerified"] is False
    assert result["srpmSha256"] == EXPECTED_SRPM_SHA256
    assert result["srpmSignatureVerifiedByThisModule"] is False
    assert result["espRisk"]["replaceAlongside"].startswith("DENY")
    assert all(result[key] is False for key in NO_ACCESS)


def test_default_cli_report_cannot_claim_srpm_signature():
    result = minimal_unproven_record()
    assert result["decision"] == "SOURCE_ELF_UNPROVEN"
    assert result["srpmSha256Verified"] is False
    assert result["srpmSignatureVerified"] is False
    assert all(result[key] is False for key in NO_ACCESS)


@pytest.mark.parametrize(
    ("key", "value", "reason"),
    [
        ("sourceRpmName", "bootc-1.17.1-2.fc45.src.rpm", "FOREIGN_SRPM_ELF_IDENTITY"),
        ("rpmNevra", "bootc-0:1.17.1-1.fc44.x86_64", "FOREIGN_SRPM_ELF_IDENTITY"),
        ("elfSha256", "f" * 64, "FOREIGN_SRPM_ELF_IDENTITY"),
        ("elfBuildId", "0" * 40, "FOREIGN_SRPM_ELF_IDENTITY"),
        ("fedoraKeyFingerprint", "0" * 40, "FOREIGN_SRPM_ELF_IDENTITY"),
        ("sourceCommit", "a" * 40, "FOREIGN_SRPM_ELF_IDENTITY"),
        ("srpmSha256", None, "UNPINNED_SRPM_BYTES"),
        ("srpmSha256", "A" * 64, "UNPINNED_SRPM_BYTES"),
        ("srpmSha256", "f" * 64, "FOREIGN_SRPM_SHA256"),
        ("sourceTarSha256", None, "UNPINNED_SOURCE_ARCHIVE"),
        ("sourceTarSha256", "d" * 64, "FEDORA_SOURCE_ARCHIVE_NOT_UPSTREAM_RELEASE"),
        ("specPatchNames", ["0001-unsafe-esp.patch"], "PATCHES_NOT_INDEPENDENTLY_REVIEWED"),
        ("specPatchNames", "none", "INVALID_SRPM_PATCH_INVENTORY"),
        ("reproducibleBuildVerified", 1, "INVALID_EVIDENCE_BOOLEAN"),
        ("buildRecordAuthenticated", None, "INVALID_EVIDENCE_BOOLEAN"),
        ("elfRebuildSha256", "f" * 64, "REBUILT_ELF_DIFFERS"),
        ("elfRebuildSha256", "INVALID", "INVALID_REBUILD_DIGEST"),
    ],
)
def test_foreign_srpm_elf_patch_and_metadata_denied(key, value, reason):
    record = source()
    record[key] = value
    with pytest.raises(Refusal, match=reason):
        assess_source_elf_binding(record, candidate())


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"firmware": "bios"}, "BIOS_MBR_UNSUPPORTED"),
        ({"partitionTable": "mbr"}, "BIOS_MBR_UNSUPPORTED"),
        ({"selectedEspPartuuid": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"}, "WINDOWS_ESP"),
        ({"selectedDiskGuid": "99999999-4444-4555-8666-777777777777"}, "FOREIGN_DESTINATION"),
        ({"replaceMode": "alongside"}, "DESTRUCTIVE_REPLACE"),
        ({"replaceMode": "wipe"}, "DESTRUCTIVE_REPLACE"),
        ({"transactionId": "UNRELATED"}, "FOREIGN_TRANSACTION"),
        ({"requestedBootloader": "systemd-boot"}, "UNPLANNED_BOOTLOADER"),
        ({"planComplete": False}, "PARTIAL_PLAN"),
    ],
)
def test_real_candidate_prewrite_gate_recused_before_source_claim(change, reason):
    plan = candidate()
    plan.update(change)
    with pytest.raises(Refusal, match=reason):
        assess_source_elf_binding(source(), plan)


def test_missing_fields_and_extra_provenance_never_promote():
    data = source()
    data.pop("srpmSignatureVerified")
    with pytest.raises(Refusal, match="INCOMPLETE_SRPM_ELF_EVIDENCE"):
        assess_source_elf_binding(data, candidate())
    data = source()
    data["installationAuthorized"] = True
    with pytest.raises(Refusal, match="INCOMPLETE_SRPM_ELF_EVIDENCE"):
        assess_source_elf_binding(data, candidate())


def test_spec_requires_exact_nvr_and_patch_review():
    template = (
        "Name: bootc\nVersion: 1.17.1\nRelease: 1%{?dist}\n%prep\n%autosetup -p1 -a1\n%build\n"
    )
    result = analyze_spec(template)
    assert result["patchesDeclared"] == []
    fedora_packit = template.replace("Release: 1%{?dist}", "Release: %{autorelease}")
    assert analyze_spec(fedora_packit)["requiresPatchReview"] is False
    assert result["specAloneProvesNoSourceMutations"] is False
    result = analyze_spec(template + "Patch0: 0001-delete-windows-efi.patch\n")
    assert result["requiresPatchReview"]
    assert result["patchesDeclared"] == ["0001-delete-windows-efi.patch"]
    for spec in (
        template.replace("Version: 1.17.1", "Version: 1.17.2"),
        template.replace("Name: bootc", "Name: other"),
        template.replace("%prep", "%post"),
        template.replace("Release: 1%{?dist}", "Release: 2%{?dist}"),
        "",
    ):
        with pytest.raises(Refusal):
            analyze_spec(spec)


def test_input_copy_does_not_change_original_and_never_claims_replay():
    original = source()
    changed = copy.deepcopy(original)
    changed["sourceTarSha256"] = EXPECTED_TARBALL_SHA256
    assert assess_source_elf_binding(changed, candidate())["decision"] == "SOURCE_ELF_UNPROVEN"
    assert original == changed
