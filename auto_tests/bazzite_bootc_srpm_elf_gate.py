#!/usr/bin/env python3
"""Fedora bootc SRPM/ELF provenance and Windows ESP *deny-only* boundary.

Source names, signed package metadata and matching Rust paths cannot prove
a reproducible source-to-ELF relationship or bootloader preservation.  This
module never launches rpm, bootc, a guest or any storage writer.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from bazzite_bootc_prewrite_source import NO_AUTHORITY, Refusal, assess_candidate

EXPECTED_SOURCE = "bootc-1.17.1-1.fc45.src.rpm"
# Measured from official Koji SRPM bytes in exact-head read-only Actions #45038284594.
# A pin is identity, not independent publisher authentication.
EXPECTED_SRPM_SHA256 = "0e037cb10ba17bc3f06af3e7a3ae56ebc096673533bf5803f6571ae89ee77e32"
EXPECTED_RPM = "bootc-0:1.17.1-1.fc45.x86_64"
EXPECTED_ELF_SHA256 = "f8944e5431de613133aa56bd7ac623dcf223f40ec3745a8c87b9cdcff4956e08"
EXPECTED_BUILD_ID = "b6de95c7102a4d12325589251e67353b9e4f936c"
EXPECTED_F45_FINGERPRINT = "4f50a6114cd5c6976a7f1179655a4b02f577861e"
EXPECTED_GIT = "d01e723ae9480fa53aa9db09a7eff0439548e9f6"
EXPECTED_TARBALL_SHA256 = "8d06b7b20e6a3fe862275f089a2ac5275ff91151de2e3f0ef090a426292ab3dd"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REQUIRED_EVIDENCE = frozenset(
    {
        "sourceRpmName",
        "rpmNevra",
        "elfSha256",
        "elfBuildId",
        "fedoraKeyFingerprint",
        "srpmSha256",
        "srpmSignatureVerified",
        "srpmPayloadVerified",
        "sourceTarSha256",
        "sourceCommit",
        "sourceFilesCompared",
        "specPatchNames",
        "specPrepModificationsProvenAbsent",
        "reproducibleBuildVerified",
        "buildRecordAuthenticated",
        "elfRebuildSha256",
    }
)
# Every path below stays denied regardless of metadata or caller-supplied flags.
NO_ACCESS = NO_AUTHORITY + (
    "secureBootEnrollmentAuthorized",
    "windowsEspPreservationVerified",
    "bootloaderAndNVRAMWriteSetVerified",
    "sourceToElfCryptographicBindingVerified",
)


def _hex(value: object, length: int) -> bool:
    if type(value) is not str or len(value) != length:
        return False
    return all(c in "0123456789abcdef" for c in value)


def analyze_spec(spec: str) -> dict:
    """Examine *the actual extracted SRPM spec*, not an upstream template."""
    if type(spec) is not str or not 0 < len(spec) <= 256 * 1024:
        raise Refusal("SRPM_SPEC_NOT_AVAILABLE")
    if not re.search(r"(?im)^Name:\s*bootc\s*$", spec):
        raise Refusal("SRPM_SPEC_NAME_MISMATCH")
    if not re.search(r"(?im)^Version:\s*1\.17\.1\s*$", spec):
        raise Refusal("SRPM_SPEC_VERSION_MISMATCH")
    if not re.search(r"(?im)^Release:\s*(?:1%\{\?dist\}|%\{autorelease\})\s*$", spec):
        raise Refusal("SRPM_SPEC_RELEASE_MISMATCH")
    if "%prep" not in spec or "%build" not in spec or "%autosetup" not in spec:
        raise Refusal("SRPM_SPEC_PREP_UNKNOWN")
    # Explicit patch declarations/commands may alter the dangerous Rust path.
    patches = re.findall(r"(?im)^\s*Patch\d*:\s*([^\r\n#]+)", spec)
    patch_commands = re.findall(r"(?im)^\s*%(?:patch\d*|apply_patch)\b", spec)
    return {
        "patchesDeclared": [p.strip() for p in patches],
        "explicitPatchCommands": len(patch_commands),
        "requiresPatchReview": bool(patches or patch_commands),
        "specAloneProvesNoSourceMutations": False,
    }


def assess_source_elf_binding(evidence: Mapping, plan: dict) -> dict:
    """Refuse alien claims and retain DENY even when all fields look coherent.

    Evidence is a *caller claim*, not direct access to an RPM signature,
    reproducible build or source tree.  True booleans never promote authority.
    """
    assert_base = assess_candidate(plan)  # existing real Bazzite target gate
    if type(evidence) is not dict or set(evidence) != REQUIRED_EVIDENCE:
        raise Refusal("INCOMPLETE_SRPM_ELF_EVIDENCE")
    exact = (
        ("sourceRpmName", EXPECTED_SOURCE),
        ("rpmNevra", EXPECTED_RPM),
        ("elfSha256", EXPECTED_ELF_SHA256),
        ("elfBuildId", EXPECTED_BUILD_ID),
        ("fedoraKeyFingerprint", EXPECTED_F45_FINGERPRINT),
        ("sourceCommit", EXPECTED_GIT),
    )
    for key, expected in exact:
        if type(evidence[key]) is not str or evidence[key] != expected:
            raise Refusal("FOREIGN_SRPM_ELF_IDENTITY_" + key)
    if not _hex(evidence["srpmSha256"], 64):
        raise Refusal("UNPINNED_SRPM_BYTES")
    if evidence["srpmSha256"] != EXPECTED_SRPM_SHA256:
        raise Refusal("FOREIGN_SRPM_SHA256")
    if not _hex(evidence["sourceTarSha256"], 64):
        raise Refusal("UNPINNED_SOURCE_ARCHIVE")
    for key in (
        "srpmSignatureVerified",
        "srpmPayloadVerified",
        "sourceFilesCompared",
        "specPrepModificationsProvenAbsent",
        "reproducibleBuildVerified",
        "buildRecordAuthenticated",
    ):
        if type(evidence[key]) is not bool:
            raise Refusal("INVALID_EVIDENCE_BOOLEAN_" + key)
    if type(evidence["specPatchNames"]) is not list or any(
        type(x) is not str or not 0 < len(x) <= 256 for x in evidence["specPatchNames"]
    ):
        raise Refusal("INVALID_SRPM_PATCH_INVENTORY")
    if evidence["sourceTarSha256"] != EXPECTED_TARBALL_SHA256:
        raise Refusal("FEDORA_SOURCE_ARCHIVE_NOT_UPSTREAM_RELEASE")
    if evidence["specPatchNames"]:
        raise Refusal("SRPM_PATCHES_NOT_INDEPENDENTLY_REVIEWED")
    rebuild = evidence["elfRebuildSha256"]
    if rebuild is not None and not _hex(rebuild, 64):
        raise Refusal("INVALID_REBUILD_DIGEST")
    if (
        evidence["elfRebuildSha256"] is not None
        and evidence["elfRebuildSha256"] != evidence["elfSha256"]
    ):
        raise Refusal("REBUILT_ELF_DIFFERS_FROM_SIGNED_OCI")
    # A self-authored boolean or digest is not a reproducible build attestation;
    # even an identical ELF would not on its own authorize ESP/boot writes.
    return {
        "decision": "SOURCE_ELF_UNPROVEN",
        "authorization": "DENY_NO_WRITER",
        "sourceRpm": EXPECTED_SOURCE,
        "srpmSha256": EXPECTED_SRPM_SHA256,
        "fedoraKeyFingerprint": EXPECTED_F45_FINGERPRINT,
        "elfSha256": EXPECTED_ELF_SHA256,
        "sourceCommit": EXPECTED_GIT,
        "rpmSourceRecordOnly": True,
        "srpmSignatureVerifiedByThisModule": False,
        "buildProcessIndependentAttestationVerified": False,
        "sourceToElfCryptographicBindingVerified": False,
        "espRisk": {
            "replaceAlongside": "DENY_CONDITIONAL_EFI_LOADER_RECURSIVE_REMOVAL",
            "replaceWipe": "DENY_TARGET_ROOT_REMOVAL",
            "replaceNone": "DENY_NO_ESP_BOOTLOADER_WRITESET",
            "windowsEsp": "DENY_FOREIGN_ESP",
            "linuxEsp": "DENY_UNPROVEN_BOOTUPCTL_BOOTCTL_WRITES_AND_NVRAM",
        },
        **{k: False for k in NO_ACCESS},
        "previousPlanDecision": assert_base["decision"],
    }


def minimal_unproven_record() -> dict:
    """Explicit absence of independent SRPM/ELF attestation; never infer a hash."""
    return {
        "decision": "SOURCE_ELF_UNPROVEN",
        "authorization": "DENY_NO_WRITER",
        "reason": "NO_INDEPENDENT_SRPM_SOURCE_BINARY_BUILD_ATTESTATION",
        "srpmLocationClaim": (
            "https://kojipkgs.fedoraproject.org/packages/bootc/"
            "1.17.1/1.fc45/src/bootc-1.17.1-1.fc45.src.rpm"
        ),
        "srpmSha256Verified": False,
        "srpmSignatureVerified": False,
        "srpmPatchSetReviewed": False,
        "sourceToElfCryptographicBindingVerified": False,
        **{k: False for k in NO_ACCESS},
    }


if __name__ == "__main__":
    import json

    print(json.dumps(minimal_unproven_record(), indent=2, sort_keys=True))
    raise SystemExit(2)
