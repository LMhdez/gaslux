#!/usr/bin/env python3
"""POP-DISTINST-PREWRITE-01: inert System76 pre-write boundary classifier.

No source-to-ELF correspondence, complete native pre-write operation proposal,
or actual preflight-to-commit FD handoff has been demonstrated. Therefore this
code NEVER authorizes a writer, calls distinst, touches block devices, or
exposes executable CLI arguments. It reuses the existing Win10/Pop six-GPT
transaction and write-set validation; all input evidence remains untrusted.
"""

from __future__ import annotations

from windows10_popos_native_write_set import propose_native_write_set
from windows_x64_installed_gpt_ro_audit import require

# Verified Gaslux 24.04 Intel build-20 *laboratory* ISO / ELF pins.
# These values are identity checks, NOT source-level equivalence proofs.
ISO_SHA256 = "a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c"
ELF_SHA256 = "8bfedbc2d6921c440449ec1fda8c4e4d1c0078d69db5aa5832d9a7bf8b13e1a5"
SIGNER_FINGERPRINT = "63C46DF0140D738961429F4E204DD8AEC33A7AFF"
ISO_BUILD = "24.04/intel/20"

# Upstream source inspected read-only at this commit. This is NOT the proven
# source revision of the pinned ISO ELF. Never compare these as if they were.
UPSTREAM_SOURCE_COMMIT = "282dfc441ee608e963930d0ce01f04b672ca4f71"
SOURCE_BLOBS = {
    "cli/src/main.rs": "bac1346a59ef2b48befd913d6d462f60187aa81d",
    "cli/src/configure/reuse.rs": "31bfbe010479a5ede32a966e4867efc42850a562",
    "src/installer/mod.rs": "1f73056529fcff7b282afe2f91b53f07eb2ae255",
    "src/installer/steps/initialize.rs": "06b84e139d373266c61ca86e51f1d01ee9db9f6b",
    "src/installer/steps/partition.rs": "863a0e35ca1c5d69b9369727fc9cdde260e6fe0f",
    "src/installer/steps/bootloader.rs": "6def4885a1b654cbd9e698a8d4f87bf6f3de8c71",
    "crates/disk-ops/src/ops.rs": "9381e4b5fa14b420260fe8b29716d5cc86512901",
}
# Explicit narrow scope: existing transaction/plan are *shaped* but not
# independently authenticated by this function. No source/ELF trust upgrade.
REQUEST_FIELDS = frozenset({
    "operation", "transactionId", "diskGuid",
    "sourceCommitObserved", "sourceMatchesInstalledElf",
    "completePrewriteProposalFromNativeInstaller",
    "preflightToCommitIdentityProven", "nativeBootloaderAuthenticated",
    "installerAlreadyInvoked", "efiVariablesWritable",
    "windowsBootManagerModificationAllowed",
    "signedManifestFingerprint",
    "isoBuild", "isoSha256", "distinstElfSha256",
    "backingParentSha256", "stageCheckpointSha256",
})

DENIED = (
    "native-source-to-ELF-correspondence-unverified",
    "native-complete-prewrite-write-set-unavailable",
    "native-disk-commit-and-format-effects-unconfined",
    "cross-process-FD-identity-handoff-unverified",
    "Windows-in-place-rollback-unproven",
    "independent-bootloader-file-and-NVRAM-proof-unavailable",
)


def assess_prewrite_gap(
    before: dict,
    after: dict,
    plan: dict,
    media: dict,
    guest: dict,
    transaction: dict,
    checkpoint: dict,
    requested_operations: list[dict],
    request: dict,
) -> dict:
    """Inspect a shaped synthetic proposal, then DENY execution unconditionally.

    This function does not model upstream commit as a contained operation:
    disk.commit() may rewrite GPT even for a 'reuse' or '--test' request.
    Untrusted self-asserted input cannot establish a native installer hook.
    """
    # Reuse previous strict six-GPT/Windows ownership and recovery-shaped
    # checks; do not reimplement partition offsets or a GPT parser.
    proposal = propose_native_write_set(
        before, after, plan, media, guest, transaction,
        checkpoint, requested_operations,
    )
    require(
        type(request) is dict and set(request) == REQUEST_FIELDS,
        "REFUSE_POP_PREWRITE: missing, extra or untrusted prewrite fields",
    )
    require(
        media.get("isoSha256") == ISO_SHA256
        and media.get("distinstSha256") == ELF_SHA256
        and request["isoSha256"] == ISO_SHA256
        and request["distinstElfSha256"] == ELF_SHA256
        and request["isoBuild"] == ISO_BUILD
        and request["signedManifestFingerprint"] == SIGNER_FINGERPRINT,
        "REFUSE_POP_PREWRITE: installer or ISO provenance does not match pin",
    )
    require(
        request["operation"] == "read-only-observation"
        and type(request["transactionId"]) is str
        and request["transactionId"] == proposal["transactionId"]
        and request["diskGuid"] == proposal["disk"]["guid"]
        and request["backingParentSha256"] == proposal["backingParentsSha256"]["base"]
        and request["stageCheckpointSha256"] == proposal["backingParentsSha256"]["stage"],
        "REFUSE_POP_PREWRITE: foreign destination, transaction or checkpoint",
    )
    require(
        request["sourceCommitObserved"] == UPSTREAM_SOURCE_COMMIT
        and request["sourceMatchesInstalledElf"] is False
        and request["completePrewriteProposalFromNativeInstaller"] is False
        and request["preflightToCommitIdentityProven"] is False
        and request["nativeBootloaderAuthenticated"] is False
        and request["installerAlreadyInvoked"] is False
        and request["efiVariablesWritable"] is False
        and request["windowsBootManagerModificationAllowed"] is False,
        "REFUSE_POP_PREWRITE: attempted elevation of unverified native capability",
    )
    require(
        proposal["bootloader"] == {
            "name": "systemd-boot",
            "partitionIndex": 5,
            "efiVariablesWritable": False,
            "windowsEspWritable": False,
        }
        and proposal["forbiddenEfiPaths"] == [
            "EFI/Microsoft", "EFI/Boot/bootmgfw.efi",
        ]
        and "disk-commit" in proposal["forbiddenOperations"]
        and proposal["diskCommitSideEffectsConfined"] is False
        and proposal["signedHandoffAuthorityEstablished"] is False
        and proposal["durableNativeWriteRollbackVerified"] is False
        and proposal["distinstExecutionAuthorized"] is False,
        "REFUSE_POP_PREWRITE: unsafe native writer/bootloader claim",
    )
    # Source-at-HEAD observation, not a claim about the installed ELF's code.
    # --test terminates only AFTER Installer::partition/disk.commit/mount.
    return {
        "schemaVersion": 1,
        "scenario": "pop-distinst-native-prewrite-deny-only",
        "transactionId": proposal["transactionId"],
        "diskGuid": proposal["disk"]["guid"],
        "isoBuild": ISO_BUILD,
        "isoSha256": ISO_SHA256,
        "distinstElfSha256": ELF_SHA256,
        "upstreamSourceCommitObserved": UPSTREAM_SOURCE_COMMIT,
        "sourceToInstalledElfCorrespondenceVerified": False,
        "firstPotentialPersistentDiskStep": "Installer::partition -> disk.commit",
        "nativeTestFlagIsReadOnly": False,
        "completeNativeWriteSetAvailableBeforeMutation": False,
        "nativeBootloaderVerifiedForPinnedElf": False,
        "nativePreflightToCommitFDIdentityVerified": False,
        "proposalIsFromNativeInstaller": False,
        "candidateOwnershipShapeChecked": True,
        "blockedBy": list(DENIED),
        "decision": "DENY_NO_WRITER",
        "observationComplete": False,
        "distinstExecutionAuthorized": False,
        "windowsWriterAuthorized": False,
        "productionInstallationAuthorized": False,
        "sameDiskDualBootVerified": False,
        "windowsInPlaceRollbackProven": False,
        "releaseEligible": False,
        "stable": False,
    }
