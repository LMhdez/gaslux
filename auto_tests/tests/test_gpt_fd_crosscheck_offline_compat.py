"""Pinned-source offline composition tests; disposable raw GPT files only."""
from __future__ import annotations

import copy
import importlib.util
import os
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PIN_ROOT = Path(os.environ["GASLUX_COMPAT_PIN_ROOT"]).resolve()


def load(name: str, path: Path):
    require_file = path.resolve()
    if not require_file.is_file():
        raise RuntimeError(f"missing pinned upstream module: {name}")
    spec = importlib.util.spec_from_file_location(name, require_file)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# These are actual upstream sources checked out at exact commits by CI;
# no validator/parsing logic is copied into the experimental integration tree.
parser = load(
    "libertix_disk_identity_gate",
    PIN_ROOT / "parser/assets/live/libertix_disk_identity_gate.py",
)
crosscheck = load(
    "disk_identity_crosscheck_pinned",
    PIN_ROOT / "crosscheck/auto_tests/tools/disk_identity_crosscheck.py",
)
prewrite = load(
    "libertix_prewrite_no_writer",
    PIN_ROOT / "safety/assets/live/libertix_prewrite_no_writer.py",
)
observer = load(
    "libertix_safety_observer_adapter",
    PIN_ROOT / "safety/assets/live/libertix_safety_observer_adapter.py",
)
upstream_gpt_test = load(
    "upstream_gpt_test_image", PIN_ROOT / "parser/auto_tests/tests/test_disk_identity_gate.py"
)
compat = load(
    "gpt_fd_crosscheck_offline_compat",
    ROOT / "auto_tests/tools/gpt_fd_crosscheck_offline_compat.py",
)

TX = "a" * 32
VM = "synthetic-guest-vm-0001"


def scan(image: Path, *, sector: int = 512) -> dict:
    fd = os.open(image, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        return parser.inspect_gpt_fd(fd, logical_sector_size=sector)
    finally:
        os.close(fd)


def windows_record(snapshot: dict) -> dict:
    return {
        "number": 0, "uniqueId": "synthetic-disk-identity-not-authenticated",
        "sizeBytes": snapshot["sizeBytes"], "partitionStyle": "GPT",
        "logicalSectorSizeBytes": snapshot["logicalSectorSizeBytes"],
        "physicalSectorSizeBytes": 4096,
        "guid": snapshot["partitionTableId"][4:],
        "signature": 0, "inventoryError": None,
        "partitions": [
            {"number": 99 + i, "guid": p["partGuid"], "gptType": p["typeGuid"],
             "offsetBytes": p["offsetBytes"], "sizeBytes": p["sizeBytes"]}
            for i, p in enumerate(snapshot["partitions"])
        ],
    }


def records(snapshot: dict) -> dict:
    """Deliberately untrusted invented digests for *negative* provenance cases.

    These are NEVER derived from GPT CRC or claimed to hash partition content.
    The comparator may return True for a forgery: the adapter still denies.
    """
    p = compat.parser_projection(parser, snapshot)
    record = {
        "transactionId": TX, "diskId": "synthetic-unverified-disk-claim",
        "partitionTableId": p["partitionTableId"], "partitionStyle": "GPT",
        "sizeBytes": p["sizeBytes"], "logicalSectorBytes": p["logicalSectorBytes"],
        "physicalSectorBytes": 4096, "partitionTableSha256": "0" * 64,
        "partitions": [{**item, "contentSha256": "1" * 64}
                       for item in p["partitions"]],
    }
    return {name: copy.deepcopy(record) for name in ("windows", "host", "guest")}


def contexts() -> dict:
    return {
        role: {"role": role, "vmId": VM, "transactionId": TX, "runId": "synthetic-run-1"}
        for role in ("windows", "host", "guest", "guest-immediate")
    }


@pytest.fixture
def case(tmp_path):
    image = tmp_path / "synthetic-gpt.raw"
    upstream_gpt_test.make_image(image)
    original = scan(image)
    snapshots = {
        role: copy.deepcopy(original) for role in ("host", "guest", "guest-immediate")
    }
    return {
        "image": image,
        "snapshot": original,
        "windows_disk": windows_record(original),
        "snapshots": snapshots,
        "inventories": records(original),
        "role_context": contexts(),
    }


def structural(case):
    return compat.reconcile_structure(parser, case["snapshots"], case["windows_disk"])


def decision(case):
    return compat.refuse_operational_composition(
        parser=parser, crosscheck=crosscheck, snapshots=case["snapshots"],
        windows_disk=case["windows_disk"], inventories=case["inventories"],
        role_context=case["role_context"], claimed_transaction_id=TX,
        claimed_vm_id=VM,
    )


def test_gpt_from_original_fd_reconciles_structurally_only(case):
    assert case["snapshot"] == scan(case["image"])
    assert structural(case) == {
        "structuralConsistency": True, "originAuthenticated": False,
        "guestImmediateIndependentWindows": False,
        "contentHashesPresentFromParser": False, "authorization": False,
    }


def test_forged_identical_crosscheck_returns_only_deny(case):
    assert crosscheck.compare_evidence(case["inventories"]) is True
    value = decision(case)
    assert value["crosscheckConsistency"] is True
    assert value["decision"] == compat.UNVERIFIED
    for key in ("provenanceIndependent", "replayProtected",
                "windowsOriginVerified", "guestAttestationVerified",
                "writerAuthorized", "productionInstallationAuthorized"):
        assert value[key] is False


@pytest.mark.parametrize("target", ["primary_crc", "secondary_crc", "entry_crc"])
def test_gpt_crc_failure_rejected_by_pinned_parser(case, target):
    if target == "primary_crc":
        offset = 512 + 56
    elif target == "secondary_crc":
        offset = case["snapshot"]["sizeBytes"] - 512 + 56
    else:
        offset = 1024 + 16
    with case["image"].open("r+b") as stream:
        stream.seek(offset)
        initial = stream.read(1)
        stream.seek(offset)
        stream.write(bytes([initial[0] ^ 1]))
    with pytest.raises(parser.DiskIdentityError):
        scan(case["image"])


@pytest.mark.parametrize("alter", ["partuuid", "disk", "sector", "offset", "size"])
def test_cross_role_structural_change_rejected(case, alter):
    guest = case["snapshots"]["guest"]
    if alter == "partuuid":
        guest["partitions"][0]["partGuid"] = str(uuid.uuid4())
    elif alter == "disk":
        guest["partitionTableId"] = "gpt:" + str(uuid.uuid4())
    elif alter == "sector":
        guest["logicalSectorSizeBytes"] = 4096
    elif alter == "offset":
        guest["partitions"][0]["offsetBytes"] += 512
    else:
        guest["partitions"][0]["sizeBytes"] += 512
    with pytest.raises(compat.CompatibilityRefused):
        structural(case)


def test_windows_numbers_are_not_immutable_identity(case):
    case["windows_disk"]["partitions"][0]["number"] += 731
    assert structural(case)["structuralConsistency"] is True


@pytest.mark.parametrize("alter", ["partuuid", "gpt_type", "logical", "physical", "guid", "error"])
def test_windows_structural_mapping_mismatch_is_refused(case, alter):
    disk = case["windows_disk"]
    if alter == "partuuid":
        disk["partitions"][0]["guid"] = str(uuid.uuid4())
    elif alter == "gpt_type":
        disk["partitions"][0]["gptType"] = str(uuid.uuid4())
    elif alter == "logical":
        disk["logicalSectorSizeBytes"] = 4096
    elif alter == "physical":
        disk["physicalSectorSizeBytes"] = 256
    elif alter == "guid":
        disk["guid"] = str(uuid.uuid4())
    else:
        disk["inventoryError"] = "Windows probe failed"
    with pytest.raises(compat.CompatibilityRefused):
        structural(case)


@pytest.mark.parametrize("alter", ["missing_content", "missing_table", "different_content"])
def test_content_digest_missing_or_conflicting_rejected(case, alter):
    if alter == "missing_content":
        del case["inventories"]["guest"]["partitions"][0]["contentSha256"]
    elif alter == "missing_table":
        del case["inventories"]["guest"]["partitionTableSha256"]
    else:
        case["inventories"]["guest"]["partitions"][0]["contentSha256"] = "f" * 64
    with pytest.raises(compat.CompatibilityRefused):
        decision(case)


def test_crosscheck_inventory_cannot_be_constructed_from_fd_snapshot(case):
    only_fd = compat.parser_projection(parser, case["snapshot"])
    assert "partitionTableSha256" not in only_fd
    assert "physicalSectorBytes" not in only_fd
    assert all("contentSha256" not in p for p in only_fd["partitions"])
    case["inventories"]["host"] = only_fd
    with pytest.raises(compat.CompatibilityRefused):
        decision(case)


@pytest.mark.parametrize("role", ["windows", "host", "guest"])
def test_missing_role_or_swapped_claims_rejected(case, role):
    case["role_context"][role]["role"] = "guest-immediate"
    with pytest.raises(compat.CompatibilityRefused, match="ROLE_ORIGIN_SWAP"):
        decision(case)


@pytest.mark.parametrize("source", ["windows", "host", "guest", "guest-immediate"])
def test_cross_role_transaction_or_vm_mismatch_refused(case, source):
    case["role_context"][source]["transactionId"] = "b" * 32
    with pytest.raises(compat.CompatibilityRefused, match="TRANSACTION_MISMATCH"):
        decision(case)
    case["role_context"][source]["transactionId"] = TX
    case["role_context"][source]["vmId"] = "different-guest-vm-id"
    with pytest.raises(compat.CompatibilityRefused, match="VM_MISMATCH"):
        decision(case)


def test_run_replay_cannot_be_treated_as_authenticated(case):
    case["role_context"]["guest"]["runId"] = "old-run"
    with pytest.raises(compat.CompatibilityRefused, match="WORKFLOW_REPLAY_OR_RUN_MISMATCH"):
        decision(case)
    case["role_context"]["guest"]["runId"] = "synthetic-run-1"
    assert decision(case)["replayProtected"] is False


def test_after_fd_read_mutation_requires_reinspection(case):
    previous = case["snapshot"]
    with case["image"].open("r+b") as stream:
        stream.seek(512 + 56)
        b = stream.read(1)
        stream.seek(512 + 56)
        stream.write(bytes([b[0] ^ 1]))
    with pytest.raises(parser.DiskIdentityError):
        scan(case["image"])
    # The previously returned dictionary has no cryptographic temporal fencing.
    assert compat.parser_projection(parser, previous)["partitionStyle"] == "GPT"
    assert decision(case)["writerAuthorized"] is False


def test_mutated_snapshot_after_fd_read_rejected(case):
    case["snapshots"]["guest-immediate"]["partitions"][0]["sizeBytes"] += 512
    with pytest.raises(compat.CompatibilityRefused):
        structural(case)


def test_mbr_experiment_rejected(case):
    case["snapshots"]["host"]["partitionStyle"] = "MBR"
    with pytest.raises(compat.CompatibilityRefused):
        structural(case)
    case["snapshots"]["host"]["partitionStyle"] = "GPT"
    case["windows_disk"]["partitionStyle"] = "MBR"
    with pytest.raises(compat.CompatibilityRefused, match="GPT_ONLY"):
        structural(case)


def test_no_writer_original_real_api_does_not_authorize():
    # Original #267 tests separately cover the synthetic HMAC laboratory case.
    result = {
        "decision": "ACCEPT_NO_WRITER", "transactionId": TX,
        "vmId": VM, "planSha256": "0" * 64, "writeCount": 1,
    }
    with pytest.raises(compat.CompatibilityRefused, match="NO_WRITER_RESULT"):
        compat.deny_prewrite_promotion(result)


def test_real_no_writer_validator_refuses_missing_trust(case):
    with pytest.raises(prewrite.PrewriteDenied):
        prewrite.decide_no_writer(
            plan={}, plan_bytes=b"", transaction_id=TX, vm_id=VM,
            host_evidence={}, guest_evidence={}, immediate_evidence={},
            host_key=b"", guest_key=b"", fresh_nonce="",
            owned_regions=[], write_set=[],
        )


def test_real_observer_consumer_refuses_no_verified_verifier(case):
    with pytest.raises(observer.SafetyObserverRefused):
        observer.consume_observer_state_no_writer(
            verifier=None, request=b"", response=b"", pins=None, plan_bytes=b"",
            host_gpt=case["snapshots"]["host"], guest_gpt=case["snapshots"]["guest"],
            immediate_gpt=case["snapshots"]["guest-immediate"], gate_evidence=None,
            now=None, deadline=None,
        )


def test_no_write_or_install_can_be_derived_from_offline_consistency(case):
    result = decision(case)
    assert result["decision"] == "DENY_UNAUTHENTICATED_PROVENANCE"
    assert not result["writerAuthorized"]
    assert not result["productionInstallationAuthorized"]
