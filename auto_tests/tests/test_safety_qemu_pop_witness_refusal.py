"""Negative tests for real QEMU witness adapter; mocked artifact contents only."""
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from safety_qemu_pop_witness_refusal import (
    observe_readonly_lab, assess_for_safety,
)
from libertix_prewrite_no_writer import PrewriteDenied

GUID = "12345678-1234-1234-1234-123456789abc"


def write(root, name, payload):
    content = json.dumps(payload, sort_keys=True).encode()
    (root / name).write_bytes(content)
    (root / (name + ".sha256")).write_text(
        hashlib.sha256(content).hexdigest() + "  " + name + "\n"
    )


@pytest.fixture
def evidence(tmp_path):
    write(tmp_path, "win10-pop-live-gpt.json",
          {"guestGpt": {"primaryAndBackupGptCrcVerified": True,
                        "diskWritePerformed": False,
                        "distinstExecutionAuthorized": False,
                        "diskGuid": GUID},
           "nativeInstallationExecuted": False})
    write(tmp_path, "win10-pop-native-child-checkpoint.json",
          {"childCreatedThenDiscardedWithoutWrite": True,
           "distinstExecutionAuthorized": False,
           "authenticatedNativeInstallHandoffVerified": False,
           "productionInstallationAuthorized": False,
           "snapshotOfGenuineWindowsParentSha256": "a" * 64,
           "snapshotOfSixGptWindowsStageSha256": "b" * 64})
    return tmp_path


def test_lab_witness_is_not_safety_authorization(evidence):
    read = observe_readonly_lab(evidence)
    assert read["primaryAndBackupGptCrcVerified"]
    assert not read["hostGuestAuthenticatedBySafety"]
    result = assess_for_safety(
        read, transaction_id="1" * 32, vm_id="authentic-vm-identity-001",
        nonce="x" * 40, expected_guest_guid=GUID,
    )
    assert result["decision"] == "DENY_NO_WRITER"
    assert result["writerCalled"] is False


@pytest.mark.parametrize("change", ["other_disk", "other_transaction", "replay"])
def test_operational_witness_adversarial_refusal(evidence, change):
    read = observe_readonly_lab(evidence)
    request = {
        "transaction_id": "1" * 32,
        "vm_id": "authentic-vm-identity-001",
        "nonce": "x" * 40,
        "expected_guest_guid": GUID,
    }
    if change == "other_disk":
        request["expected_guest_guid"] = "00000000-1234-1234-1234-123456789abc"
    elif change == "other_transaction":
        request["transaction_id"] = None
    else:
        request["nonce"] = None
    decision = assess_for_safety(read, **request)
    assert decision["decision"] == "DENY_NO_WRITER"
    assert decision["writerCalled"] is False


@pytest.mark.parametrize("change", ["tamper_guest", "tamper_checkpoint", "symlink", "missing"])
def test_artifact_injection_fails_before_authorization(evidence, change):
    target = evidence / "win10-pop-live-gpt.json"
    if change == "tamper_guest":
        target.write_bytes(target.read_bytes() + b" ")
    elif change == "tamper_checkpoint":
        target = evidence / "win10-pop-native-child-checkpoint.json"
        target.write_bytes(target.read_bytes() + b" ")
    elif change == "symlink":
        target.unlink()
        target.symlink_to(evidence / "win10-pop-native-child-checkpoint.json")
    else:
        target.unlink()
    with pytest.raises((PrewriteDenied, FileNotFoundError)):
        observe_readonly_lab(evidence)
