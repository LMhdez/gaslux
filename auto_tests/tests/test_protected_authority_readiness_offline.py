"""Adversarial static readiness checks. None authenticate an administrative actor."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
PIN_ROOT = Path(os.environ["GASLUX_READINESS_PIN_ROOT"]).resolve()
FIXTURE = (
    ROOT
    / "auto_tests/fixtures/protected-authority-readiness/untrusted-github-observations.json"
)
SCHEMA = ROOT / "schemas/protected-authority-readiness-v1.schema.json"


def load(name: str, path: Path):
    assert path.is_file(), f"missing pinned source: {path}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gate = load(
    "protected_authority_readiness_offline",
    ROOT / "auto_tests/tools/protected_authority_readiness_offline.py",
)
trigger = load(
    "observer_gpt_qemu_one_shot",
    PIN_ROOT / "trigger/auto_tests/tools/observer_gpt_qemu_one_shot.py",
)
ledger = load(
    "observer_one_shot_ledger_offline",
    PIN_ROOT / "ledger/auto_tests/tools/observer_one_shot_ledger_offline.py",
)
sys.path.insert(0, str(PIN_ROOT / "safety/assets/live"))
load(
    "libertix_disk_identity_gate",
    PIN_ROOT / "safety/assets/live/libertix_disk_identity_gate.py",
)
safety = load(
    "libertix_prewrite_no_writer",
    PIN_ROOT / "safety/assets/live/libertix_prewrite_no_writer.py",
)


def report() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def outcome(data=None):
    return gate.assess_readiness(report() if data is None else data)


def assert_blocked(value):
    assert value["decision"] == "BLOCKED_TRUST_ROOT"
    assert value["readOnlyDiagnostic"] is True
    assert set(value["controls"]) == set(gate.CONTROLS)
    assert set(value["individualStatusesDefined"]) == {
        "VERIFIED", "MISSING", "NOT_VERIFIABLE"
    }
    assert all(v["status"] == "NOT_VERIFIABLE" for v in value["controls"].values())
    assert set(value["capabilities"]) == set(gate.CAPABILITY_NAMES)
    assert all(item is False for item in value["capabilities"].values())


def probe(key, payload, *, status=200, source="GITHUB_READ_ONLY"):
    return {"source": source, "httpStatus": status, "payload": payload}


def test_schema_draft_2020_12_accepts_fixture_but_not_authority():
    raw = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(raw)
    Draft202012Validator(raw).validate(report())
    assert raw["additionalProperties"] is False
    assert_blocked(outcome())


def test_realistic_branch_flag_false_with_403_and_ruleset_gap():
    result = outcome()
    assert result["controls"]["main.protection"]["reason"].startswith(
        "DIRECT_BRANCH_PROTECTION_FLAG_FALSE"
    )
    assert result["controls"]["reviews.required"]["reason"] == (
        "API_FORBIDDEN_NOT_VERIFIABLE"
    )
    assert result["controls"]["main.rulesets"]["reason"].startswith(
        "EMPTY_RULESET_LIST"
    )
    assert_blocked(result)


@pytest.mark.parametrize(
    ("name", "item", "reason"),
    [
        (
            "main.protection",
            probe(None, status=403),
            "API_FORBIDDEN_NOT_VERIFIABLE",
        ),
        (
            "dev.protection",
            probe(None, status=403),
            "API_FORBIDDEN_NOT_VERIFIABLE",
        ),
        (
            "main.rulesets",
            probe({"rulesets": []}),
            "EMPTY_RULESET_LIST_NOT_AN_INDEPENDENT_ADMIN_PROOF",
        ),
        (
            "environment.requiredReviewers",
            probe(None, status=403),
            "API_FORBIDDEN_NOT_VERIFIABLE",
        ),
        (
            "reviews.selfApprovalExcluded",
            probe({"requester": "LMhdez", "approver": "LMhdez"}),
            "SELF_APPROVAL_NOT_EXCLUDED",
        ),
        (
            "controller.protectedLocation",
            probe({"controllerRef": "refs/heads/feature/attacker"}),
            "WORKFLOW_REQUESTER_CONTROLLED_OR_WRONG_REF",
        ),
        (
            "commit.preparationExact",
            probe({"expectedSha": "a" * 40, "actualSha": "b" * 40}),
            "EXACT_COMMIT_IDENTITY_MISMATCH",
        ),
        (
            "commit.authorizationExact",
            probe({"expectedSha": "a" * 40, "actualSha": "b" * 40}),
            "EXACT_COMMIT_IDENTITY_MISMATCH",
        ),
        (
            "requester.branchIsolation",
            probe({"branchRecreated": True}),
            "REQUIRES_INDEPENDENT_ADMINISTRATIVE_PROVENANCE",
        ),
        (
            "reviews.required",
            probe({"humanApproved": True}, source="PR_COMMENT"),
            "PR_COMMENT_NOT_AN_ADMINISTRATIVE_APPROVAL",
        ),
        (
            "ledger.externalService",
            probe({"backend": "sqlite"}, source="SQLITE_LOCAL"),
            "SELF_ASSERTED_OR_LOCAL_SOURCE",
        ),
        (
            "ledger.rollbackResistant",
            probe({"backend": "external", "snapshotRestored": True}),
            "LEDGER_SNAPSHOT_ROLLBACK_UNFENCED",
        ),
        (
            "ledger.globalUniqueness",
            probe({"decisionId": "reused", "backend": "sqlite"}),
            "LOCAL_LEDGER_NOT_EXTERNALLY_ROLLBACK_RESISTANT",
        ),
        (
            "coordinator.freshChallenge",
            probe({"reused": True}),
            "REPLAYED_OR_EXPIRED_CHALLENGE",
        ),
        (
            "coordinator.freshChallenge",
            probe({"expired": True}),
            "REPLAYED_OR_EXPIRED_CHALLENGE",
        ),
        (
            "controller.tokenPermissions",
            probe({"permissions": {"contents": "read"}}),
            "RUNNER_TOKEN_CANNOT_ATTEST_ADMINISTRATIVE_PROTECTION",
        ),
        (
            "controller.immutableWorkflow",
            probe({"verified": True, "source": "runner"}, source="RUNNER_LOCAL"),
            "SELF_ASSERTED_OR_LOCAL_SOURCE",
        ),
        (
            "observer.readOnlyProducer",
            probe({"conclusion": "success"}, source="CI_STATUS"),
            "GREEN_CI_NOT_AN_ADMINISTRATIVE_AUTHORITY",
        ),
        (
            "guest.no-such-control",
            probe({"claimed": True}),
            "INPUT_SCHEMA_INVALID",
        ),
    ],
)
def test_adversarial_infrastructure_observation_blocks(name, item, reason):
    data = report()
    data["observations"][name] = item
    result = outcome(data)
    if name not in gate.CONTROLS:
        assert result["controls"]["main.protection"]["reason"] == reason
    else:
        assert result["controls"][name]["reason"] == reason
    assert_blocked(result)


def test_all_documents_supplied_by_runner_do_not_become_verified():
    data = report()
    data["observations"] = {
        name: probe({"verified": True, "protected": True}, source="RUNNER_LOCAL")
        for name in gate.CONTROLS
    }
    result = outcome(data)
    assert all(
        value["reason"] == "SELF_ASSERTED_OR_LOCAL_SOURCE"
        for value in result["controls"].values()
    )
    assert_blocked(result)


def test_full_synthetic_github_200_does_not_authenticate_admin():
    data = report()
    data["observations"] = {
        name: probe({"protected": True, "approved": True, "authorized": True})
        for name in gate.CONTROLS
    }
    assert_blocked(outcome(data))


def test_fake_pr_comment_and_green_ci_do_not_prove_approval():
    data = report()
    data["observations"]["reviews.required"] = probe(
        {"approver": "human", "approved": True}, source="PR_COMMENT"
    )
    data["observations"]["environment.requiredReviewers"] = probe(
        {"workflow": "success"}, source="CI_STATUS"
    )
    assert_blocked(outcome(data))


def test_matching_sha_remains_untrusted():
    data = report()
    data["observations"]["commit.preparationExact"] = probe(
        {"expectedSha": "a" * 40, "actualSha": "a" * 40}
    )
    result = outcome(data)
    assert result["controls"]["commit.preparationExact"]["reason"] == (
        "SHA_EQUALITY_WITHOUT_PROTECTED_PIN_ORIGIN"
    )
    assert_blocked(result)


def test_unavailable_environment_and_incomplete_response():
    data = report()
    data["observations"]["environment.requiredReviewers"] = probe(
        None, status=503
    )
    result = outcome(data)
    assert result["controls"]["environment.requiredReviewers"]["reason"] == (
        "API_UNAVAILABLE_OR_UNSUPPORTED"
    )
    assert_blocked(result)


@pytest.mark.parametrize(
    "invalid",
    [
        lambda d: d.update({"authorized": True}),
        lambda d: d.update({"contractVersion": 2}),
        lambda d: d.update({"repository": "other/repo"}),
        lambda d: d["observations"]["main.protection"].update({"trusted": True}),
        lambda d: d["observations"]["main.protection"].update(
            {"source": "INDEPENDENT_ADMIN"}
        ),
        lambda d: d["observations"]["main.protection"].update({"httpStatus": 999}),
    ],
)
def test_structurally_invalid_self_authorization_refused(invalid):
    data = report()
    invalid(data)
    result = outcome(data)
    assert all(
        x["reason"] == "INPUT_SCHEMA_INVALID" for x in result["controls"].values()
    )
    assert_blocked(result)


def test_ledger_v3_original_contracts_remain_denial_only():
    grant = json.loads(
        (
            PIN_ROOT / "ledger/auto_tests/fixtures/observer-one-shot/valid-grant.json"
        ).read_text(encoding="utf-8")
    )
    ledger._check_grant(grant)
    assert len(ledger._identities(grant)) == 3
    assert len(ledger._commit_key(grant)) == 64
    assert ledger._decision_reason(grant, None) == "EXTERNAL_AUTHORITY_UNAVAILABLE"
    run = ledger.RunObservationFixture(
        repository=grant["repository"],
        experiment_id=grant["experimentId"],
        request_ref=grant["requestRef"],
        preparation_sha=grant["preparationSha"],
        authorization_sha=grant["authorizationSha"],
        protected_controller_sha=grant["protectedControllerSha"],
        audited_code_sha=grant["auditedCodeSha"],
        run_id="synthetic-run",
        branch_recreated=True,
    )
    assert ledger._run_reason(grant, run) == "BRANCH_CREATION_OR_RECREATION_REFUSED"
    assert_blocked(outcome())


def test_pinned_275_git_verifier_requires_real_protected_pins(tmp_path):
    with pytest.raises(trigger.Refused, match="TRUSTED_PREPARATION_MISSING"):
        trigger.validate_git(tmp_path, {})
    assert_blocked(outcome())


def test_original_267_no_writer_refuses_untrusted_input():
    with pytest.raises(safety.PrewriteDenied):
        safety.decide_no_writer(
            plan={}, plan_bytes=b"", transaction_id="", vm_id="",
            host_evidence={}, guest_evidence={}, immediate_evidence={},
            host_key=b"", guest_key=b"", fresh_nonce="",
            owned_regions=[], write_set=[],
        )
    assert_blocked(outcome())


def test_probe_existing_original_contracts_reuses_denials():
    grant = json.loads(
        (
            PIN_ROOT / "ledger/auto_tests/fixtures/observer-one-shot/valid-grant.json"
        ).read_text(encoding="utf-8")
    )
    value = gate.probe_existing_denial_contracts(
        trigger_module=trigger, ledger_module=ledger, safety_module=safety, grant=grant
    )
    assert value["decision"] == "BLOCKED_TRUST_ROOT"
    assert value["upstreamContractObservations"]["ledgerSchema"] == "STRUCTURAL_ONLY"
    assert value["upstreamContractObservations"]["exactGitTrigger"].startswith("REFUSED")
    assert value["upstreamContractObservations"]["noWriter"].startswith("REFUSED")
    assert all(x is False for x in value["capabilities"].values())


def test_inert_275_trigger_and_294_producer_are_not_authority():
    workflow = (
        PIN_ROOT / "trigger/.github/workflows/observer-gpt-qemu-one-shot.yml"
    ).read_text(encoding="utf-8")
    assert "if: ${{ false }}" in workflow
    assert "qemu-disabled:" in workflow
    producer = (
        PIN_ROOT / "observer/auto_tests/installer_observer/host_qemu_fd_evidence.py"
    )
    assert producer.is_file()
    assert "no writer" in producer.read_text(encoding="utf-8").lower() or (
        "read-only" in producer.read_text(encoding="utf-8").lower()
    )
    assert_blocked(outcome())


def test_self_reuse_of_positive_status_tokens_is_never_trusted():
    data = report()
    data["observations"]["ledger.consumeAtomic"] = probe(
        {"status": "VERIFIED", "consumed": True, "singleUse": True}
    )
    data["observations"]["environment.requiredReviewers"] = probe(
        {"status": "VERIFIED", "humanApproved": True}
    )
    assert_blocked(outcome(data))
