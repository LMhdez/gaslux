"""Q4OS UI-map contracts. No virtual machines, disk writers, network or screenshot fabrication."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs/distro-backends"
MAP_FILE = DOCS / "ui-maps/q4os.json"
EVIDENCE_FILE = DOCS / "evidence/q4os-manifest.json"
MAP_SCHEMA = ROOT / "schemas/distro-ui-map.schema.json"
EVIDENCE_SCHEMA = ROOT / "schemas/distro-ui-evidence.schema.json"
LAB_SOURCE = "6b6d5521dbd4c2c26712fb57cb6ae5b29e0c69bb"
ISO_SHA = "1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def documents() -> tuple[dict, dict]:
    return read_json(MAP_FILE), read_json(EVIDENCE_FILE)


def test_schema_contracts_current_instance(documents: tuple[dict, dict]) -> None:
    mapping, evidence = documents
    for instance, schema_path in [
        (mapping, MAP_SCHEMA),
        (evidence, EVIDENCE_SCHEMA),
    ]:
        schema = read_json(schema_path)
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(instance, schema)
    assert mapping["lab"]["sourceCommit"] == LAB_SOURCE
    assert evidence["labSourceCommit"] == LAB_SOURCE
    assert mapping["iso"]["sha256"] == evidence["iso"]["sha256"] == ISO_SHA
    assert evidence["iso"]["upstreamGpgSignatureVerified"] is False
    assert mapping["lab"]["windowsDiskAttached"] is False
    assert mapping["lab"]["vmReplicasRequired"] == 2


def test_state_machine_order_and_coordinates(documents: tuple[dict, dict]) -> None:
    mapping, _ = documents
    states = mapping["states"]
    transitions = mapping["transitions"]
    assert len(states) == 9 and len(transitions) == 8
    ids = [s["id"] for s in states]
    assert len(ids) == len(set(ids))
    assert [s["order"] for s in states] == list(range(len(states)))
    for state in states:
        assert state["screenshot"].startswith("vnc-")
        assert state["qtAccessibilityId"] is None or state["qtAccessibilityId"]
        assert all(x["qtId"] is None or x["qtId"] for x in state["controls"])
    for i, transition in enumerate(transitions):
        assert transition["from"] == ids[i]
        assert transition["to"] == ids[i + 1]
        assert transition["configuredCommandTimeoutSeconds"] == 20
        assert transition["preconditions"] and transition["postconditions"]
        loc = transition["locator"]
        assert loc["type"] == "sha-gated-vnc-coordinate"
        x, y = loc["x"], loc["y"]
        assert isinstance(x, int) and isinstance(y, int)
        assert 0 <= x < 1280 and 0 <= y < 800
        left, top, right, bottom = loc["boundingBox"]
        assert left <= x < right and top <= y < bottom
        if transition["status"] == "verified":
            assert len(transition["proofs"]) == 2
        else:
            assert len(transition["proofs"]) < 2


def test_only_original_images_can_support_a_verified_claim(
    documents: tuple[dict, dict],
) -> None:
    mapping, evidence = documents
    artifact_ids = set()
    for state in mapping["states"]:
        if len(state["proofs"]) == 2:
            assert {p["replica"] for p in state["proofs"]} == {1, 2}
            assert all(p["visualGatePassed"] for p in state["proofs"])
            assert all(p["screenshot"] == state["screenshot"] for p in state["proofs"])
            assert len({p["artifactId"] for p in state["proofs"]}) == 2
        elif state["proofs"]:
            assert evidence["status"] in {"partial", "blocked"}
    for transition in mapping["transitions"]:
        if transition["status"] == "verified":
            proofs = transition["proofs"]
            assert len(proofs) == 2
            assert {x["replica"] for x in proofs} == {1, 2}
            assert len({x["artifactId"] for x in proofs}) == 2
            assert all(x["visualGatesPassed"] and x["centralRegionChanged"] for x in proofs)
            for x in proofs:
                artifact_ids.add(x["artifactId"])
        else:
            assert len(transition["proofs"]) < 2
    if evidence["status"] == "two-vm-verified":
        assert len(artifact_ids) == 2
        assert evidence["stateCountVerifiedInTwoGuests"] == 9
        assert evidence["transitionCountVerifiedInTwoGuests"] == 8
        assert len(evidence["runs"]) == 2
        assert all(r["result"] == "success" for r in evidence["runs"])
        assert {r["artifactId"] for r in evidence["runs"]} == artifact_ids
        assert len({r["replica"] for r in evidence["runs"]}) == 2
        assert all(
            len(run["screenshots"]) == 9 and len(run["transitions"]) == 8
            for run in evidence["runs"]
        )
        assert mapping["iso"]["sizeBytes"] == evidence["iso"]["sizeBytes"]


def test_no_destructive_promotion(documents: tuple[dict, dict]) -> None:
    mapping, evidence = documents
    assert mapping["stopBoundary"]["lastObservedState"] == "calamares-users-unfilled"
    assert mapping["stopBoundary"]["nextStateUnobserved"] == "calamares-summary"
    assert mapping["stopBoundary"]["nativeCalamaresInstallExecuted"] is False
    assert mapping["stopBoundary"]["windowsDiskModified"] is False
    assert mapping["stopBoundary"]["accountInputAttempted"] is False
    assert "Summary" in mapping["stopBoundary"]["reason"]
    assert evidence["blockedAt"].startswith("calamares-users-unfilled")
    assert all(r["result"] != "success" or r["isoHashVerified"] for r in evidence["runs"])


def test_schema_rejects_invalid_sha_and_install_claim(documents: tuple[dict, dict]) -> None:
    mapping, _ = documents
    schema = read_json(MAP_SCHEMA)
    bogus = copy.deepcopy(mapping)
    bogus["iso"]["sha256"] = "fake-sha256"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bogus, schema)
    bogus = copy.deepcopy(mapping)
    bogus["stopBoundary"]["nativeCalamaresInstallExecuted"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bogus, schema)
    bogus = copy.deepcopy(mapping)
    bogus["transitions"][0]["locator"]["type"] = "unguarded-click"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bogus, schema)


def test_exact_source_workflow_is_lab_only() -> None:
    workflow = (ROOT / ".github/workflows/q4os-ui-repro-2vm.yml").read_text(encoding="utf-8")
    for required in (
        LAB_SOURCE,
        ISO_SHA,
        "GASLUX_Q4OS_NATIVE_COW_VIEW_ONLY: 'yes'",
        "GASLUX_Q4OS_GRAPHICS_LAB_ONLY: '1'",
        "matrix:",
        "replica: [1, 2]",
        "permissions:",
        "contents: read",
        "vnc-users-page.png",
        "nativeCalamaresInstallExecuted",
        "official Q4OS",
    ):
        assert required in workflow
