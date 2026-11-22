"""Offline adversarial ISO45 read-only inspection proposals (never guest execution)."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))

from bazzite_anaconda_readonly_capture import READS  # noqa: E402
from bazzite_gpt_fixture import PARTITIONS  # noqa: E402
from bazzite_iso45_guest_inspection_contract import (  # noqa: E402
    DISK_BYTES,
    DISK_SERIAL,
    ISO_BYTES,
    ISO_SHA256,
    NO_WRITE,
    ORIGINAL_ARCHIVE_SHA256,
    PAYLOAD_DIGEST,
    Refusal,
    validate_contract,
)


def sample() -> dict:
    """Everything in this fixture is synthetic and untrusted, including hashes."""
    disk = {
        "serial": DISK_SERIAL,
        "guid": "11111111-2222-4333-8444-555555555555",
        "logicalSectorBytes": 512,
        "sizeBytes": DISK_BYTES,
        "partitions": [
            {
                "number": n,
                "typeGuid": guid.lower(),
                "partuuid": f"0000000{n}-2222-4333-8444-555555555555",
                "firstSector": first,
                "lastSector": last,
            }
            for n, guid, _name, first, last in PARTITIONS
        ],
    }
    reply = "aa{sv} 0"
    return {
        "schemaVersion": 1,
        "origin": "synthetic-untrusted-proposal",
        "media": {
            "version": "45.20261117.1",
            "isoSha256": ISO_SHA256,
            "isoSizeBytes": ISO_BYTES,
            "payloadDigest": PAYLOAD_DIGEST,
            "sourceRunId": 44822100590,
            "sourceArtifactId": 14672623998,
            "sourceArchiveSha256": ORIGINAL_ARCHIVE_SHA256,
        },
        "run": {
            "transaction": "a" * 32,
            "challenge": "b" * 64,
            "qemuPid": 4321,
            "qemuStartTicks": 556677,
            "qemuExecutableSha256": "c" * 64,
            "qemuArgvSha256": "d" * 64,
            "hostVmId": "gaslux-bazzite-fixture",
            "guestVmId": "gaslux-bazzite-fixture",
            "sequence": 1,
        },
        "storage": {
            "firmware": "uefi",
            "partitionTable": "gpt",
            "diskCount": 1,
            "hostDisk": disk,
            "guestDisk": copy.deepcopy(disk),
            "additionalDisks": [],
            "windowsAttached": False,
        },
        "collector": {
            "path": "auto_tests/bazzite_anaconda_readonly_capture.py",
            "hostSha256": "e" * 64,
            "guestSha256": "e" * 64,
            "transport": "not-established",
            "invoked": False,
        },
        "installer": {
            "service": "org.fedoraproject.Anaconda.Modules.Storage",
            "owner": ":1.24",
            "pid": 456,
            "startTicks": 555,
            "executableSha256": "f" * 64,
            "version": "anaconda-45.0-fixture",
            "servicePresent": True,
        },
        "dbus": {
            "allowlistedMethods": list(READS),
            "replies": [
                {
                    "method": "GetActions",
                    "text": reply,
                    "sha256": hashlib.sha256(reply.encode()).hexdigest(),
                    "elapsedMs": 10,
                    "truncated": False,
                    "timedOut": False,
                }
            ],
        },
        "provenance": {
            "source": "untrusted-runner",
            "independentlyVerified": False,
            "trustRoot": None,
            "safetyApproved": False,
            "observerApproved": False,
        },
        "permissions": {name: False for name in NO_WRITE},
    }


def test_structurally_valid_record_still_refuses_all_authority():
    result = validate_contract(sample())
    assert result["status"] == "REFUSED_NO_AUTHENTICATED_GUEST_COLLECTOR_CHANNEL"
    assert result["structuralChecksPassed"] is True
    for key in (
        *NO_WRITE,
        "safetyApproved",
        "observerApproved",
        "externallyAuthenticated",
        "anacondaProcessVerified",
    ):
        assert result[key] is False


@pytest.mark.parametrize(
    ("path", "value", "reason"),
    [
        (("schemaVersion",), 2, "version"),
        (("media", "isoSha256"), "0" * 64, "ISO"),
        (("media", "payloadDigest"), "sha256:" + "a" * 64, "payload"),
        (("media", "sourceArchiveSha256"), "9" * 64, "lineage"),
        (("media", "isoSizeBytes"), ISO_BYTES - 1, "ISO"),
        (("run", "qemuPid"), 0, "PID"),
        (("run", "qemuStartTicks"), 0, "ticks"),
        (("run", "qemuExecutableSha256"), "x" * 64, "SHA256"),
        (("run", "guestVmId"), "another-vm", "VM identity"),
        (("run", "sequence"), 2, "sequence"),
        (("run", "transaction"), "0" * 32, None),
        (("storage", "firmware"), "bios", "BIOS"),
        (("storage", "partitionTable"), "mbr", "BIOS"),
        (("storage", "diskCount"), 2, "disk"),
        (("storage", "additionalDisks"), ["vdb"], "disk"),
        (("storage", "windowsAttached"), True, "Windows"),
        (("storage", "guestDisk", "serial"), "FOREIGN", "serial"),
        (("storage", "guestDisk", "guid"), "22222222-2222-4333-8444-555555555555", "identity"),
        (("storage", "guestDisk", "partitions", 0, "firstSector"), 4096, "offset"),
        (
            ("storage", "guestDisk", "partitions", 1, "partuuid"),
            "00000001-2222-4333-8444-555555555555",
            "Duplicate",
        ),
        (("collector", "guestSha256"), "1" * 64, "substituted"),
        (("collector", "transport"), "ssh", "channel"),
        (("collector", "invoked"), True, "invocation"),
        (("installer", "servicePresent"), False, "absent"),
        (("installer", "owner"), ":1.999-notowner", "owner"),
        (("installer", "pid"), 0, "PID"),
        (("installer", "executableSha256"), "1" * 63, "Anaconda"),
        (("installer", "version"), "", "version"),
        (("dbus", "allowlistedMethods"), ["GetDevices"], "GetActions"),
        (
            ("dbus", "allowlistedMethods"),
            ["GetActions", "GetDevices", "ApplyPartitioning"],
            "read-only",
        ),
        (
            ("dbus", "allowlistedMethods"),
            ["GetActions", "GetDevices", "InstallWithTasks"],
            "read-only",
        ),
        (("dbus", "replies", 0, "text"), "aa{sv} 1", "Changed"),
        (("dbus", "replies", 0, "truncated"), True, "Truncated"),
        (("dbus", "replies", 0, "timedOut"), True, "timed out"),
        (("dbus", "replies", 0, "elapsedMs"), 12001, "unbounded"),
        (("dbus", "replies", 0, "method"), "GetDevices", "GetActions reply"),
        (("provenance", "independentlyVerified"), True, "Untrusted claims"),
        (("provenance", "trustRoot"), "self-signed-runner", "Untrusted claims"),
        (("provenance", "source"), "runner-signed-self", "Untrusted claims"),
        (("provenance", "safetyApproved"), True, "Untrusted claims"),
        (("provenance", "observerApproved"), True, "Untrusted claims"),
        (("permissions", "getActionsObserved"), True, "cannot grant"),
        (("permissions", "installationAuthorized"), True, "cannot grant"),
        (("permissions", "gptMetadataWriteAuthorized"), True, "cannot grant"),
        (("permissions", "secureBootEnrollmentAuthorized"), True, "cannot grant"),
    ],
)
def test_adversarial_substitutions_fail_closed(path, value, reason):
    if path == ("run", "transaction"):
        with pytest.raises(Refusal, match="repeated transaction"):
            validate_contract(sample(), seen_transactions=frozenset({"a" * 32}))
        return
    data = sample()
    target = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    if reason is None:
        with pytest.raises(Refusal):
            validate_contract(data)
    else:
        with pytest.raises(Refusal, match=reason):
            validate_contract(data)


def test_missing_fields_unknown_fields_noncanonical_type_and_duplicate_method():
    for changed in ("missing", "extra", "bool-schema", "duplicate-method", "bool-disk-count"):
        data = sample()
        if changed == "missing":
            del data["collector"]["hostSha256"]
        elif changed == "extra":
            data["permissions"]["writeAllowed"] = True
        elif changed == "bool-schema":
            data["schemaVersion"] = True
        elif changed == "duplicate-method":
            data["dbus"]["allowlistedMethods"].append("GetActions")
        else:
            data["storage"]["diskCount"] = True
        with pytest.raises(Refusal):
            validate_contract(data)


def test_dbus_response_size_bound_before_digest():
    data = sample()
    body = "x" * (1024 * 1024 + 1)
    data["dbus"]["replies"][0]["text"] = body
    data["dbus"]["replies"][0]["sha256"] = hashlib.sha256(body.encode()).hexdigest()
    with pytest.raises(Refusal, match="Unbounded"):
        validate_contract(data)


def test_offline_cli_valid_structure_is_exit_2_not_authorization(tmp_path):
    path = tmp_path / "untrusted.json"
    path.write_text(json.dumps(sample()))
    tool = ROOT / "auto_tests" / "bazzite_iso45_guest_inspection_contract.py"
    result = subprocess.run(
        [sys.executable, str(tool), "--proposal", str(path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 2
    report = json.loads(result.stdout)
    assert report["status"] == "REFUSED_NO_AUTHENTICATED_GUEST_COLLECTOR_CHANNEL"
    assert report["installationAuthorized"] is False


def test_offline_cli_rejects_symlink_and_untrusted_claim(tmp_path):
    actual = tmp_path / "evidence.json"
    actual.write_text(json.dumps(sample()))
    link = tmp_path / "link.json"
    link.symlink_to(actual)
    tool = ROOT / "auto_tests" / "bazzite_iso45_guest_inspection_contract.py"
    result = subprocess.run(
        [sys.executable, str(tool), "--proposal", str(link)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 3
    assert "REFUSED_CONTRACT" in result.stderr


def test_json_schema_fixture_if_library_present():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (ROOT / "schemas" / "bazzite_iso45_guest_inspection_contract_v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(sample(), schema)
    data = sample()
    data["permissions"]["installationAuthorized"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)


# Differential categories: A = schema refusal, B = Python-only relationship
# refusal after schema acceptance, C = well-formed but permanently deny-only.
# Neither JSON Schema nor self-consistent hashes provide guest authenticity.


@pytest.fixture(scope="module")
def iso45_schema_validator():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (ROOT / "schemas" / "bazzite_iso45_guest_inspection_contract_v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


@pytest.mark.parametrize(
    ("name", "path", "replacement"),
    [
        ("qemu-pid-zero", ("run", "qemuPid"), 0),
        ("qemu-pid-one", ("run", "qemuPid"), 1),
        ("qemu-pid-boolean", ("run", "qemuPid"), True),
        ("anaconda-pid-zero", ("installer", "pid"), 0),
        ("anaconda-pid-one", ("installer", "pid"), 1),
        ("anaconda-pid-boolean", ("installer", "pid"), True),
        ("qemu-start-boolean", ("run", "qemuStartTicks"), True),
        ("anaconda-start-boolean", ("installer", "startTicks"), True),
        ("dbus-elapsed-boolean", ("dbus", "replies", 0, "elapsedMs"), True),
        ("disk-count-boolean", ("storage", "diskCount"), True),
        ("schema-version-boolean", ("schemaVersion",), True),
        ("media-runid-boolean", ("media", "sourceRunId"), True),
        ("host-vm-prefix", ("run", "hostVmId"), "not-a-gaslux-vm"),
        ("guest-vm-prefix", ("run", "guestVmId"), "not-a-gaslux-vm"),
        ("anaconda-version-space", ("installer", "version"), "Anaconda 45"),
        ("anaconda-version-too-long", ("installer", "version"), "a" * 129),
        ("missing-getactions-list", ("dbus", "allowlistedMethods"), ["GetDevices"]),
        ("missing-getactions-reply", ("dbus", "replies", 0, "method"), "GetDevices"),
        (
            "forbidden-dbus-method",
            ("dbus", "allowlistedMethods"),
            ["GetActions", "GetDevices", "ApplyPartitioning"],
        ),
        ("unexpected-dbus-method", ("dbus", "replies", 0, "method"), "SetStorage"),
        ("truncated-dbus", ("dbus", "replies", 0, "truncated"), True),
        ("timedout-dbus", ("dbus", "replies", 0, "timedOut"), True),
        ("extra-permission", ("permissions", "writer"), True),
        ("false-safety-approval", ("provenance", "safetyApproved"), True),
        ("false-observer-approval", ("provenance", "observerApproved"), True),
        ("false-trust-root", ("provenance", "trustRoot"), "runner-local-key"),
        ("false-independent-proof", ("provenance", "independentlyVerified"), True),
        ("false-install-authorization", ("permissions", "installationAuthorized"), True),
        ("false-guest-authority", ("permissions", "guestCommandChannelAuthorized"), True),
    ],
)
def test_differential_a_schema_and_python_both_reject(
    iso45_schema_validator, name, path, replacement
):
    proposal = sample()
    target = proposal
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement
    assert not iso45_schema_validator.is_valid(proposal), name
    with pytest.raises(Refusal):
        validate_contract(proposal)


@pytest.mark.parametrize(
    "attack",
    [
        "host-guest-vm",
        "host-guest-guid",
        "host-guest-partuuid",
        "host-guest-offset",
        "collector-hashes",
        "dbus-response-method-not-declared",
        "dbus-digest-tampered",
        "dbus-duplicate-reply",
        "dbus-utf8-byte-limit",
        "nonce-reused-in-memory",
    ],
)
def test_differential_b_python_relationships_not_schema_authority(
    iso45_schema_validator, attack
):
    proposal = sample()
    previously_seen = frozenset()
    if attack == "host-guest-vm":
        proposal["run"]["guestVmId"] = "gaslux-bazzite-other"
    elif attack == "host-guest-guid":
        proposal["storage"]["guestDisk"]["guid"] = "88888888-2222-4333-8444-555555555555"
    elif attack == "host-guest-partuuid":
        proposal["storage"]["guestDisk"]["partitions"][0]["partuuid"] = (
            "99999999-2222-4333-8444-555555555555"
        )
    elif attack == "host-guest-offset":
        proposal["storage"]["guestDisk"]["partitions"][0]["firstSector"] += 1
    elif attack == "collector-hashes":
        proposal["collector"]["guestSha256"] = "1" * 64
    elif attack == "dbus-response-method-not-declared":
        proposal["dbus"]["replies"][0]["method"] = "GetFormatData"
    elif attack == "dbus-digest-tampered":
        proposal["dbus"]["replies"][0]["sha256"] = "0" * 64
    elif attack == "dbus-duplicate-reply":
        proposal["dbus"]["replies"].append(copy.deepcopy(proposal["dbus"]["replies"][0]))
    elif attack == "dbus-utf8-byte-limit":
        # JSON Schema maxLength counts code points; Python checks UTF-8 bytes.
        text = "é" * (1024 * 1024 // 2 + 1)
        proposal["dbus"]["replies"][0]["text"] = text
        proposal["dbus"]["replies"][0]["sha256"] = hashlib.sha256(text.encode()).hexdigest()
    elif attack == "nonce-reused-in-memory":
        previously_seen = frozenset({proposal["run"]["transaction"]})
    assert iso45_schema_validator.is_valid(proposal), attack
    with pytest.raises(Refusal):
        validate_contract(proposal, seen_transactions=previously_seen)


@pytest.mark.parametrize("pid", [2, 4321])
def test_differential_c_valid_proposal_permanently_refused(
    iso45_schema_validator, pid, tmp_path
):
    proposal = sample()
    proposal["run"]["qemuPid"] = pid
    proposal["installer"]["pid"] = pid
    assert iso45_schema_validator.is_valid(proposal)
    decision = validate_contract(proposal)
    assert decision["status"] == "REFUSED_NO_AUTHENTICATED_GUEST_COLLECTOR_CHANNEL"
    assert decision["contractOnly"] is True
    assert decision["structuralChecksPassed"] is True
    assert decision["externallyAuthenticated"] is False
    assert decision["safetyApproved"] is False
    assert decision["observerApproved"] is False
    assert decision["anacondaProcessVerified"] is False
    assert all(decision[name] is False for name in NO_WRITE)
    # Two independent CLI invocations of the same nonce: neither receives authority.
    path = tmp_path / "untrusted-claim.json"
    path.write_text(json.dumps(proposal), encoding="utf-8")
    script = ROOT / "auto_tests" / "bazzite_iso45_guest_inspection_contract.py"
    for _ in range(2):
        proc = subprocess.run(
            [sys.executable, str(script), "--proposal", str(path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        assert proc.returncode == 2
        assert json.loads(proc.stdout) == decision
