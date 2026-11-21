"""One disposable QEMU/libguestfs GPT read-only collection and Safety-v1 diagnostic.

Safety source is checked out at an exact SHA in a separate tree. Uses its GPT
validator and guest reconstruction helpers. The signed v1 state is ONLY a
same-runner laboratory envelope; never a guest attestation or production receipt.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .gpt_readonly_producer import (
    GptProducerRefused,
    GuestSliceProof,
    build_safety_v1,
    capture_gpt,
    require,
)
from .lab_identity import process_seal
from .remote_verifier import (
    InMemoryReplayGuard,
    RemoteResponseVerifier,
    TrustedController,
    TrustStore,
)

SAFETY_COMMIT = "0be04192acd542646a5b6cd952e01620379edf5d"
SIZE = 64 * 1024 * 1024
SECTOR = 512


def sha_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            value.update(block)
    return value.hexdigest()


def install_pinned_safety(safety_root: Path):
    """Import existing Safety parser/reader without copying any Safety source."""
    root = safety_root.resolve(strict=True)
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    require(result.stdout.strip() == SAFETY_COMMIT, "SAFETY_SOURCE_HEAD_MISMATCH")
    require(
        (root / "assets/live/libertix_disk_identity_gate.py").is_file()
        and (root / "auto_tests/tools/safety_qemu_gpt_host_guest.py").is_file()
        and (root / "schemas/safety-gpt-provenance-v1.schema.json").is_file(),
        "SAFETY_MODULES_MISSING",
    )
    sys.path.insert(0, str(root / "assets/live"))
    sys.path.insert(0, str(root / "auto_tests/tools"))
    disk = importlib.import_module("libertix_disk_identity_gate")
    lab = importlib.import_module("safety_qemu_gpt_host_guest")
    provenance = importlib.import_module("libertix_gpt_provenance")
    adapter = importlib.import_module("libertix_safety_observer_adapter")
    return disk, lab, provenance, adapter


def _nonce() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")


def _signed_response(
    signer: Ed25519PrivateKey,
    trusted: TrustedController,
    request: dict,
    *,
    session_id: str,
    qemu: dict,
    observed_at: datetime,
    result: dict,
) -> dict:
    response = {
        "protocol": 1,
        "operation": request["operation"],
        "status": "ok",
        "session_id": session_id,
        "transaction_id": request["transaction_id"],
        "request_id": request["request_id"],
        "request_sha256": hashlib.sha256(rfc8785.dumps(request)).hexdigest(),
        "nonce": request["nonce"],
        "sequence": request["sequence"],
        "issued_at": observed_at.isoformat(),
        "expires_at": (observed_at + timedelta(seconds=20)).isoformat(),
        "controller": {
            "controller_id": trusted.controller_id,
            "key_id": trusted.key_id,
            "artifact_sha256": trusted.controller_artifact_sha256,
            "policy_sha256": trusted.policy_sha256,
        },
        "collector": {
            "collector_id": trusted.collector_id,
            "artifact_sha256": trusted.collector_artifact_sha256,
        },
        "guest": {
            "vm_uuid": trusted.vm_uuid,
            "identity_assurance": "host-observed",
            "qemu_process": {
                "pid": qemu["pid"],
                "start_ticks": qemu["startTicks"],
                "executable_sha256": qemu["executableSha256"],
            },
            "distribution": {
                "id": trusted.distribution_id,
                "version": trusted.distribution_version,
                "iso_sha256": trusted.iso_sha256,
                "installer_id": trusted.installer_id,
            },
            "attestation": {
                "status": "not-provided",
                "evidence_sha256": None,
                "verifier_id": None,
                "trust_anchor_id": None,
            },
        },
        "result": result,
        "result_sha256": hashlib.sha256(rfc8785.dumps(result)).hexdigest(),
    }
    signature = signer.sign(rfc8785.dumps(response))
    response["signature"] = {
        "algorithm": "Ed25519",
        "key_id": trusted.key_id,
        "value": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }
    return response


def lab_only_state_result(gpt: dict, chain: dict, qemu: dict, label: str) -> tuple[dict, dict]:
    """Verify v1 Ed25519 messages from a same-runner ephemeral key; NOT guest trust."""
    signer = Ed25519PrivateKey.generate()
    public = signer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    vm_uuid = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    trusted = TrustedController(
        key_id="lab-only-generated-key",
        public_key_raw=public,
        controller_id="lab-only-controller",
        controller_artifact_sha256=hashlib.sha256(b"LAB_ONLY").hexdigest(),
        policy_sha256=hashlib.sha256(b"LAB_ONLY_POLICY").hexdigest(),
        collector_id="lab-only-collector",
        collector_artifact_sha256=sha_file(Path(__file__).resolve()),
        vm_uuid=vm_uuid,
        qemu_executable_sha256=qemu["executableSha256"],
        distribution_id="synthetic",
        distribution_version="gpt-readonly",
        iso_sha256="0" * 64,
        installer_id="none",
        attestation_verifier_id="none",
        attestation_trust_anchor_id="none",
    )
    verifier = RemoteResponseVerifier(
        TrustStore({trusted.key_id: trusted}),
        InMemoryReplayGuard(),
        require_guest_attestation=False,
    )
    now = datetime.now(UTC)

    def request(op: str, sequence: int, nonce: str) -> dict:
        return {
            "protocol": 1,
            "operation": op,
            "session_id": None if sequence == 0 else session_id,
            "transaction_id": transaction_id,
            "request_id": str(uuid.uuid4()),
            "nonce": nonce,
            "sequence": sequence,
            "timeout_ms": 5000,
            "max_response_bytes": 1048576,
        }

    initial = request("session.identify", 0, _nonce())
    initial_result = {
        "kind": "session",
        "closed": False,
        "session_expires_at": (now + timedelta(minutes=5)).isoformat(),
    }
    signed_initial = _signed_response(
        signer,
        trusted,
        initial,
        session_id=session_id,
        qemu=qemu,
        observed_at=now,
        result=initial_result,
    )
    verifier.verify(
        initial,
        signed_initial,
        deadline=now + timedelta(seconds=4),
        now=now,
    )
    observed = request("state.read", 1, _nonce())
    state_result = {
        "kind": "state",
        "observed_at": now.isoformat(),
        "snapshot": {
            "safety": {
                "trust_boundary": "NOT_INDEPENDENT",
                "mode": "read-only",
                "gpt": gpt,
                "qcow2": {
                    "format": "qcow2",
                    "backingFormat": "raw",
                    "backingFilename": chain["backingFilename"],
                    "backingSha256": chain["backingSha256"],
                    "overlaySha256": chain["overlaySha256"],
                    "virtualSerial": label,
                    "virtualSizeBytes": chain["virtualSizeBytes"],
                },
            }
        },
    }
    signed_observed = _signed_response(
        signer,
        trusted,
        observed,
        session_id=session_id,
        qemu=qemu,
        observed_at=now,
        result=state_result,
    )
    verified = verifier.verify(
        observed,
        signed_observed,
        deadline=now + timedelta(seconds=4),
        now=now,
    )
    require(
        verified.controller_signature_verified
        and verified.guest_attestation_verified_locally is False
        and verified.result_sha256 == signed_observed["result_sha256"],
        "LAB_SIGNED_RESULT_INVALID",
    )
    return (
        {
            "trusted": trusted,
            "request": observed,
            "response": signed_observed,
            "verified_result_sha256": verified.result_sha256,
        },
        {"vmUuid": vm_uuid, "transactionId": transaction_id, "sessionId": session_id},
    )


def _save_json(folder: Path, filename: str, record: dict) -> str:
    payload = json.dumps(record, sort_keys=True, indent=2, ensure_ascii=True).encode() + b"\n"
    require(len(payload) <= 512 * 1024, "EVIDENCE_OVERSIZED")
    fd = os.open(
        folder / filename,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    return hashlib.sha256(payload).hexdigest()


def _qemu_executable_hash(pid: int) -> str:
    require(pid > 1, "QEMU_PID_INVALID")
    fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        digest = hashlib.sha256()
        while True:
            value = os.read(fd, 1024 * 1024)
            if not value:
                break
            digest.update(value)
        return digest.hexdigest()
    finally:
        os.close(fd)


def experiment(workspace: Path, evidence: Path, safety_root: Path) -> dict:
    """Boot one guestfs appliance and collect three genuine read-only GPT samples."""
    disk, lab, provenance, adapter = install_pinned_safety(safety_root)
    base, overlay = workspace / "base.raw", workspace / "overlay.qcow2"
    lab.make_raw(base, workspace, disk_guid=str(uuid.uuid4()), part_guid=str(uuid.uuid4()))
    base_stat = lab.own_regular(base, workspace)
    lab.make_qcow(overlay, base, workspace)
    overlay_stat = lab.own_regular(overlay, workspace)
    chain_before = lab.verify_chain(overlay, base, workspace)
    lab.host_snapshot(overlay, workspace / "host.raw", workspace)
    label = "gaslux" + "".join(secrets.choice("abcdef") for _ in range(12))
    require(os.environ.get("LIBGUESTFS_BACKEND") == "direct", "GUEST_BACKEND_UNAVAILABLE")
    try:
        import guestfs
    except ImportError as exc:
        raise GptProducerRefused("GUEST_READ_CHANNEL_UNAVAILABLE") from exc
    appliance = guestfs.GuestFS(python_return_dict=True)
    qemu = None
    try:
        appliance.set_backend("direct")
        appliance.add_drive_opts(str(overlay), format="qcow2", readonly=1, label=label)
        appliance.launch()
        devs = appliance.list_devices()
        guest_dev = "/dev/disk/guestfs/" + label
        require(len(devs) == 1, "AMBIGUOUS_GUEST_DISKS")
        require(
            appliance.blockdev_getsize64(guest_dev) == SIZE
            and appliance.blockdev_getsize64(devs[0]) == SIZE,
            "GUEST_GEOMETRY_DIVERGENT",
        )
        require(appliance.blockdev_getss(guest_dev) == SECTOR, "GUEST_SECTOR_DIVERGENT")
        pid = int(appliance.get_pid())
        before_process = process_seal(pid)
        lab_pid_identity = lab.qemu_identity(pid, overlay)
        require(lab_pid_identity["qcow2Attached"] is True, "QEMU_OVERLAY_NOT_ATTACHED")
        executable_sha = _qemu_executable_hash(pid)
        qemu = {
            "pid": pid,
            "startTicks": before_process.start_ticks,
            "uid": before_process.uid,
            "executableSha256": executable_sha,
            "commandSha256": before_process.command_sha256,
            "executableDev": before_process.executable_dev,
            "executableInode": before_process.executable_ino,
            "qemuKvmObserved": lab_pid_identity["kvmDeviceOpen"],
            "virtualSerialClaim": label,
            "virtualSerialHardwareVerified": False,
            "vmUuidReadFromQmp": False,
            "qmpSessionObserved": False,
        }
        host = capture_gpt(
            workspace / "host.raw",
            workspace,
            source="host",
            logical_sector_size=SECTOR,
            safety_disk=disk,
        )
        first = appliance.pread_device(guest_dev, lab.GUEST_SLICE, 0)
        last = appliance.pread_device(guest_dev, lab.GUEST_SLICE, SIZE - lab.GUEST_SLICE)
        lab.reconstruct_guest_sample(
            first, last, SIZE, workspace / "guest-reconstructed.raw", workspace
        )
        guest = capture_gpt(
            workspace / "guest-reconstructed.raw",
            workspace,
            source="guest",
            logical_sector_size=SECTOR,
            safety_disk=disk,
            guest_sample_origin=GuestSliceProof(
                first, last, label, pid, before_process.start_ticks
            ),
        )
        require(process_seal(pid) == before_process, "QEMU_PROCESS_CHANGED")
        require(_qemu_executable_hash(pid) == executable_sha, "QEMU_EXECUTABLE_CHANGED")
    finally:
        appliance.close()
    require(qemu is not None, "QEMU_IDENTITY_MISSING")
    for _ in range(30):
        if not (Path("/proc") / str(qemu["pid"])).exists():
            break
        time.sleep(0.1)
    require(not (Path("/proc") / str(qemu["pid"])).exists(), "QEMU_PROCESS_NOT_TERMINATED")
    lab.same_file(base, workspace, base_stat)
    lab.same_file(overlay, workspace, overlay_stat)
    require(lab.verify_chain(overlay, base, workspace) == chain_before, "BACKING_CHANGED")
    require(
        sha_file(base) == chain_before["backingSha256"]
        and sha_file(overlay) == chain_before["overlaySha256"],
        "BACKING_HASH_CHANGED",
    )
    # A new, independently exported read of the unchanged QCOW2 is mandatory.
    # Never re-label the earlier host.raw copy as an immediate live observation.
    lab.host_snapshot(overlay, workspace / "immediate.raw", workspace)
    immediate = capture_gpt(
        workspace / "immediate.raw",
        workspace,
        source="immediate",
        logical_sector_size=SECTOR,
        safety_disk=disk,
    )
    lab.same_file(base, workspace, base_stat)
    lab.same_file(overlay, workspace, overlay_stat)
    require(
        sha_file(base) == chain_before["backingSha256"]
        and sha_file(overlay) == chain_before["overlaySha256"],
        "BACKING_CHANGED_AFTER_IMMEDIATE",
    )
    captures = (host, guest, immediate)
    require(
        all(c.gpt == host.gpt and c.sectors == host.sectors for c in captures),
        "THREE_WAY_GPT_MISMATCH",
    )
    signed, context = lab_only_state_result(host.gpt, chain_before, qemu, label)
    pins = adapter.SafetyObserverPins(
        transaction_id=context["transactionId"],
        vm_uuid=context["vmUuid"],
        request_id=signed["request"]["request_id"],
        session_id=context["sessionId"],
        nonce=signed["request"]["nonce"],
        sequence=1,
        observer_key_id=signed["trusted"].key_id,
        controller_id=signed["trusted"].controller_id,
        collector_id=signed["trusted"].collector_id,
        qemu_pid=qemu["pid"],
        qemu_start_ticks=qemu["startTicks"],
        plan_sha256=hashlib.sha256(b"LAB_NO_PLAN").hexdigest(),
        backing_filename=chain_before["backingFilename"],
        backing_sha256=chain_before["backingSha256"],
        overlay_sha256=chain_before["overlaySha256"],
        virtual_serial=label,
        disk_id=host.gpt["partitionTableId"],
        virtual_size_bytes=SIZE,
    )
    o, parent = overlay_stat, base_stat
    authority = provenance.ProvenanceAuthority(
        issuer_id="lab-local-untrusted-issuer",
        observer_id="lab-local-readonly-observer",
        collector_id=pins.collector_id,
        controller_id=pins.controller_id,
        policy_id="lab-only-pcr-not-verified",
        policy_sha256=hashlib.sha256(b"LAB_ONLY_GPT_POLICY").hexdigest(),
        signing_key_id=pins.observer_key_id,
        administrative_domain="same-github-runner",
        qemu_executable_sha256=qemu["executableSha256"],
        device_id="guestfs-label:" + label,
        overlay_path=str(overlay),
        overlay_device_id="dev:" + str(o.st_dev),
        overlay_inode=o.st_ino,
        parent_device_id="dev:" + str(parent.st_dev),
        parent_inode=parent.st_ino,
    )
    statement = build_safety_v1(
        captures,
        pins=pins,
        authority=authority,
        logical_sector_size=SECTOR,
        expected_observer_result_sha256=signed["verified_result_sha256"],
        schema_path=safety_root / "schemas/safety-gpt-provenance-v1.schema.json",
    )
    # The Safety evaluator must not infer independent origin from this record.
    assessment = provenance.assess_gpt_provenance_v1(
        statement,
        pins=pins,
        authority=authority,
        expected_observer_result_sha256=signed["verified_result_sha256"],
        host_gpt=host.gpt,
        guest_gpt=guest.gpt,
        immediate_gpt=immediate.gpt,
        now=datetime.now(UTC),
    )
    require(
        assessment.result == "DIAGNOSTIC_ONLY"
        and assessment.classification == "NOT_INDEPENDENT"
        and assessment.production_write_authorized is False
        and assessment.origin_independently_attested is False,
        "SAFETY_DIAGNOSTIC_ESCALATION",
    )
    hashes = {
        "safety-gpt-provenance-v1.json": _save_json(
            evidence, "safety-gpt-provenance-v1.json", statement
        ),
        "host-read-trace.json": _save_json(evidence, "host-read-trace.json", host.trace),
        "guest-read-trace.json": _save_json(evidence, "guest-read-trace.json", guest.trace),
        "immediate-read-trace.json": _save_json(
            evidence, "immediate-read-trace.json", immediate.trace
        ),
    }
    result = {
        "status": "LABORATORY_ONLY",
        "classification": "NOT_INDEPENDENT",
        "safetyAssessment": assessment.result,
        "productionWriteAuthorized": False,
        "guestInputAuthorized": False,
        "independentAttestationVerified": False,
        "remoteGuestAttestationVerifiedLocally": False,
        "remoteStateSignedWithEphemeralRunnerKey": True,
        "remoteStateControllerIsIndependent": False,
        "remoteSafetyAdapterProductionAccepted": False,
        "processPidMeasured": True,
        "processStartTicksMeasured": True,
        "processExecutableSha256Measured": True,
        "virtualSerialHardwareVerified": False,
        "vmUuidReadFromQmp": False,
        "hostCapturedFromExportedQcow2RawImage": True,
        "immediateCapturedFromFreshQcow2Export": True,
        "immediateQemuProcessAlreadyTerminated": True,
        "guestCapturedWithLibguestfsPreadDevice": True,
        "guestCaptureAuthentication": "same-runner-readonly-not-independent",
        "snapshotCaptureSource": "real-qemu-libguestfs",
        "sourceCommitSafety": SAFETY_COMMIT,
        "backingChain": chain_before,
        "backingChainSha256": hashlib.sha256(rfc8785.dumps(chain_before)).hexdigest(),
        "qemu": qemu,
        "gpt": host.gpt,
        "measurements": [
            {"source": c.source, "time": c.observed_at, "traceSha256": c.trace_sha256}
            for c in captures
        ],
        "fileSha256": hashes,
        "diskSynthetic": True,
        "windowsGenuine": False,
        "qemuProcessTerminated": True,
        "backingPreserved": True,
        "overlayPreserved": True,
        "diskWriterCalled": False,
        "guestInputs": 0,
    }
    result["manifestSha256"] = _save_json(evidence, "manifest.json", result)
    return result


def main() -> int:
    require(os.environ.get("GITHUB_ACTIONS") == "true", "NOT_AUTHORIZED_LAB_RUNNER")
    require(os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux", "WRONG_LAB_REPOSITORY")
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "UNTRUSTED_LAB_HOST")
    require(os.name == "posix" and os.geteuid() != 0, "PRIVILEGED_PRODUCER_FORBIDDEN")
    require(Path("/dev/kvm").exists(), "KVM_UNAVAILABLE")
    workspace_root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    evidence = Path(os.environ["GASLUX_GPT_EVIDENCE"]).resolve(strict=True)
    safety_root = Path(os.environ["GASLUX_PINNED_SAFETY"]).resolve(strict=True)
    require(evidence != workspace_root and evidence.is_dir(), "EVIDENCE_DIR_UNSAFE")
    with tempfile.TemporaryDirectory(prefix="gaslux-gpt-observer-", dir=workspace_root) as work:
        result = experiment(Path(work), evidence, safety_root)
    result["ephemeralDiskRemoved"] = True
    print(
        json.dumps(
            {
                "status": result["status"],
                "classification": result["classification"],
                "diagnostic": result["safetyAssessment"],
                "guestRealPread": result["guestCapturedWithLibguestfsPreadDevice"],
                "guestInputCount": result["guestInputs"],
                "writerCalled": result["diskWriterCalled"],
                "ephemeralDiskRemoved": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "BLOCKED_FAIL_CLOSED",
                    "error": type(exc).__name__,
                    "reason": str(exc)[:250],
                    "productionWriteAuthorized": False,
                    "guestInputAuthorized": False,
                    "classification": "NOT_INDEPENDENT",
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(2) from exc
