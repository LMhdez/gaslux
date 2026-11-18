#!/usr/bin/env python3
"""Bounded disposable QEMU guest write + signed snapshot recovery laboratory.

THIS IS NOT A Q4OS INSTALLER. Never modify the signed plan or authorize
Calamares, ESP, GPT, Windows, real disks, or arbitrary guest writes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets" / "live"))
sys.path.insert(0, str(ROOT / "auto_tests" / "tools"))

from gaslux_q4os_guest_disk_probe import (  # noqa: E402
    expected_virtio_serial,
    validate_guest_disk_report,
)
from gaslux_q4os_qemu_identity_lab import (  # noqa: E402
    _fsync_directory,
    _fsync_file,
    _qemu_img_info,
    _read_line,
    _verify_plan,
    _write_json_durable,
    sparse_content_sha256,
)
from gaslux_q4os_snapshot_manifest import (  # noqa: E402
    SNAPSHOT_NAME,
    verify_signed_manifest,
)
from gaslux_q4os_vm_target_plan import DISK_BYTES  # noqa: E402
from q4os_guest_identity_agent import inspect_gpt_fd  # noqa: E402

PREFLIGHT = b"GQ4OS-WRITE-PREFLIGHT-V1"
HELLO = b"GQ4OS-WRITE-HELLO-V1"
RESULT = b"GQ4OS-WRITE-RESULT-V1"
CHALLENGE = "GQ4OS-WRITE-CHALLENGE-V1"
AUTH = b"GQ4OS-WRITE-ALLOW-V1"
REPORT_DOMAIN = b"GASLUX-Q4OS-BOUND-WRITE-REPORT-V1\n"
AUTH_DOMAIN = b"GASLUX-Q4OS-BOUND-WRITE-AUTH-V1\n"
ESP_END_LBA = 1050623
ROOT_START_LBA = ESP_END_LBA + 1
WRITE_OFFSET = (ROOT_START_LBA + 2048) * 512
WRITE_BYTES = 4096
MARKER = b"\xa5" * WRITE_BYTES
MARKER_SHA = hashlib.sha256(MARKER).hexdigest()
EMPTY_SHA = hashlib.sha256(bytes(WRITE_BYTES)).hexdigest()


class BoundVmWriteRefusal(RuntimeError):
    """Fail-closed synthetic VM-only transaction error."""


def _require(ok: bool, reason: str) -> None:
    if not ok:
        raise BoundVmWriteRefusal(reason)


def _run(args: list[str], *, timeout: int = 180, expected: int = 0) -> str:
    process = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    _require(
        process.returncode == expected,
        "Command refused: " + args[0] + ": " + (process.stderr + process.stdout)[-900:],
    )
    return process.stdout


def _strict_json(raw: bytes, expected: set[str]) -> dict:
    _require(0 < len(raw) <= 16384, "Unexpected guest report length")

    def pairs(items):
        output = {}
        for name, value in items:
            _require(name not in output, "Duplicate guest report field")
            output[name] = value
        return output

    try:
        decoded = json.loads(raw.decode("ascii"), object_pairs_hook=pairs)
    except (UnicodeError, ValueError) as exc:
        raise BoundVmWriteRefusal("Unreadable guest report") from exc
    _require(type(decoded) is dict and set(decoded) == expected, "Unexpected guest report fields")
    return decoded


def _read_authenticated(stream, label: bytes, secret: str) -> tuple[dict, bytes]:
    _require(_read_line(stream, 80, "guest frame") == label, "Wrong guest report frame type")
    raw = _read_line(stream, 16384, "guest report")
    mac = _read_line(stream, 90, "guest HMAC")
    expected = (
        hmac.new(secret.encode("ascii"), REPORT_DOMAIN + label + b"\n" + raw, hashlib.sha256)
        .hexdigest()
        .encode("ascii")
    )
    _require(hmac.compare_digest(mac, expected), "Guest report HMAC rejected")
    return json.loads(raw), raw


def validate_writable_preflight(raw: bytes, *, plan: dict, serial: str) -> dict:
    """Reuse the independent read-only GPT identity contract without weakening it."""
    fields = {
        "schemaVersion",
        "runId",
        "nonce",
        "device",
        "serial",
        "sizeBytes",
        "logicalSectorBytes",
        "physicalSectorBytes",
        "diskGuid",
        "partitions",
        "blockDeviceReadOnly",
        "readOnlyProbe",
        "writeAttempted",
        "writeOffsetBytes",
        "writeLengthBytes",
        "markerBeforeSha256",
    }
    data = _strict_json(raw, fields)
    _require(data["blockDeviceReadOnly"] is False, "COW guest was unexpectedly read-only")

    _require(
        data["readOnlyProbe"] is True and data["writeAttempted"] is False,
        "Guest attempted write before authorization",
    )
    _require(
        type(data["writeOffsetBytes"]) is int
        and data["writeOffsetBytes"] == WRITE_OFFSET
        and type(data["writeLengthBytes"]) is int
        and data["writeLengthBytes"] == WRITE_BYTES,
        "Guest proposed an unbounded or foreign write",
    )
    _require(data["markerBeforeSha256"] == EMPTY_SHA, "Unallocated marker area is not empty")
    read_only_view = {
        name: value
        for name, value in data.items()
        if name in fields - {"writeOffsetBytes", "writeLengthBytes", "markerBeforeSha256"}
    }
    read_only_view["blockDeviceReadOnly"] = True
    # This transformation is ONLY to verify the same immutable GPT semantics.
    # The original guest's writable state is checked separately above and
    # never exposed to the pre-existing read-only production contract.
    canonical = json.dumps(read_only_view, sort_keys=True, separators=(",", ":")).encode()
    verified = validate_guest_disk_report(canonical, plan=plan, expected_serial=serial)
    _require(verified["guestDiskIdentityVerified"] is True, "Guest disk identity rejected")
    _require(data["diskGuid"] == plan["diskGuid"], "Guest target GUID mismatch")
    _require(data["serial"] == serial, "Wrong authenticated VirtIO serial")
    return {"serial": serial, "device": data["device"], "gptVerified": True}


def validate_write_result(raw: bytes, *, plan: dict, serial: str) -> dict:
    fields = {
        "schemaVersion",
        "runId",
        "nonce",
        "serial",
        "diskGuid",
        "writeAttempted",
        "writeCompleted",
        "writeOffsetBytes",
        "writeLengthBytes",
        "markerAfterSha256",
        "gptUnchanged",
        "calamaresExecuted",
        "windowsEspTouched",
    }
    value = _strict_json(raw, fields)
    required = {
        "schemaVersion": 1,
        "runId": plan["runId"],
        "nonce": plan["nonce"],
        "serial": serial,
        "diskGuid": plan["diskGuid"],
        "writeAttempted": True,
        "writeCompleted": True,
        "writeOffsetBytes": WRITE_OFFSET,
        "writeLengthBytes": WRITE_BYTES,
        "markerAfterSha256": MARKER_SHA,
        "gptUnchanged": True,
        "calamaresExecuted": False,
        "windowsEspTouched": False,
    }
    for key, val in required.items():
        _require(type(value[key]) is type(val) and value[key] == val, "Unsafe write result: " + key)
    return value


def validate_overlay_allocation(mapping: list[dict]) -> list[dict]:
    """Reject any COW data allocation outside the proposed root/free extent."""
    _require(type(mapping) is list and bool(mapping), "Missing COW allocation mapping")
    root_low = ROOT_START_LBA * 512
    root_high = (67106815 + 1) * 512
    extents = []
    for item in mapping:
        _require(type(item) is dict, "Bad QEMU block map")
        if item.get("depth") == 0 and item.get("data") is True:
            start, length = item.get("start"), item.get("length")
            _require(
                type(start) is int and type(length) is int and length > 0,
                "Invalid allocated guest extent",
            )
            _require(
                start >= root_low and start + length <= root_high,
                "COW write escaped owned proposed root extent",
            )
            extents.append({"start": start, "length": length})
    _require(bool(extents), "No mutated guest-owned COW block observed")
    _require(
        any(
            x["start"] <= WRITE_OFFSET and x["start"] + x["length"] >= WRITE_OFFSET + WRITE_BYTES
            for x in extents
        ),
        "Guest write was not recorded in the allowed COW extent",
    )
    return extents


def _authenticate_guest_write(
    *,
    workspace: Path,
    overlay: Path,
    kernel: Path,
    initramfs: Path,
    plan: dict,
    evidence: Path,
) -> dict:
    sock_dir = Path(tempfile.mkdtemp(prefix="gq4osw-", dir="/tmp"))
    os.chmod(sock_dir, 0o700)
    sock = sock_dir / "report.sock"
    _require(len(str(sock).encode()) < 100, "QEMU socket path too long")
    serial = expected_virtio_serial(plan)
    kvm = Path("/dev/kvm")
    accel = "kvm" if kvm.exists() and os.access(kvm, os.R_OK | os.W_OK) else "tcg"
    log = evidence / "q4os-write-qemu.log"
    guest_log = evidence / "q4os-write-guest-serial.log"
    command = [
        "qemu-system-x86_64",
        "-no-user-config",
        "-nodefaults",
        "-machine",
        f"q35,accel={accel}",
        "-cpu",
        "max",
        "-smp",
        "2",
        "-m",
        "2048",
        "-no-reboot",
        "-display",
        "none",
        "-monitor",
        "none",
        "-net",
        "none",
        "-kernel",
        str(kernel),
        "-initrd",
        str(initramfs),
        "-append",
        "console=ttyS0,115200n8 rdinit=/init panic=5 loglevel=4",
        "-serial",
        f"file:{guest_log}",
        "-drive",
        f"if=none,id=q4oswrite,file={overlay},format=qcow2,readonly=off,cache=none",
        "-device",
        f"virtio-blk-pci,drive=q4oswrite,serial={serial}",
        "-device",
        "virtio-serial-pci,id=q4osserial",
        "-chardev",
        f"socket,id=q4osreport,path={sock},server=on,wait=off",
        "-device",
        "virtserialport,chardev=q4osreport,name=org.gaslux.q4os.identity",
    ]
    process = None
    conn = None
    stream = None
    try:
        with log.open("xb") as output:
            process = subprocess.Popen(
                command,
                cwd=workspace,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                close_fds=True,
            )
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise BoundVmWriteRefusal("QEMU exited before guest auth socket")
            if sock.is_socket():
                break
            time.sleep(0.1)
        else:
            raise BoundVmWriteRefusal("QEMU write report socket missing")
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(120)
        conn.connect(str(sock))
        _require(hasattr(socket, "SO_PEERCRED"), "Peer credential support unavailable")
        pid, uid, _gid = struct.unpack(
            "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        _require(pid == process.pid and uid == os.getuid(), "Foreign QEMU report socket")
        stream = conn.makefile("rb")
        _require(
            _read_line(stream, 90, "guest hello") == HELLO,
            "Guest did not enter bounded write protocol",
        )
        secret = secrets.token_hex(32)
        challenge = f"{CHALLENGE}:{plan['runId']}:{plan['nonce']}:{secret}\n".encode("ascii")
        conn.sendall(challenge)
        _require(
            _read_line(stream, 80, "guest preflight") == PREFLIGHT,
            "Missing signed-run guest prewrite identity",
        )
        pre_raw = _read_line(stream, 16384, "guest preflight report")
        pre_mac = _read_line(stream, 90, "guest preflight mac")
        expected_pre_mac = (
            hmac.new(
                secret.encode("ascii"),
                REPORT_DOMAIN + PREFLIGHT + b"\n\n" + pre_raw,
                hashlib.sha256,
            )
            .hexdigest()
            .encode("ascii")
        )
        _require(hmac.compare_digest(pre_mac, expected_pre_mac), "Unauthenticated guest preflight")
        preflight = validate_writable_preflight(pre_raw, plan=plan, serial=serial)
        allow = b":".join(
            (AUTH, str(WRITE_OFFSET).encode(), str(WRITE_BYTES).encode(), MARKER_SHA.encode())
        )
        allow_mac = (
            hmac.new(secret.encode("ascii"), AUTH_DOMAIN + allow, hashlib.sha256)
            .hexdigest()
            .encode("ascii")
        )
        conn.sendall(allow + b":" + allow_mac + b"\n")
        _require(
            _read_line(stream, 80, "guest write result") == RESULT,
            "Guest did not return final bounded-write report",
        )
        post_raw = _read_line(stream, 16384, "guest write JSON")
        post_mac = _read_line(stream, 90, "guest write HMAC")
        expected_post_mac = (
            hmac.new(
                secret.encode("ascii"), REPORT_DOMAIN + RESULT + b"\n\n" + post_raw, hashlib.sha256
            )
            .hexdigest()
            .encode("ascii")
        )
        _require(
            hmac.compare_digest(post_mac, expected_post_mac), "Unauthenticated guest write report"
        )
        verified = validate_write_result(post_raw, plan=plan, serial=serial)
        process.wait(timeout=50)
        _require(process.returncode == 0, "QEMU guest did not shut down successfully")
        _require(not stream.read(1), "Unexpected trailing guest output")
        log_text = guest_log.read_text(encoding="utf-8", errors="replace")
        _require(
            "GASLUX_Q4OS_BOUND_GUEST_WRITE=PASS" in log_text,
            "Missing guest serial evidence of the bounded write",
        )
        return {
            "guestDiskIdentityVerified": preflight["gptVerified"],
            "transportPeerBoundToQemuPid": True,
            "transportAuthenticated": True,
            "guestAttestation": False,
            "guestWriteCompleted": verified["writeCompleted"],
            "qemuGuestShutdownObserved": True,
            "qemuNetworkAttached": False,
            "qemuPhysicalDiskAttached": False,
            "qemuAcceleration": accel,
            "reportSha256": hashlib.sha256(post_raw).hexdigest(),
            "qemuProcessId": pid,
            "writeOffsetBytes": WRITE_OFFSET,
            "writeLengthBytes": WRITE_BYTES,
        }
    finally:
        if stream is not None:
            stream.close()
        if conn is not None:
            conn.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        try:
            sock.unlink(missing_ok=True)
            sock_dir.rmdir()
        except OSError:
            pass


def _verify_prewrite_snapshot(
    snapshot_dir: Path, plan: dict, raw_plan: bytes, backing: Path
) -> tuple[Path, dict]:
    _require(
        snapshot_dir.is_absolute() and snapshot_dir.is_dir() and not snapshot_dir.is_symlink(),
        "Missing private snapshot directory",
    )
    manifest_path = snapshot_dir / "q4os-recovery-snapshot-manifest.json"
    manifest = verify_signed_manifest(
        manifest_path.read_bytes(),
        (snapshot_dir / "q4os-recovery-snapshot-manifest.ed25519").read_bytes(),
        (snapshot_dir / "q4os-recovery-snapshot-public-key.bin").read_bytes(),
        (snapshot_dir / "q4os-recovery-snapshot-public-key.sha256").read_text().strip(),
    )
    _require(
        manifest["planSha256"] == hashlib.sha256(raw_plan).hexdigest()
        and manifest["runId"] == plan["runId"]
        and manifest["nonce"] == plan["nonce"],
        "Recovery snapshot is not bound to signed plan",
    )
    snapshot = snapshot_dir / SNAPSHOT_NAME
    _require(
        snapshot.is_file() and not snapshot.is_symlink() and snapshot.stat().st_nlink == 1,
        "Unowned recovery snapshot",
    )
    info = _qemu_img_info(snapshot)
    _require(
        info.get("format") == "qcow2"
        and info.get("virtual-size") == DISK_BYTES
        and info.get("backing-filename") in (None, ""),
        "Recovery snapshot is not self-contained",
    )
    actual_hash = hashlib.sha256()
    with snapshot.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            actual_hash.update(chunk)
    _require(
        actual_hash.hexdigest() == manifest["snapshotSha256"], "Recovery snapshot SHA-256 mismatch"
    )
    _run(["qemu-img", "check", str(snapshot)], timeout=120)
    _run(
        ["qemu-img", "compare", "-f", "qcow2", "-F", "raw", str(snapshot), str(backing)],
        timeout=600,
    )
    return snapshot, manifest


def _restore_verified_snapshot(
    *,
    workspace: Path,
    snapshot: Path,
    base: Path,
    expected_plan: dict,
) -> bool:
    restored = workspace / "q4os-write-restored.raw"
    _require(
        not restored.exists() and not restored.is_symlink(), "Recovery destination already exists"
    )
    try:
        _run(
            [
                "qemu-img",
                "convert",
                "-f",
                "qcow2",
                "-O",
                "raw",
                "-S",
                "4k",
                str(snapshot),
                str(restored),
            ],
            timeout=600,
        )
        _fsync_file(restored)
        _fsync_directory(workspace)
        _run(
            ["qemu-img", "compare", "-f", "raw", "-F", "raw", str(base), str(restored)], timeout=600
        )
        _run(["sgdisk", "--verify", str(restored)], timeout=60)
        with restored.open("rb") as stream:
            gpt = inspect_gpt_fd(stream.fileno(), disk_size_bytes=DISK_BYTES, sector_bytes=512)
            marker = os.pread(stream.fileno(), WRITE_BYTES, WRITE_OFFSET)
        _require(
            gpt["diskGuid"] == expected_plan["diskGuid"]
            and len(gpt["partitions"]) == 1
            and gpt["partitions"][0]["partGuid"] == expected_plan["espGuid"],
            "Restored GPT failed signed target identity",
        )
        _require(marker == bytes(WRITE_BYTES), "Recovered snapshot retained guest scratch mutation")
        return True
    finally:
        if restored.exists() and restored.is_file() and not restored.is_symlink():
            restored.unlink()
            _fsync_directory(workspace)


def run_lab(
    workspace: Path,
    plan_dir: Path,
    snapshot_dir: Path,
    evidence: Path,
    kernel: Path,
    initramfs: Path,
) -> dict:
    _require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GASLUX_Q4OS_SYNTHETIC_WRITE_LAB_ONLY") == "yes",
        "Explicit synthetic QEMU-only write lab opt-in required",
    )
    _require(
        all(
            p.is_absolute() and p.exists() and not p.is_symlink()
            for p in (workspace, plan_dir, snapshot_dir, kernel, initramfs)
        ),
        "Invalid owner-controlled QEMU write inputs",
    )
    _require(
        workspace.is_dir() and workspace.stat().st_uid == os.getuid(),
        "QEMU owner workspace mismatch",
    )
    _require(
        not evidence.exists() and not evidence.is_symlink(), "QEMU recovery evidence path exists"
    )
    plan, raw_plan, verification = _verify_plan(workspace, plan_dir)
    _require(
        plan["runId"] == "q4os-actions-" + os.environ.get("GITHUB_RUN_ID", ""),
        "Signed plan is not from current Actions run",
    )
    _require(
        verification["signatureVerified"] and verification["gptMetadataVerified"],
        "Unsigned host disk",
    )
    _require(
        plan["installationAuthorized"] is False
        and plan["calamaresJobsAuthorized"] is False
        and plan["windowsEspWritesAuthorized"] is False,
        "Signed plan granted production writes",
    )
    base = workspace / "efi-disk.img"
    snapshot, manifest = _verify_prewrite_snapshot(snapshot_dir, plan, raw_plan, base)
    checkpoint = evidence / "q4os-bounded-write-recovery-checkpoint.json"
    overlay = workspace / "q4os-bound-write-only.qcow2"
    _require(
        not overlay.exists() and not overlay.is_symlink(), "Bound-write overlay already exists"
    )
    base_before = sparse_content_sha256(base)
    _require(
        base_before == manifest["baseImageSparseSha256Before"],
        "Prewrite base no longer matches durable snapshot",
    )
    _require(
        os.stat(base).st_nlink == 1 and os.stat(base).st_size == DISK_BYTES,
        "Base disk ownership mismatch",
    )
    evidence.mkdir(mode=0o700)
    checkpoint_state = {
        "schemaVersion": 1,
        "operation": "isolated-qemu-4k-cow-scratch",
        "runId": plan["runId"],
        "planSha256": hashlib.sha256(raw_plan).hexdigest(),
        "snapshotSha256": manifest["snapshotSha256"],
        "baseImageSparseSha256": base_before,
        "guestWritesAuthorized": False,
        "authorizedOffsetBytes": WRITE_OFFSET,
        "authorizedLengthBytes": WRITE_BYTES,
        "guestDiskIdentityVerified": False,
        "guestWriteObserved": False,
        "syntheticWriteRecoveredVerified": False,
        "rollbackVerified": False,
        "calamaresJobsAuthorized": False,
        "windowsEspWritesAuthorized": False,
        "productionDiskWritesAuthorized": False,
    }
    _write_json_durable(checkpoint, checkpoint_state)
    success = False
    try:
        _run(
            ["qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", str(base), str(overlay)],
            timeout=60,
        )
        info = _qemu_img_info(overlay)
        _require(
            info.get("format") == "qcow2"
            and info.get("virtual-size") == DISK_BYTES
            and info.get("backing-filename") == str(base)
            and info.get("backing-filename-format") == "raw",
            "Unsafe COW image backing chain",
        )
        _run(["qemu-img", "check", str(overlay)])
        _fsync_file(overlay)
        _fsync_directory(workspace)
        _run(
            [
                "qemu-io",
                "-f",
                "qcow2",
                "-c",
                f"read -P 0x00 {WRITE_OFFSET} {WRITE_BYTES}",
                str(overlay),
            ]
        )
        # The snapshot and private overlay are durable BEFORE arming the write.
        checkpoint_state["guestWritesAuthorized"] = True
        checkpoint_state["snapshotDurableBeforeWrite"] = True
        _write_json_durable(checkpoint, checkpoint_state)
        observed = _authenticate_guest_write(
            workspace=workspace,
            overlay=overlay,
            kernel=kernel,
            initramfs=initramfs,
            plan=plan,
            evidence=evidence,
        )
        checkpoint_state["guestDiskIdentityVerified"] = observed["guestDiskIdentityVerified"]
        _run(["qemu-img", "check", str(overlay)])
        _run(
            [
                "qemu-io",
                "-f",
                "qcow2",
                "-c",
                f"read -P 0xa5 {WRITE_OFFSET} {WRITE_BYTES}",
                str(overlay),
            ]
        )
        allocation = validate_overlay_allocation(
            json.loads(_run(["qemu-img", "map", "--output=json", "-f", "qcow2", str(overlay)]))
        )
        _run(
            ["qemu-img", "compare", "-f", "qcow2", "-F", "raw", str(overlay), str(base)],
            expected=1,
            timeout=600,
        )
        checkpoint_state["guestWriteObserved"] = True
        _write_json_durable(checkpoint, checkpoint_state)
        _require(
            sparse_content_sha256(base) == base_before,
            "Immutable backing changed after guest scratch write",
        )
        _verify_plan(workspace, plan_dir)
        _require(
            _restore_verified_snapshot(
                workspace=workspace,
                snapshot=snapshot,
                base=base,
                expected_plan=plan,
            ),
            "Snapshot did not recover expected original bytes",
        )
        _require(
            sparse_content_sha256(base) == base_before,
            "Base image differs after independent recovery",
        )
        overlay.unlink()
        _fsync_directory(workspace)
        _require(not overlay.exists(), "Guest COW overlay was not discarded")
        _verify_plan(workspace, plan_dir)
        checkpoint_state["guestWritesAuthorized"] = False
        checkpoint_state["syntheticWriteRecoveredVerified"] = True
        _write_json_durable(checkpoint, checkpoint_state)
        result = {
            **checkpoint_state,
            **observed,
            "cowModifiedOnlyInProposedRootExtent": True,
            "cowAllocatedExtents": allocation,
            "overlayDiscarded": True,
            "baseImageUnchanged": True,
            "snapshotRestoredAndCompared": True,
            "guestBlockWriteBytes": WRITE_BYTES,
            "calamaresExecuted": False,
            "windowsDiskAttached": False,
            "guestAttestation": False,
            "installationAuthorized": False,
            "rollbackVerified": False,
        }
        _write_json_durable(evidence / "q4os-bounded-write-recovery-result.json", result)
        success = True
        print("GASLUX_Q4OS_QEMU_GUEST_BOUND_WRITE=PASS", flush=True)
        print("GASLUX_Q4OS_QEMU_COW_REAL_MUTATION=PASS", flush=True)
        print("GASLUX_Q4OS_QEMU_SNAPSHOT_RESTORE=PASS", flush=True)
        print("GASLUX_Q4OS_QEMU_BASE_AND_GPT_UNCHANGED=PASS", flush=True)
        print("GASLUX_Q4OS_CALAMARES_EXECUTED=FALSE", flush=True)
        print("GASLUX_Q4OS_WINDOWS_DISK_ATTACHED=FALSE", flush=True)
        print("GASLUX_Q4OS_FULL_ROLLBACK_VERIFIED=FALSE", flush=True)
        return result
    finally:
        if not success and overlay.exists() and overlay.is_file() and not overlay.is_symlink():
            # Failure compensation: only this exact transaction-owned overlay.
            # A failed discard or base validation is a hard failure, never success.
            overlay.unlink()
            _fsync_directory(workspace)
            _require(
                sparse_content_sha256(base) == base_before,
                "Failure compensation did not preserve original base",
            )
            checkpoint_state["guestWritesAuthorized"] = False
            _write_json_durable(checkpoint, checkpoint_state)


def main() -> int:
    if len(sys.argv) != 7:
        print("REFUSED: WORKSPACE PLAN_DIR SNAPSHOT_DIR EVIDENCE KERNEL INITRAMFS", file=sys.stderr)
        return 2
    try:
        run_lab(*(Path(p) for p in sys.argv[1:]))
    except (BoundVmWriteRefusal, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"GASLUX_Q4OS_BOUNDED_VM_WRITE_REFUSED={exc}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
