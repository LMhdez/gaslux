#!/usr/bin/env python3
"""QEMU-only Q4OS guest identity, private virtio-serial and read-only checkpoint lab."""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import os
import secrets
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets" / "live"))
sys.path.insert(0, str(ROOT / "auto_tests" / "tools"))

from gaslux_q4os_guest_disk_probe import (  # noqa: E402
    expected_virtio_serial,
    validate_guest_disk_report,
)
from gaslux_q4os_vm_target_plan import (  # noqa: E402
    Q4osPlanRefusal,
    verify_signed_plan_against_disk,
)

MAC_DOMAIN = b"GASLUX-Q4OS-GUEST-REPORT-V1\n"
HELLO = b"GQ4OS-HELLO-V1"
REPORT_MAGIC = b"GQ4OS-REPORT-V1"
CHALLENGE_MAGIC = "GQ4OS-CHALLENGE-V1"
MAX_REPORT_BYTES = 16384
DISK_BYTES = 32 * 1024**3


class Q4osQemuLabRefusal(RuntimeError):
    """A Q4OS QEMU identity or recovery-checkpoint condition was not met."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise Q4osQemuLabRefusal(message)


def sparse_content_sha256(path: Path) -> str:
    """Hash a sparse file's logical size, data extents, offsets and exact bytes."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode), "Checkpoint image is not a regular file")
        digest = hashlib.sha256()
        digest.update(b"GASLUX-SPARSE-FILE-V1\n")
        digest.update(struct.pack(">Q", info.st_size))
        position = 0
        use_sparse = hasattr(os, "SEEK_DATA") and hasattr(os, "SEEK_HOLE")
        while use_sparse and position < info.st_size:
            try:
                data_start = os.lseek(fd, position, os.SEEK_DATA)
            except OSError as exc:
                if exc.errno == errno.ENXIO:
                    break
                if exc.errno in (errno.EINVAL, errno.ENOTSUP, errno.ENOSYS):
                    use_sparse = False
                    break
                raise
            try:
                hole_start = os.lseek(fd, data_start, os.SEEK_HOLE)
            except OSError as exc:
                if exc.errno in (errno.EINVAL, errno.ENOTSUP, errno.ENOSYS):
                    use_sparse = False
                    break
                raise
            _require(hole_start > data_start, "Invalid sparse-file extent")
            digest.update(struct.pack(">QQ", data_start, hole_start - data_start))
            cursor = data_start
            while cursor < hole_start:
                chunk = os.pread(fd, min(8 * 1024 * 1024, hole_start - cursor), cursor)
                _require(bool(chunk), "Checkpoint image was truncated while hashing")
                digest.update(chunk)
                cursor += len(chunk)
            position = hole_start
        if not use_sparse:
            digest = hashlib.sha256()
            digest.update(b"GASLUX-FULL-FILE-V1\n")
            digest.update(struct.pack(">Q", info.st_size))
            position = 0
            while position < info.st_size:
                chunk = os.pread(fd, min(8 * 1024 * 1024, info.st_size - position), position)
                _require(bool(chunk), "Checkpoint image was truncated while hashing")
                digest.update(chunk)
                position += len(chunk)
        return digest.hexdigest()
    finally:
        os.close(fd)


def _fsync_file(path: Path) -> None:
    fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_then_chmod(path: Path, mode: int) -> None:
    fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
        os.chmod(path, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_json_durable(path: Path, value: dict[str, Any]) -> None:
    payload = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    temporary = path.with_name(path.name + ".tmp")
    _require(not temporary.exists() and not temporary.is_symlink(), "Checkpoint temp path exists")
    with temporary.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    _fsync_file(path)
    _fsync_directory(path.parent)
    _require(path.read_bytes() == payload, "Durable checkpoint read-back mismatch")


def verify_authenticated_report(
    report_raw: bytes,
    mac_hex: str,
    *,
    challenge_secret: str,
    plan: dict[str, Any],
) -> dict[str, Any]:
    if len(report_raw) == 0 or len(report_raw) > MAX_REPORT_BYTES:
        raise Q4osQemuLabRefusal("Guest report length outside protocol bounds")
    if len(challenge_secret) != 64 or any(c not in "0123456789abcdef" for c in challenge_secret):
        raise Q4osQemuLabRefusal("Invalid one-time host challenge secret")
    if len(mac_hex) != 64 or any(c not in "0123456789abcdef" for c in mac_hex):
        raise Q4osQemuLabRefusal("Malformed guest report HMAC")
    expected_mac = hmac.new(
        challenge_secret.encode("ascii"), MAC_DOMAIN + report_raw, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(mac_hex, expected_mac):
        raise Q4osQemuLabRefusal("Guest report HMAC mismatch")
    identity = validate_guest_disk_report(
        report_raw,
        plan=plan,
        expected_serial=expected_virtio_serial(plan),
    )
    return {
        **identity,
        "transportAuthenticated": True,
        "transportProtocol": "private-qemu-virtio-serial-unix-socket+hmac-sha256",
        "transportChallengeFresh": True,
        "guestAttestation": False,
        "installationAuthorized": False,
        "diskWritesAuthorized": False,
        "calamaresJobsAuthorized": False,
        "windowsEspWritesAuthorized": False,
        "rollbackVerified": False,
    }


def _read_line(stream: Any, limit: int) -> bytes:
    value = stream.readline(limit + 1)
    if not value or len(value) > limit or not value.endswith(b"\n"):
        raise Q4osQemuLabRefusal("Incomplete or oversized QEMU virtio-serial frame")
    return value[:-1]


def _verify_plan(workspace: Path, plan_dir: Path) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    disk = workspace / "efi-disk.img"
    plan_path = plan_dir / "q4os-vm-plan.json"
    signature_path = plan_dir / "q4os-vm-plan.ed25519"
    public_path = plan_dir / "q4os-vm-lab-public-key.bin"
    fingerprint_path = plan_dir / "q4os-vm-key-sha256.txt"
    for path in (disk, plan_path, signature_path, public_path, fingerprint_path):
        _require(
            path.is_file() and not path.is_symlink(),
            f"Missing or unsafe signed-plan input: {path.name}",
        )
    info = disk.stat()
    _require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
        "Target image is not exclusively owned",
    )
    _require(
        info.st_uid == os.getuid() and info.st_size == DISK_BYTES,
        "Target image owner or size mismatch",
    )
    raw_plan = plan_path.read_bytes()
    plan = json.loads(raw_plan.decode("utf-8"))
    signature = signature_path.read_bytes()
    public_key = public_path.read_bytes()
    fingerprint = fingerprint_path.read_text(encoding="ascii").strip()
    _require(plan.get("operation") == "read-only-plan", "Unexpected target-plan operation")
    for flag in (
        "installationAuthorized",
        "calamaresJobsAuthorized",
        "windowsEspWritesAuthorized",
    ):
        _require(plan.get(flag) is False, f"Signed plan unexpectedly enables {flag}")
    _require(plan.get("guestOnly") is True, "Target plan is not guest-only")
    _require(plan.get("diskSizeBytes") == DISK_BYTES, "Signed plan disk size mismatch")
    verification = verify_signed_plan_against_disk(
        workspace,
        disk,
        raw_plan,
        signature,
        public_key,
        trusted_public_key_sha256=fingerprint,
        independently_expected_run_id=plan["runId"],
        independently_expected_nonce=plan["nonce"],
    )
    _require(verification.get("signatureVerified") is True, "Host plan signature did not verify")
    _require(verification.get("gptMetadataVerified") is True, "Host GPT metadata did not verify")
    _require(verification.get("diskWritesAuthorized") is False, "Signed plan enabled disk writes")
    return plan, raw_plan, verification


def _qemu_img_info(path: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["qemu-img", "info", "--output=json", str(path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    value = json.loads(result.stdout)
    _require(isinstance(value, dict), "qemu-img info returned an invalid object")
    return value


def _run_qemu(
    *,
    workspace: Path,
    overlay: Path,
    kernel: Path,
    initramfs: Path,
    serial: str,
    run_id: str,
    nonce: str,
    evidence: Path,
) -> tuple[dict[str, Any], int, str, str]:
    socket_dir = Path(tempfile.mkdtemp(prefix="gq4os-", dir="/tmp"))
    os.chmod(socket_dir, 0o700)
    socket_path = socket_dir / "r.sock"
    serial_log = workspace / "guest-serial.log"
    qemu_log = workspace / "qemu.log"
    _require(len(str(socket_path).encode()) < 100, "QEMU Unix socket path is too long")
    _require(
        "," not in str(overlay) and "," not in str(kernel) and "," not in str(initramfs),
        "Unsafe comma in QEMU file path",
    )
    kvm = Path("/dev/kvm")
    accel = "kvm" if kvm.exists() and os.access(kvm, os.R_OK | os.W_OK) else "tcg"
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
        "512",
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
        f"file:{serial_log}",
        "-drive",
        f"if=none,id=q4ostarget,file={overlay},format=qcow2,readonly=on,cache=none",
        "-device",
        f"virtio-blk-pci,drive=q4ostarget,serial={serial}",
        "-device",
        "virtio-serial-pci,id=q4osserial",
        "-chardev",
        f"socket,id=q4osreport,path={socket_path},server=on,wait=off",
        "-device",
        "virtserialport,chardev=q4osreport,name=org.gaslux.q4os.identity",
    ]
    process: subprocess.Popen[bytes] | None = None
    connection: socket.socket | None = None
    stream: Any = None
    try:
        with qemu_log.open("xb") as log:
            process = subprocess.Popen(
                command,
                cwd=workspace,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                close_fds=True,
            )
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise Q4osQemuLabRefusal("QEMU exited before creating its report socket")
                if socket_path.exists():
                    mode = socket_path.lstat().st_mode
                    if stat.S_ISSOCK(mode):
                        break
                time.sleep(0.1)
            else:
                raise Q4osQemuLabRefusal("QEMU virtio-serial socket did not appear")

            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(120)
            connection.connect(str(socket_path))
            if not hasattr(socket, "SO_PEERCRED"):
                raise Q4osQemuLabRefusal("Host lacks Unix peer-credential support")
            peer = struct.unpack(
                "3i",
                connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")),
            )
            peer_pid, peer_uid, _peer_gid = peer
            if peer_pid != process.pid or peer_uid != os.getuid():
                raise Q4osQemuLabRefusal("Virtio-serial peer is not the expected QEMU process")
            stream = connection.makefile("rb")
            hello = _read_line(stream, 128)
            if hello != HELLO:
                raise Q4osQemuLabRefusal("Guest did not identify the named virtio-serial endpoint")

            challenge_secret = secrets.token_hex(32)
            challenge = (f"{CHALLENGE_MAGIC}:{run_id}:{nonce}:{challenge_secret}\n").encode("ascii")
            connection.sendall(challenge)

            header = _read_line(stream, 64)
            if header != REPORT_MAGIC:
                raise Q4osQemuLabRefusal("Unexpected guest report frame header")
            report_raw = _read_line(stream, MAX_REPORT_BYTES + 1)
            mac_line = _read_line(stream, 128)
            try:
                mac_hex = mac_line.decode("ascii")
            except UnicodeDecodeError as exc:
                raise Q4osQemuLabRefusal("Guest report HMAC is not ASCII") from exc

            if process.poll() is None:
                process.wait(timeout=45)
            if process.returncode != 0:
                raise Q4osQemuLabRefusal(f"QEMU guest shutdown returned {process.returncode}")
            extra = stream.read(1)
            if extra:
                raise Q4osQemuLabRefusal("Unexpected trailing bytes after guest report")
            with serial_log.open("rb") as serial_stream:
                serial_output = serial_stream.read(65536).decode("utf-8", errors="replace")
            if "GASLUX_Q4OS_GUEST_PROBE=PASS" not in serial_output:
                raise Q4osQemuLabRefusal("Guest serial console did not report a successful probe")
            identity = verify_authenticated_report(
                report_raw,
                mac_hex,
                challenge_secret=challenge_secret,
                plan=json.loads((evidence / "q4os-vm-plan-copy.json").read_text(encoding="utf-8")),
            )
            identity["reportMacSha256"] = hashlib.sha256(mac_line).hexdigest()
            identity["qemuProcessId"] = process.pid
            identity["qemuPeerPid"] = peer_pid
            identity["qemuPeerUid"] = peer_uid
            identity["qemuAcceleration"] = accel
            identity["qemuDiskAttachmentReadOnly"] = True
            identity["qemuNetworkAttached"] = False
            identity["qemuPhysicalDisksAttached"] = False
            return identity, process.pid, accel, serial_output
    finally:
        if stream is not None:
            stream.close()
        if connection is not None:
            connection.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        try:
            socket_path.unlink(missing_ok=True)
            socket_dir.rmdir()
        except OSError:
            pass


def run_lab(
    workspace: Path,
    plan_dir: Path,
    evidence: Path,
    kernel: Path,
    initramfs: Path,
) -> dict[str, Any]:
    _require(os.environ.get("GITHUB_ACTIONS") == "true", "Q4OS QEMU lab requires GitHub Actions")
    for path in (workspace, plan_dir, kernel, initramfs):
        _require(
            path.is_absolute() and path.exists() and not path.is_symlink(),
            "Q4OS QEMU lab input path is missing or unsafe",
        )
    _require(
        workspace.is_dir() and workspace.stat().st_uid == os.getuid(),
        "Q4OS QEMU workspace is not owned by this runner",
    )
    _require(
        plan_dir.is_dir() and plan_dir.stat().st_uid == os.getuid(),
        "Signed plan evidence is not runner-owned",
    )
    _require(kernel.is_file() and initramfs.is_file(), "Kernel or initramfs is missing")
    _require(
        not evidence.exists() and not evidence.is_symlink(),
        "Q4OS QEMU evidence directory already exists",
    )
    evidence.mkdir(mode=0o700)
    disk = workspace / "efi-disk.img"
    overlay = workspace / "q4os-target-overlay.qcow2"
    checkpoint_path = evidence / "q4os-vm-recovery-checkpoint.json"
    plan, raw_plan, plan_verification = _verify_plan(workspace, plan_dir)
    serial = expected_virtio_serial(plan)
    base_stat = disk.stat()
    base_before = sparse_content_sha256(disk)
    _require(not overlay.exists() and not overlay.is_symlink(), "QEMU overlay path already exists")

    checkpoint = {
        "schemaVersion": 1,
        "runId": plan["runId"],
        "nonce": plan["nonce"],
        "planSha256": hashlib.sha256(raw_plan).hexdigest(),
        "baseImage": disk.name,
        "baseImageDevice": base_stat.st_dev,
        "baseImageInode": base_stat.st_ino,
        "baseImageSizeBytes": base_stat.st_size,
        "baseImageSparseSha256Before": base_before,
        "snapshotFormat": "qcow2-overlay-with-raw-immutable-backing",
        "overlayImage": overlay.name,
        "overlayBackingFormat": "raw",
        "guestDiskAttachmentReadOnly": True,
        "guestWriteAttempted": False,
        "checkpointFsyncBeforeQemu": False,
        "checkpointDurableForRunnerJob": False,
        "rollbackVerified": False,
        "installationAuthorized": False,
        "diskWritesAuthorized": False,
        "calamaresJobsAuthorized": False,
        "windowsEspWritesAuthorized": False,
    }
    qemu_pid: int | None = None
    qemu_accel = "not-started"
    serial_output = ""
    identity: dict[str, Any] = {}
    try:
        subprocess.run(
            [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-F",
                "raw",
                "-b",
                str(disk),
                str(overlay),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        info = _qemu_img_info(overlay)
        _require(info.get("format") == "qcow2", "QEMU checkpoint overlay is not qcow2")
        _require(info.get("backing-filename") == str(disk), "QEMU overlay backing image mismatch")
        _require(info.get("backing-filename-format") == "raw", "QEMU backing format mismatch")
        _require(info.get("virtual-size") == DISK_BYTES, "QEMU overlay virtual size mismatch")
        subprocess.run(
            ["qemu-img", "check", str(overlay)],
            check=True,
            capture_output=True,
            timeout=60,
        )
        _fsync_then_chmod(disk, 0o400)
        _fsync_then_chmod(overlay, 0o400)
        checkpoint["overlayImageSparseSha256Before"] = sparse_content_sha256(overlay)
        checkpoint["checkpointFsyncBeforeQemu"] = True
        checkpoint["checkpointDurableForRunnerJob"] = True
        _write_json_durable(checkpoint_path, checkpoint)
        # The signed plan is copied into the evidence directory for the runner-side
        # verifier; the signing key is public and the ephemeral private key is absent.
        (evidence / "q4os-vm-plan-copy.json").write_bytes(raw_plan)
        _fsync_file(evidence / "q4os-vm-plan-copy.json")

        identity, qemu_pid, qemu_accel, serial_output = _run_qemu(
            workspace=workspace,
            overlay=overlay,
            kernel=kernel,
            initramfs=initramfs,
            serial=serial,
            run_id=plan["runId"],
            nonce=plan["nonce"],
            evidence=evidence,
        )

        base_after = sparse_content_sha256(disk)
        overlay_after = sparse_content_sha256(overlay)
        _require(base_after == base_before, "Immutable backing image changed during QEMU boot")
        _require(
            overlay_after == checkpoint["overlayImageSparseSha256Before"],
            "Read-only QEMU overlay changed during guest boot",
        )
        subprocess.run(
            ["qemu-img", "check", str(overlay)],
            check=True,
            capture_output=True,
            timeout=60,
        )
        _verify_plan(workspace, plan_dir)
        checkpoint.update(
            {
                "baseImageSparseSha256After": base_after,
                "overlayImageSparseSha256After": overlay_after,
                "baseImageUnchanged": True,
                "overlayUnchanged": True,
                "qemuGuestShutdownObserved": True,
                "guestDiskIdentityVerified": identity["guestDiskIdentityVerified"],
                "transportAuthenticated": identity["transportAuthenticated"],
                "guestBlockDeviceReadOnly": identity["blockDeviceReadOnly"],
                "snapshotIntegrityVerified": True,
                "overlayDiscarded": False,
                "rollbackVerified": False,
            }
        )
        _write_json_durable(checkpoint_path, checkpoint)
        overlay.unlink()
        _fsync_directory(workspace)
        _require(
            sparse_content_sha256(disk) == base_before,
            "Backing image changed after overlay discard",
        )
        checkpoint["overlayDiscarded"] = True
        checkpoint["baseRevalidatedAfterOverlayDiscard"] = True
        checkpoint["rollbackVerified"] = False
        _write_json_durable(checkpoint_path, checkpoint)

        evidence_result = {
            "schemaVersion": 1,
            "distributionId": "q4os",
            "runId": plan["runId"],
            "nonce": plan["nonce"],
            "virtioSerial": serial,
            "qemuBootObserved": True,
            "guestDiskIdentityVerified": True,
            "transportAuthenticated": True,
            "transportPeerBoundToQemuPid": True,
            "guestAttestation": False,
            "guestBlockDeviceReadOnly": True,
            "guestWriteAttempted": False,
            "baseImageUnchanged": True,
            "overlayUnchanged": True,
            "checkpointFsyncVerified": True,
            "checkpointDurableForRunnerJob": True,
            "overlayDiscarded": True,
            "baseRevalidatedAfterOverlayDiscard": True,
            "rollbackVerified": False,
            "installationAuthorized": False,
            "diskWritesAuthorized": False,
            "calamaresJobsAuthorized": False,
            "windowsEspWritesAuthorized": False,
            "windowsDiskAttached": False,
            "qemuNetworkAttached": False,
            "qemuAcceleration": qemu_accel,
            "qemuProcessId": qemu_pid,
            "planSignatureVerified": plan_verification["signatureVerified"],
            "hostPlanRevalidatedAfterGuest": True,
            "reportMacSha256": identity["reportMacSha256"],
            "observedGuestReport": {
                "device": identity.get("observedDevice"),
                "serial": identity["observedSerial"],
                "diskGuid": identity["observedDiskGuid"],
                "espGuid": identity["observedEspGuid"],
                "reportSha256": identity["guestReportSha256"],
            },
        }
        _write_json_durable(evidence / "q4os-qemu-guest-identity.json", evidence_result)
        (evidence / "q4os-guest-serial.log").write_text(serial_output, encoding="utf-8")
        _fsync_file(evidence / "q4os-guest-serial.log")
        return evidence_result
    finally:
        for source, destination in (
            (workspace / "guest-serial.log", evidence / "qemu-guest-serial.log"),
            (workspace / "qemu.log", evidence / "qemu-process.log"),
        ):
            if source.is_file() and not source.is_symlink():
                destination.write_bytes(source.read_bytes())
                _fsync_file(destination)
        if not checkpoint_path.exists():
            _write_json_durable(evidence / "q4os-vm-recovery-checkpoint.json", checkpoint)


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "REFUSED: usage: gaslux_q4os_qemu_identity_lab.py "
            "WORKSPACE PLAN_EVIDENCE OUTPUT_DIR KERNEL INITRAMFS",
            file=sys.stderr,
        )
        return 2
    try:
        result = run_lab(
            Path(sys.argv[1]),
            Path(sys.argv[2]),
            Path(sys.argv[3]),
            Path(sys.argv[4]),
            Path(sys.argv[5]),
        )
    except (
        Q4osQemuLabRefusal,
        Q4osPlanRefusal,
        OSError,
        ValueError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"GASLUX_Q4OS_QEMU_IDENTITY_REFUSED={exc}", file=sys.stderr, flush=True)
        return 1
    print("GASLUX_Q4OS_QEMU_BOOT=PASS")
    print("GASLUX_Q4OS_VIRTIO_SERIAL_BOUND=PASS")
    print("GASLUX_Q4OS_AUTHENTICATED_TRANSPORT=PASS")
    print("GASLUX_Q4OS_READ_ONLY_CHECKPOINT=PASS")
    print("GASLUX_Q4OS_BASE_IMAGE_UNCHANGED=PASS")
    print("GASLUX_Q4OS_INSTALLATION_AUTHORIZED=0")
    print("GASLUX_Q4OS_DISK_WRITES_AUTHORIZED=0")
    print("GASLUX_Q4OS_ROLLBACK_VERIFIED=0")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
