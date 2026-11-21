#!/usr/bin/env python3
"""QEMU/libguestfs GPT observation, synthetic QCOW2 only, NEVER a writer.

Runs with a lab-owned raw GPT backing and a read-only qcow2 overlay.
libguestfs is a real Linux appliance booted by QEMU, not a simulated guest.
Both sensors and ephemeral keys are controlled by the runner: NOT_INDEPENDENT.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets" / "live"))
from libertix_disk_identity_gate import (  # noqa: E402
    DiskIdentityError, assert_snapshot_matches, inspect_gpt_image,
)
from libertix_prewrite_no_writer import (  # noqa: E402
    PrewriteDenied, authenticated_record, canonical, decide_no_writer,
)

SIZE = 64 * 1024 * 1024
SECTOR = 512
GUEST_SLICE = 34 * SECTOR
GUEST_LABEL_PREFIX = "gaslux"


def require(value: bool, message: str) -> None:
    if not value:
        raise PrewriteDenied(message)


def run(*args: str, timeout: int = 60) -> str:
    result = subprocess.run(
        list(args), check=False, capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode:
        raise PrewriteDenied(
            f"Command {args[0]} failed ({result.returncode}): {result.stderr[-500:]}"
        )
    return result.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as src:
        while True:
            buf = src.read(1024 * 1024)
            if not buf:
                break
            digest.update(buf)
    return digest.hexdigest()


def own_regular(path: Path, folder: Path) -> os.stat_result:
    require(path.parent == folder, "path outside the owned workspace")
    require(not path.is_symlink(), "symlink disk rejected")
    value = path.lstat()
    require(
        stat.S_ISREG(value.st_mode) and value.st_nlink == 1
        and value.st_uid == os.getuid() and value.st_size > 0,
        "foreign, hardlinked or non-regular disk rejected",
    )
    return value


def same_file(path: Path, folder: Path, original: os.stat_result) -> None:
    current = own_regular(path, folder)
    require(
        (current.st_dev, current.st_ino, current.st_size)
        == (original.st_dev, original.st_ino, original.st_size),
        "disk path, inode or geometry changed",
    )


def make_raw(path: Path, folder: Path, *, disk_guid: str, part_guid: str) -> None:
    require(path.parent == folder and not path.exists(), "unsafe raw image destination")
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.ftruncate(fd, SIZE)
        os.fsync(fd)
    finally:
        os.close(fd)
    own_regular(path, folder)
    run(
        "sgdisk", "--clear", "--new=1:2048:4095", "--typecode=1:0700",
        f"--disk-guid={disk_guid}", f"--partition-guid=1:{part_guid}", str(path),
    )
    require(path.stat().st_size == SIZE, "GPT construction changed disk size")
    inspect_gpt_image(path, logical_sector_size=SECTOR)


def make_qcow(overlay: Path, base: Path, folder: Path) -> None:
    require(overlay.parent == folder and not overlay.exists(), "unsafe overlay destination")
    own_regular(base, folder)
    run("qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", str(base), str(overlay))
    own_regular(overlay, folder)


def verify_chain(overlay: Path, base: Path, folder: Path) -> dict:
    own_regular(overlay, folder)
    own_regular(base, folder)
    chain = json.loads(
        run("qemu-img", "info", "--output=json", "--backing-chain", str(overlay))
    )
    require(type(chain) is list and len(chain) == 2, "unexpected QCOW2 backing depth")
    child, backing = chain
    require(child.get("format") == "qcow2", "unexpected overlay format")
    require(backing.get("format") == "raw", "unexpected backing format")
    require(
        child.get("virtual-size") == SIZE and backing.get("virtual-size") == SIZE,
        "QCOW2 virtual geometry mismatch",
    )
    actual_path = child.get("full-backing-filename")
    require(
        type(actual_path) is str and Path(actual_path).resolve() == base.resolve(),
        "QCOW2 backing path mismatch",
    )
    require(child.get("backing-filename-format") == "raw", "QCOW2 backing format mismatch")
    return {
        "format": "qcow2", "virtualSizeBytes": SIZE,
        "backingFormat": "raw", "backingFilename": str(base),
        "backingSha256": sha256(base), "overlaySha256": sha256(overlay),
    }


def host_snapshot(overlay: Path, raw_output: Path, folder: Path) -> dict:
    require(raw_output.parent == folder and not raw_output.exists(), "unsafe host output")
    run("qemu-img", "convert", "-f", "qcow2", "-O", "raw", str(overlay), str(raw_output))
    own_regular(raw_output, folder)
    return inspect_gpt_image(raw_output, logical_sector_size=SECTOR)


def reconstruct_guest_sample(
    first: bytes, last: bytes, size: int, output: Path, folder: Path
) -> dict:
    require(type(first) is bytes and len(first) == GUEST_SLICE, "guest GPT front sample missing")
    require(type(last) is bytes and len(last) == GUEST_SLICE, "guest GPT rear sample missing")
    require(
        type(size) is int and size >= 68 * SECTOR and size % SECTOR == 0
        and size <= SIZE, "guest block device geometry differs",
    )
    require(output.parent == folder and not output.exists(), "unsafe guest evidence destination")
    fd = os.open(str(output), os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        os.ftruncate(fd, size)
        os.pwrite(fd, first, 0)
        os.pwrite(fd, last, size - GUEST_SLICE)
        os.fsync(fd)
    finally:
        os.close(fd)
    return inspect_gpt_image(output, logical_sector_size=SECTOR)


def qemu_identity(pid: int, overlay: Path) -> dict:
    require(type(pid) is int and pid > 1, "QEMU PID unavailable")
    proc = Path("/proc") / str(pid)
    executable = (proc / "exe").resolve(strict=True)
    require(executable.name.startswith("qemu-system-"), "unexpected Linux guest hypervisor")
    argv = (proc / "cmdline").read_bytes().split(b"\0")
    command = [a.decode("utf-8", errors="replace") for a in argv if a]
    attached = any(str(overlay) in item for item in command)
    fds = []
    for item in (proc / "fd").iterdir():
        try:
            target = os.readlink(item)
        except OSError:
            continue
        fds.append(target)
        if target == str(overlay):
            attached = True
    require(attached, "QEMU does not reference the selected QCOW2 file")
    require(
        any("/dev/kvm" in entry for entry in fds)
        and any("kvm" in item.lower() for item in command),
        "QEMU/KVM was not demonstrated",
    )
    return {
        "qemuPid": pid, "qemuBinary": executable.name,
        "qemuCmdlineSha256": hashlib.sha256(b"\0".join(argv)).hexdigest(),
        "qcow2Attached": attached, "kvmDeviceOpen": True,
    }


def inspect_guest(overlay: Path, output: Path, folder: Path, label: str) -> tuple[dict, dict]:
    try:
        import guestfs
    except ImportError as error:
        raise PrewriteDenied("python3-guestfs unavailable") from error
    require(bool(re.fullmatch(r"gaslux[a-f]{12}", label)), "invalid guest disk label")
    require(os.environ.get("LIBGUESTFS_BACKEND") == "direct", "direct guestfs backend required")
    guest = guestfs.GuestFS(python_return_dict=True)
    try:
        guest.set_backend("direct")
        guest.add_drive_opts(str(overlay), format="qcow2", readonly=1, label=label)
        guest.launch()
        devices = guest.list_devices()
        require(len(devices) == 1, "guest has ambiguous attached disks")
        # libguestfs creates a guest-side by-label device independent of /dev/sda.
        named_device = "/dev/disk/guestfs/" + label
        require(
            guest.blockdev_getsize64(named_device) == SIZE
            and guest.blockdev_getsize64(devices[0]) == SIZE,
            "guest disk label or virtual size mismatch",
        )
        require(guest.blockdev_getss(named_device) == SECTOR, "guest logical sector size mismatch")
        pid_identity = qemu_identity(int(guest.get_pid()), overlay)
        first = guest.pread_device(named_device, GUEST_SLICE, 0)
        last = guest.pread_device(named_device, GUEST_SLICE, SIZE - GUEST_SLICE)
        snapshot = reconstruct_guest_sample(first, last, SIZE, output, folder)
        identity = {
            "guestDiskLabel": label, "guestLogicalSectorBytes": SECTOR,
            "guestVirtualSizeBytes": SIZE, "deviceCount": len(devices),
            "diskSelectedBy": "libguestfs-label-and-GPT",
            "diskHardwareSerialVerified": False,
            **pid_identity,
        }
        return snapshot, identity
    finally:
        guest.close()


class NonceRegistry:
    """Single-use nonce per VM/transaction, local to one ephemeral lab process."""

    def __init__(self) -> None:
        self.consumed: set[tuple[str, str, str]] = set()

    def consume(self, tx: str, vm: str, nonce: str) -> None:
        require(
            type(nonce) is str and bool(re.fullmatch(r"[0-9a-f]{48}", nonce)),
            "nonce format invalid",
        )
        value = (tx, vm, nonce)
        require(value not in self.consumed, "replayed challenge")
        self.consumed.add(value)


def evaluate(
    snapshots: tuple[dict, dict, dict],
    chain: dict,
    guest_identity: dict,
    registry: NonceRegistry,
    *,
    tamper: str | None = None,
) -> dict:
    """Laboratory-only binding. HMAC authority is NOT independent of runner."""
    host, guest, immediate = snapshots
    transaction = secrets.token_hex(16)
    vm = "gaslux-qemu-" + secrets.token_hex(12)
    nonce = secrets.token_hex(24)
    expected = {
        "planId": transaction, "firmware": "uefi",
        "disk": {key: host[key] for key in (
            "partitionStyle", "partitionTableId", "sizeBytes", "logicalSectorSizeBytes"
        )},
        "labBinding": {"qcow2": chain, "guest": guest_identity, "vmId": vm},
    }
    raw = canonical(expected)
    digest = hashlib.sha256(raw).hexdigest()
    host_key, guest_key = secrets.token_bytes(32), secrets.token_bytes(32)
    def record(source: str, snapshot: dict, key: bytes) -> dict:
        return authenticated_record({
            "source": source, "transactionId": transaction,
            "vmId": vm, "planSha256": digest, "nonce": nonce,
            "snapshot": snapshot,
        }, key)
    host_record = record("host", host, host_key)
    guest_record = record("guest", guest, guest_key)
    immediate_record = record("guest-immediate", immediate, guest_key)
    partition_end = max(
        (p["offsetBytes"] + p["sizeBytes"] for p in host["partitions"]),
        default=0,
    )
    alignment = 1024 * 1024
    free_start = ((max(alignment, partition_end) + alignment - 1) // alignment) * alignment
    free_bytes = min(
        1024 * 1024, host["sizeBytes"] - 34 * host["logicalSectorSizeBytes"] - free_start,
    )
    free_bytes = free_bytes // host["logicalSectorSizeBytes"] * host["logicalSectorSizeBytes"]
    require(free_bytes >= host["logicalSectorSizeBytes"], "no safe synthetic free-space witness")
    kwargs = {
        "plan": expected, "plan_bytes": raw, "transaction_id": transaction,
        "vm_id": vm, "host_evidence": host_record, "guest_evidence": guest_record,
        "immediate_evidence": immediate_record, "host_key": host_key,
        "guest_key": guest_key, "fresh_nonce": nonce,
        "owned_regions": [{
            "offsetBytes": free_start, "sizeBytes": free_bytes,
            "ownerTransactionId": transaction,
        }],
        "write_set": [{
            "offsetBytes": free_start, "sizeBytes": free_bytes,
            "operation": "allocate-free-space",
        }],
    }
    if tamper == "mac":
        kwargs["guest_evidence"]["mac"] = "0" * 64
    if tamper == "vm":
        kwargs["vm_id"] = "different-qemu-vm-identity"
    if tamper == "immediate":
        altered = json.loads(json.dumps(immediate))
        altered["partitions"][0]["offsetBytes"] += 512
        kwargs["immediate_evidence"] = record("guest-immediate", altered, guest_key)
    if tamper == "host_guest":
        altered = json.loads(json.dumps(guest))
        altered["partitionTableId"] = "gpt:00000000-0000-0000-0000-000000000001"
        kwargs["guest_evidence"] = record("guest", altered, guest_key)
    registry.consume(transaction, vm, nonce)
    result = decide_no_writer(**kwargs)
    return {
        "result": result, "planSha256": digest,
        "transactionId": transaction, "vmId": vm, "nonce": nonce,
        "keysPublished": False, "planSignatureVerified": False,
        "trustBoundary": "NOT_INDEPENDENT", "writerCalled": False,
        "authority": "LAB_ONLY",
    }


def experiment(folder: Path) -> dict:
    base, overlay = folder / "base.raw", folder / "child.qcow2"
    make_raw(base, folder, disk_guid=str(uuid.uuid4()), part_guid=str(uuid.uuid4()))
    base_stat = own_regular(base, folder)
    make_qcow(overlay, base, folder)
    overlay_stat = own_regular(overlay, folder)
    chain = verify_chain(overlay, base, folder)
    host = host_snapshot(overlay, folder / "host.raw", folder)
    assert_snapshot_matches(inspect_gpt_image(base, logical_sector_size=SECTOR), host)
    label = GUEST_LABEL_PREFIX + "".join(secrets.choice("abcdef") for _ in range(12))
    guest, hypervisor = inspect_guest(overlay, folder / "guest-reconstructed.raw", folder, label)
    assert_snapshot_matches(host, guest)
    same_file(base, folder, base_stat)
    same_file(overlay, folder, overlay_stat)
    require(chain == verify_chain(overlay, base, folder), "QCOW2/backing changed after guest")
    immediate = host_snapshot(overlay, folder / "immediate.raw", folder)
    assert_snapshot_matches(host, immediate)
    registry = NonceRegistry()
    good = evaluate((host, guest, immediate), chain, hypervisor, registry)
    require(good["result"]["decision"] == "ACCEPT_NO_WRITER", "valid lab evidence refused")
    original_nonce = good.pop("nonce")
    good["nonceSha256"] = hashlib.sha256(original_nonce.encode()).hexdigest()

    negatives: dict[str, str] = {}
    for fault in ("mac", "vm", "immediate", "host_guest"):
        try:
            evaluate((host, guest, immediate), chain, hypervisor, registry, tamper=fault)
        except (DiskIdentityError, PrewriteDenied):
            negatives[fault] = "DENY_NO_WRITER"
        else:
            raise PrewriteDenied("adversarial gate unexpectedly accepted " + fault)

    # An actual second QCOW2 backed by another GPT image: not a JSON-only mutation.
    foreign_base, foreign_overlay = folder / "foreign.raw", folder / "foreign.qcow2"
    make_raw(
        foreign_base, folder, disk_guid="f12a1be6-cc4d-401d-8341-77fc0bc0c159",
        part_guid="f03ada0e-3f23-4ac7-8f48-4cba28c0c160",
    )
    make_qcow(foreign_overlay, foreign_base, folder)
    foreign_chain = verify_chain(foreign_overlay, foreign_base, folder)
    foreign_host = host_snapshot(foreign_overlay, folder / "foreign-host.raw", folder)
    require(foreign_chain != chain, "foreign QCOW2 unexpectedly identical")
    try:
        assert_snapshot_matches(host, foreign_host)
    except DiskIdentityError:
        negatives["different_qcow2_real"] = "DENY_NO_WRITER"
    else:
        raise PrewriteDenied("replacement QCOW2 not rejected")
    # Actual backing-chain metadata alteration, limited to this disposable overlay.
    run(
        "qemu-img", "rebase", "-u", "-f", "qcow2", "-F", "raw",
        "-b", str(base), str(foreign_overlay),
    )
    try:
        verify_chain(foreign_overlay, foreign_base, folder)
    except PrewriteDenied:
        negatives["changed_backing_real"] = "DENY_NO_WRITER"
    else:
        raise PrewriteDenied("backing chain alteration not rejected")
    # Replay the exact successful QEMU session challenge, not a synthetic new token.
    try:
        registry.consume(good["transactionId"], good["vmId"], original_nonce)
    except PrewriteDenied:
        negatives["nonce_replay"] = "DENY_NO_WRITER"
    else:
        raise PrewriteDenied("nonce replay not rejected")

    same_file(base, folder, base_stat)
    same_file(overlay, folder, overlay_stat)
    require(chain == verify_chain(overlay, base, folder), "original QCOW2 backing changed")
    return {
        "classification": "QEMU_SYNTHETIC_LAB_ONLY",
        "trustBoundary": "NOT_INDEPENDENT",
        "guestOS": "libguestfs Linux appliance", "windowsGenuine": False,
        "baseSha256BeforeAfterSame": sha256(base) == chain["backingSha256"],
        "overlaySha256BeforeAfterSame": sha256(overlay) == chain["overlaySha256"],
        "baseBacking": chain, "hostGpt": host, "guestGpt": guest,
        "immediateGpt": immediate, "qemu": hypervisor,
        "decision": good, "adversarialDenials": negatives,
        "writerPresent": False, "diskHardwareSerialVerified": False,
        "planSignatureVerified": False,
    }


def main() -> int:
    require(os.environ.get("GITHUB_ACTIONS") == "true", "GitHub disposable runner required")
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "hosted runner required")
    require(os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux", "unexpected repository")
    require(os.environ.get("LIBGUESTFS_BACKEND") == "direct", "direct backend required")
    kvm = Path("/dev/kvm")
    require(kvm.exists() and stat.S_ISCHR(kvm.stat().st_mode), "KVM unavailable")
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(temp.is_dir() and temp != Path("/"), "unsafe RUNNER_TEMP")
    evidence = Path(os.environ["GASLUX_SAFETY_EVIDENCE"]).resolve(strict=True)
    require(evidence.is_dir() and evidence != temp, "unsafe evidence directory")
    with tempfile.TemporaryDirectory(prefix="gaslux-qemu-safety-", dir=temp) as workspace:
        folder = Path(workspace)
        result = experiment(folder)
    result["labTemporaryDisksRemoved"] = True
    result["integrityClaimScope"] = "synthetic QCOW2 runner only"
    content = canonical(result) + b"\n"
    require(len(content) < 128 * 1024, "evidence manifest too large")
    output = evidence / "gpt-host-guest-no-writer.json"
    require(not output.exists() and not output.is_symlink(), "evidence output already exists")
    output.write_bytes(content)
    (evidence / "gpt-host-guest-no-writer.sha256").write_text(
        hashlib.sha256(content).hexdigest() + "  " + output.name + "\n",
        encoding="ascii",
    )
    print(
        json.dumps(
            {
                "status": "SUCCESS_SYNTHETIC_ONLY", "trustBoundary": "NOT_INDEPENDENT",
                "decision": result["decision"]["result"]["decision"],
                "denials": result["adversarialDenials"],
                "basePreserved": result["baseSha256BeforeAfterSame"],
                "overlayPreserved": result["overlaySha256BeforeAfterSame"],
                "tempRemoved": True,
            }, sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "BLOCKED_FAIL_CLOSED", "error": type(error).__name__,
                    "message": str(error)[:500], "writerPresent": False,
                },
                sort_keys=True,
            ), file=sys.stderr,
        )
        raise SystemExit(2)
