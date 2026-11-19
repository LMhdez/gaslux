#!/usr/bin/env python3
"""ONE bounded 4-KiB guest COW write, after an authenticated host capability.

Disposable QEMU initramfs only. NO partition creation, formatting, Calamares,
Windows ESP, real disk, or persistent install authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import sys
from pathlib import Path

from guest_probe import (
    _read_line,
    _write_all,
    derive_virtio_serial,
    find_virtio_port,
    inspect_gpt_fd,
)

HELLO = b"GQ4OS-WRITE-HELLO-V1\n"
CHALLENGE = b"GQ4OS-WRITE-CHALLENGE-V1"
AUTH = b"GQ4OS-WRITE-ALLOW-V1"
POWER_CUT_MODE = b"SIMULATE-POWER-CUT"
POWER_CUT_READY = b"GQ4OS-WRITE-SYNCED-BLOCKED-V1"
FINISH = b"GQ4OS-WRITE-FINISH-V1"
PREFLIGHT = b"GQ4OS-WRITE-PREFLIGHT-V1\n"
RESULT = b"GQ4OS-WRITE-RESULT-V1\n"
REPORT_DOMAIN = b"GASLUX-Q4OS-BOUND-WRITE-REPORT-V1\n"
AUTH_DOMAIN = b"GASLUX-Q4OS-BOUND-WRITE-AUTH-V1\n"
DISK_BYTES = 32 * 1024**3
ESP_END_LBA = 1050623
ROOT_START_LBA = ESP_END_LBA + 1
WRITE_OFFSET = (ROOT_START_LBA + 2048) * 512
WRITE_LENGTH = 4096
PATTERN = b"\xa5" * WRITE_LENGTH
DIGEST = hashlib.sha256(PATTERN).hexdigest()
RUN_RE = re.compile(r"[A-Za-z0-9_-]{12,100}\Z")
NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")
SECRET_RE = re.compile(r"[0-9a-f]{64}\Z")


class BoundWriteRefusal(RuntimeError):
    """Fail-closed VM guest write boundary."""


def _require(ok: bool, reason: str) -> None:
    if not ok:
        raise BoundWriteRefusal(reason)


def _report(fd: int, label: bytes, data: dict, secret: str) -> None:
    raw = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    mac = hmac.new(secret.encode("ascii"), REPORT_DOMAIN + label + b"\n" + raw, hashlib.sha256)
    _write_all(fd, label + raw + b"\n" + mac.hexdigest().encode("ascii") + b"\n")


def _read_identity(serial: str) -> tuple[Path, dict]:
    paths = [
        p
        for p in Path("/sys/block").glob("*/serial")
        if p.is_file() and p.read_text(encoding="ascii").strip() == serial
    ]
    _require(len(paths) == 1, "Exactly one bound VirtIO serial required")
    sys_disk = paths[0].parent
    _require(sys_disk.name.startswith("vd"), "Untrusted non-VirtIO device")
    _require((sys_disk / "ro").read_text().strip() == "0", "Guest disk is not writable COW")
    logical = int((sys_disk / "queue/logical_block_size").read_text().strip())
    physical = int((sys_disk / "queue/physical_block_size").read_text().strip())
    size_sectors = int((sys_disk / "size").read_text().strip())
    _require(logical == 512 and physical in (512, 4096), "Unexpected disk sector size")
    _require(size_sectors * 512 == DISK_BYTES, "Unexpected guest disk size")
    device = Path("/dev") / sys_disk.name
    _require(device.exists() and stat.S_ISBLK(device.stat().st_mode), "Target not a block device")
    with os.fdopen(os.open(device, os.O_RDONLY | os.O_CLOEXEC), "rb", closefd=True) as reader:
        gpt = inspect_gpt_fd(reader.fileno(), disk_size_bytes=DISK_BYTES, sector_bytes=logical)
        existing = os.pread(reader.fileno(), WRITE_LENGTH, WRITE_OFFSET)
    _require(
        len(existing) == WRITE_LENGTH and existing == bytes(WRITE_LENGTH),
        "Proposed free-space marker is not empty",
    )
    _require(len(gpt["partitions"]) == 1, "Foreign partitions in Q4OS write guest")
    esp = gpt["partitions"][0]
    _require(
        esp["number"] == 1
        and esp["label"] == "GASLUX-LAB-ESP"
        and esp["startLba"] == 2048
        and esp["endLba"] == ESP_END_LBA
        and esp["filesystem"] == "vfat"
        and esp["typeGuid"] == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
        "Unknown ESP geometry or filesystem",
    )
    _require(
        WRITE_OFFSET >= (ROOT_START_LBA + 2048) * 512
        and WRITE_OFFSET + WRITE_LENGTH < (DISK_BYTES - 34 * 512),
        "Write extent is not strictly inside guest-free area",
    )
    return device, {
        "schemaVersion": 1,
        "device": str(device),
        "serial": serial,
        "sizeBytes": DISK_BYTES,
        "logicalSectorBytes": logical,
        "physicalSectorBytes": physical,
        "diskGuid": gpt["diskGuid"],
        "partitions": gpt["partitions"],
        "blockDeviceReadOnly": False,
        "readOnlyProbe": True,
        "writeAttempted": False,
        "writeOffsetBytes": WRITE_OFFSET,
        "writeLengthBytes": WRITE_LENGTH,
        "markerBeforeSha256": hashlib.sha256(existing).hexdigest(),
    }


def run() -> dict:
    port = find_virtio_port()
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY)
    try:
        _write_all(fd, HELLO)
        challenge = _read_line(fd, 512).split(b":")
        power_cut = len(challenge) == 5 and challenge[4] == POWER_CUT_MODE
        _require(
            (len(challenge) == 4 or power_cut) and challenge[0] == CHALLENGE,
            "Missing or malformed one-time challenge",
        )
        run_id, nonce, secret = [field.decode("ascii") for field in challenge[1:4]]
        _require(
            bool(RUN_RE.fullmatch(run_id)) and bool(NONCE_RE.fullmatch(nonce)),
            "Untrusted run identity",
        )
        _require(bool(SECRET_RE.fullmatch(secret)), "Invalid host challenge key")
        serial = derive_virtio_serial(run_id, nonce)
        device, preflight = _read_identity(serial)
        preflight.update({"runId": run_id, "nonce": nonce})
        _report(fd, PREFLIGHT, preflight, secret)

        command = _read_line(fd, 512).split(b":")
        _require(len(command) == 5 and command[0] == AUTH, "Host did not authorize marker")
        offset, length, digest, received_mac = command[1:]
        _require(
            offset == str(WRITE_OFFSET).encode("ascii")
            and length == str(WRITE_LENGTH).encode("ascii")
            and digest == DIGEST.encode("ascii"),
            "Host authorization outside allowed area",
        )
        payload = b":".join(command[:4])
        expected_mac = (
            hmac.new(secret.encode("ascii"), AUTH_DOMAIN + payload, hashlib.sha256)
            .hexdigest()
            .encode("ascii")
        )
        _require(hmac.compare_digest(received_mac, expected_mac), "Invalid host write capability")

        # Reopen the exact serial-discovered disk; verify GPT and empty extent
        # again immediately before the one bounded mutation.
        observed_device, current = _read_identity(serial)
        _require(
            observed_device == device and current["diskGuid"] == preflight["diskGuid"],
            "Guest disk changed before write",
        )
        handle = os.open(device, os.O_RDWR | os.O_CLOEXEC | os.O_EXCL)
        try:
            _require(
                os.pread(handle, WRITE_LENGTH, WRITE_OFFSET) == bytes(WRITE_LENGTH),
                "Target scratch extent became occupied",
            )
            _require(
                os.pwrite(handle, PATTERN, WRITE_OFFSET) == WRITE_LENGTH,
                "Short bounded guest write",
            )
            os.fsync(handle)
            _require(
                os.pread(handle, WRITE_LENGTH, WRITE_OFFSET) == PATTERN,
                "Guest write readback differs",
            )
            gpt_after = inspect_gpt_fd(handle, disk_size_bytes=DISK_BYTES, sector_bytes=512)
        finally:
            os.close(handle)
        _require(
            gpt_after == {"diskGuid": preflight["diskGuid"], "partitions": preflight["partitions"]},
            "GPT changed during single bounded write",
        )
        report = {
            "schemaVersion": 1,
            "runId": run_id,
            "nonce": nonce,
            "serial": serial,
            "diskGuid": preflight["diskGuid"],
            "writeAttempted": True,
            "writeCompleted": True,
            "writeOffsetBytes": WRITE_OFFSET,
            "writeLengthBytes": WRITE_LENGTH,
            "markerAfterSha256": DIGEST,
            "gptUnchanged": True,
            "calamaresExecuted": False,
            "windowsEspTouched": False,
        }
        _report(fd, RESULT, report, secret)
        print("GASLUX_Q4OS_BOUND_GUEST_WRITE=PASS", flush=True)
        print("GASLUX_Q4OS_BOUND_GUEST_BYTES=4096", flush=True)
        if power_cut:
            # The host can only inject a cut AFTER fsync, the independent
            # GPT check and receipt of the authenticated completion report.
            # Remain running: no guest-initiated shutdown or fake power cut.
            _write_all(fd, POWER_CUT_READY + b"\n")
            _read_line(fd, 64)  # never acknowledged; host SIGKILLs QEMU
            raise BoundWriteRefusal("Host did not simulate abrupt QEMU power loss")
        finish = _read_line(fd, 256).split(b":")
        _require(len(finish) == 2 and finish[0] == FINISH, "Missing host finish")
        finish_mac = (
            hmac.new(secret.encode("ascii"), AUTH_DOMAIN + FINISH, hashlib.sha256)
            .hexdigest()
            .encode("ascii")
        )
        _require(hmac.compare_digest(finish[1], finish_mac), "Invalid host finish")
        return report
    finally:
        os.close(fd)


def main() -> int:
    try:
        run()
    except (BoundWriteRefusal, OSError, ValueError, UnicodeError) as exc:
        print(f"GASLUX_Q4OS_BOUND_WRITE_REFUSED={exc}", file=sys.stderr, flush=True)
        return 1
    os.execv("/bin/busybox", ["busybox", "poweroff", "-f"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
