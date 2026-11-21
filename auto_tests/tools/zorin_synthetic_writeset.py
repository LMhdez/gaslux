#!/usr/bin/env python3
"""Read-only byte-diff verifier for SMALL, private, synthetic Zorin GPT fixtures.

Never grants a write permission. The GPT parser is imported, unchanged, from
Safety #265. Missing that pinned external dependency is a hard failure.
This is not an independent attestation, an installer fence, or Windows rollback.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from jsonschema import Draft202012Validator
from libertix_disk_identity_gate import (
    DiskIdentityError,
    inspect_gpt_image,
    assert_snapshot_matches,
)

MAX_DISK = 64 * 1024 * 1024
BLOCK = 65536
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TX = re.compile(r"[a-f0-9]{32}\Z")
SCHEMA = Path(__file__).resolve().parents[2] / "schemas/zorin-synthetic-writeset-v1.schema.json"


class WriteSetRefused(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def insist(ok: bool, code: str) -> None:
    if not ok:
        raise WriteSetRefused(code)


@dataclass(frozen=True)
class Region:
    number: int
    part_guid: str
    offset: int
    length: int


@dataclass(frozen=True)
class SyntheticPolicy:
    transaction: str
    checkpoint_id: str
    disk_sha256: str
    vars_sha256: str
    esp_sha256: str
    expected_disk: dict
    esp: Region
    linux: Region
    disk_bytes: int
    sector_bytes: int

    @classmethod
    def parse(cls, record: dict) -> "SyntheticPolicy":
        try:
            schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(record)
        except Exception as exc:
            raise WriteSetRefused("E_POLICY_SCHEMA") from exc
        insist(
            record["authorization"] == "DENY_NO_WRITER"
            and record["syntheticOnly"] is True
            and record["transactionOwned"] is False
            and record["externalAttestationVerified"] is False
            and record["writeOperations"] == [],
            "E_POLICY_GRANT",
        )
        insist(
            bool(TX.fullmatch(record["transactionId"]))
            and bool(HEX64.fullmatch(record["checkpointSha256"]))
            and bool(HEX64.fullmatch(record["diskSha256"])),
            "E_POLICY_IDENTITY",
        )
        root = record["linux"]
        esp = record["esp"]
        disk = record["diskIdentity"]
        insist(
            disk["partitionStyle"] == "GPT"
            and disk["sizeBytes"] == record["diskBytes"]
            and disk["logicalSectorSizeBytes"] == record["logicalSectorBytes"]
            and 16 * 1024**2 <= record["diskBytes"] <= MAX_DISK
            and record["logicalSectorBytes"] in (512, 4096),
            "E_POLICY_GEOMETRY",
        )
        parts = disk["partitions"]
        insist(
            type(parts) is list
            and len(parts) >= 3
            and len({p["number"] for p in parts}) == len(parts),
            "E_POLICY_PARTITIONS",
        )
        for part, expected in ((root, "LINUX_ROOT"), (esp, "ESP")):
            matches = [p for p in parts if p["number"] == part["number"]]
            insist(
                len(matches) == 1
                and matches[0]["partGuid"] == part["partGuid"]
                and matches[0]["offsetBytes"] == part["offsetBytes"]
                and matches[0]["sizeBytes"] == part["sizeBytes"]
                and part["role"] == expected,
                "E_POLICY_PARTITION_ID",
            )
        ordered = sorted(parts, key=lambda p: p["offsetBytes"])
        insist(
            all(
                a["offsetBytes"] + a["sizeBytes"] <= b["offsetBytes"]
                for a, b in zip(ordered, ordered[1:])
            ),
            "E_POLICY_OVERLAP",
        )
        insist(
            root["number"] != esp["number"]
            and root["offsetBytes"] >= record["logicalSectorBytes"] * 34
            and root["offsetBytes"] + root["sizeBytes"]
            <= record["diskBytes"] - record["logicalSectorBytes"] * 34
            and record["ownerLabel"] == "GASLUX-ZORIN-SYNTHETIC"
            and record["writeSet"] == ["LINUX_ROOT_BYTES_ONLY"],
            "E_FOREIGN_OWNER",
        )
        return cls(
            transaction=record["transactionId"],
            checkpoint_id=record["checkpointId"],
            disk_sha256=record["diskSha256"],
            vars_sha256=record["ovmfVarsSha256"],
            esp_sha256=record["espTreeSha256"],
            expected_disk=disk,
            esp=Region(esp["number"], esp["partGuid"], esp["offsetBytes"], esp["sizeBytes"]),
            linux=Region(root["number"], root["partGuid"], root["offsetBytes"], root["sizeBytes"]),
            disk_bytes=record["diskBytes"],
            sector_bytes=record["logicalSectorBytes"],
        )


def directory_guard(root: Path) -> None:
    insist(
        root.name.startswith("gaslux-zorin-writeset-")
        and root.is_absolute()
        and root.resolve() == root
        and not root.is_symlink(),
        "E_FOREIGN_WORKSPACE",
    )
    s = root.lstat()
    insist(
        stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700,
        "E_FOREIGN_WORKSPACE",
    )


def owned_fd(root: Path, name: str, max_bytes: int):
    insist("/" not in name and name not in (".", ".."), "E_PATH")
    path = root / name
    try:
        st = path.lstat()
        insist(
            stat.S_ISREG(st.st_mode)
            and st.st_uid == os.getuid()
            and st.st_nlink == 1
            and 0 < st.st_size <= max_bytes
            and st.st_dev == root.stat().st_dev,
            "E_FOREIGN_FILE",
        )
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            got = os.fstat(fd)
            insist(
                (got.st_dev, got.st_ino, got.st_size, got.st_mtime_ns)
                == (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns),
                "E_SOURCE_RACE",
            )
        except Exception:
            os.close(fd)
            raise
        return fd, got
    except (OSError, ValueError) as exc:
        if isinstance(exc, WriteSetRefused):
            raise
        raise WriteSetRefused("E_FOREIGN_FILE") from exc


def digest_fd(fd: int, size: int) -> str:
    h = hashlib.sha256()
    for offset in range(0, size, BLOCK):
        length = min(BLOCK, size - offset)
        content = os.pread(fd, length, offset)
        insist(len(content) == length, "E_TRUNCATED_SOURCE")
        h.update(content)
    return h.hexdigest()


def close_guard(fd: int, original: os.stat_result) -> None:
    now = os.fstat(fd)
    insist(
        (now.st_dev, now.st_ino, now.st_size, now.st_mtime_ns)
        == (original.st_dev, original.st_ino, original.st_size, original.st_mtime_ns),
        "E_SOURCE_RACE",
    )


def tree_digest(root: Path, folder: str) -> str:
    base = root / folder
    insist(
        not base.is_symlink() and base.is_dir() and base.lstat().st_uid == os.getuid(), "E_ESP_TREE"
    )
    inventory = []
    def descend(directory: Path, prefix: str) -> None:
        insist(len(inventory) <= 128, "E_ESP_TREE_OVERSIZE")
        for entry in sorted(os.scandir(directory), key=lambda x: x.name):
            insist(
                re.fullmatch(r"[A-Za-z0-9_.+-]{1,80}", entry.name) is not None
                and entry.name not in (".", ".."),
                "E_ESP_PATH",
            )
            relative = prefix + entry.name
            st = entry.stat(follow_symlinks=False)
            insist(st.st_uid == os.getuid() and st.st_dev == root.stat().st_dev, "E_ESP_FOREIGN")
            if stat.S_ISDIR(st.st_mode):
                descend(Path(entry.path), relative + "/")
                continue
            insist(
                stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= 1024 * 1024,
                "E_ESP_FOREIGN",
            )
            fd = os.open(entry.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                f = os.fstat(fd)
                insist(
                    (f.st_dev, f.st_ino, f.st_size) == (st.st_dev, st.st_ino, st.st_size),
                    "E_ESP_RACE",
                )
                inventory.append((relative, digest_fd(fd, st.st_size)))
                close_guard(fd, st)
            finally:
                os.close(fd)
    descend(base, "")
    insist(len(inventory) <= 128, "E_ESP_TREE_OVERSIZE")
    return hashlib.sha256(
        json.dumps(inventory, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def read_gpt(root: Path, name: str, policy: SyntheticPolicy) -> dict:
    try:
        return inspect_gpt_image(root / name, logical_sector_size=policy.sector_bytes)
    except (DiskIdentityError, OSError, ValueError) as exc:
        raise WriteSetRefused("E_GPT_INVALID") from exc


def compare_raw(a: int, b: int, policy: SyntheticPolicy) -> int:
    count = 0
    linux = policy.linux
    for offset in range(0, policy.disk_bytes, BLOCK):
        length = min(BLOCK, policy.disk_bytes - offset)
        old = os.pread(a, length, offset)
        new = os.pread(b, length, offset)
        insist(len(old) == length and len(new) == length, "E_TRUNCATED_SOURCE")
        if old == new:
            continue
        for i, (p, q) in enumerate(zip(old, new)):
            if p == q:
                continue
            index = offset + i
            if index < policy.sector_bytes * 34 or index >= (
                policy.disk_bytes - policy.sector_bytes * 34
            ):
                raise WriteSetRefused("E_GPT_BYTES_CHANGED")
            if policy.esp.offset <= index < policy.esp.offset + policy.esp.length:
                raise WriteSetRefused("E_ESP_PARTITION_CHANGED")
            if not linux.offset <= index < linux.offset + linux.length:
                raise WriteSetRefused("E_OUTSIDE_LINUX_CHANGED")
            count += 1
    return count


def verify_private_synthetic(root: Path, record: dict) -> dict:
    """Read only: GPT parser + independent reference/checkpoint + full byte diff."""
    directory_guard(root)
    policy = SyntheticPolicy.parse(record)
    fds = {}
    try:
        for name, limit in (
            ("baseline.raw", MAX_DISK),
            ("trial.raw", MAX_DISK),
            ("checkpoint.raw", MAX_DISK),
            ("ovmf-base.fd", 1024 * 1024),
            ("ovmf-trial.fd", 1024 * 1024),
        ):
            fds[name] = owned_fd(root, name, limit)
        insist(
            len({(s.st_dev, s.st_ino) for _, s in fds.values()}) == len(fds),
            "E_SHARED_BACKING_OR_HARDLINK",
        )
        for name in ("baseline.raw", "checkpoint.raw"):
            insist(stat.S_IMODE(fds[name][1].st_mode) & 0o222 == 0, "E_REFERENCE_WRITABLE")
        receipt_fd, receipt_stat = owned_fd(root, "receipt.json", 4096)
        try:
            receipt = json.loads(os.read(receipt_fd, receipt_stat.st_size))
            insist(
                type(receipt) is dict
                and set(receipt)
                == {"transactionId", "checkpointId", "baselineSha256", "provenance"}
                and receipt["transactionId"] == policy.transaction
                and receipt["checkpointId"] == policy.checkpoint_id
                and receipt["baselineSha256"] == policy.disk_sha256
                and receipt["provenance"] == "SYNTHETIC_UNATTESTED",
                "E_FOREIGN_TRANSACTION",
            )
            close_guard(receipt_fd, receipt_stat)
        except (ValueError, UnicodeDecodeError) as exc:
            if isinstance(exc, WriteSetRefused):
                raise
            raise WriteSetRefused("E_EVIDENCE_JSON") from exc
        finally:
            os.close(receipt_fd)
        for name in ("baseline.raw", "trial.raw", "checkpoint.raw"):
            insist(fds[name][1].st_size == policy.disk_bytes, "E_DISK_SIZE_CHANGED")
        insist(
            digest_fd(fds["baseline.raw"][0], fds["baseline.raw"][1].st_size) == policy.disk_sha256,
            "E_BASELINE_CHANGED",
        )
        insist(
            digest_fd(fds["checkpoint.raw"][0], fds["checkpoint.raw"][1].st_size)
            == record["checkpointSha256"]
            == policy.disk_sha256,
            "E_CHECKPOINT_CHANGED",
        )
        insist(
            digest_fd(fds["ovmf-base.fd"][0], fds["ovmf-base.fd"][1].st_size) == policy.vars_sha256,
            "E_OVMF_BASE_CHANGED",
        )
        insist(
            digest_fd(fds["ovmf-trial.fd"][0], fds["ovmf-trial.fd"][1].st_size)
            == policy.vars_sha256,
            "E_OVMF_CHANGED",
        )
        insist(tree_digest(root, "esp-base") == policy.esp_sha256, "E_ESP_BASE_CHANGED")
        insist(tree_digest(root, "esp-trial") == policy.esp_sha256, "E_ESP_FILES_CHANGED")
        start = read_gpt(root, "baseline.raw", policy)
        end = read_gpt(root, "trial.raw", policy)
        try:
            assert_snapshot_matches(policy.expected_disk, start)
        except DiskIdentityError as exc:
            raise WriteSetRefused("E_DISK_REFERENCE_CHANGED") from exc
        old_parts = {x["number"]: x for x in start["partitions"]}
        new_parts = {x["number"]: x for x in end["partitions"]}
        if set(old_parts) == set(new_parts):
            if any(old_parts[n]["partGuid"] != new_parts[n]["partGuid"] for n in old_parts):
                raise WriteSetRefused("E_PARTUUID_CHANGED")
        try:
            assert_snapshot_matches(start, end)
        except DiskIdentityError as exc:
            raise WriteSetRefused("E_GPT_IDENTITY_CHANGED") from exc
        changed = compare_raw(fds["baseline.raw"][0], fds["trial.raw"][0], policy)
        insist(
            digest_fd(fds["baseline.raw"][0], fds["baseline.raw"][1].st_size) == policy.disk_sha256,
            "E_BASELINE_CHANGED",
        )
        insist(
            digest_fd(fds["checkpoint.raw"][0], fds["checkpoint.raw"][1].st_size)
            == policy.disk_sha256,
            "E_CHECKPOINT_CHANGED",
        )
        insist(
            digest_fd(fds["ovmf-base.fd"][0], fds["ovmf-base.fd"][1].st_size) == policy.vars_sha256
            and digest_fd(fds["ovmf-trial.fd"][0], fds["ovmf-trial.fd"][1].st_size)
            == policy.vars_sha256,
            "E_OVMF_CHANGED",
        )
        insist(
            tree_digest(root, "esp-base") == policy.esp_sha256
            and tree_digest(root, "esp-trial") == policy.esp_sha256,
            "E_ESP_FILES_CHANGED",
        )
        for fd, original in fds.values():
            close_guard(fd, original)
        return {
            "result": "SYNTHETIC_ONLY_WITHIN_ROOT" if changed else "SYNTHETIC_NO_CHANGE",
            "changedLinuxBytes": changed,
            "transactionId": policy.transaction,
            "checkpointId": policy.checkpoint_id,
            "authorization": "DENY_NO_WRITER",
            "independentRecoveryAttested": False,
            "windowsRollbackVerified": False,
            "productionWriteAuthorized": False,
        }
    finally:
        for fd, _ in fds.values():
            os.close(fd)


def load_policy(root: Path) -> dict:
    directory_guard(root)
    fd, st = owned_fd(root, "policy.json", 65536)
    try:
        return json.loads(os.read(fd, st.st_size).decode("utf-8", "strict"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise WriteSetRefused("E_POLICY_JSON") from exc
    finally:
        os.close(fd)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-synthetic-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                verify_private_synthetic(
                    args.private_synthetic_root, load_policy(args.private_synthetic_root)
                ),
                sort_keys=True,
            )
        )
    except WriteSetRefused as exc:
        print(
            json.dumps({"authorization": "DENY_NO_WRITER", "result": "REFUSED", "code": exc.code})
        )
        raise SystemExit(2)
