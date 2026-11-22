#!/usr/bin/env python3
"""Prepare/recover a Windows-free six-GPT Pop lab using regular files ONLY.

NO distinst invocation, QEMU guest, block device, Windows source or writer
permission. This is preflight/checkpoint evidence for a later Safety review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import uuid
from pathlib import Path

from gaslux_popos_reuse_snapshot_gate import (
    Refusal,
    chain,
    command,
    make_child,
    need,
    new_file,
    region_hash,
    regular,
    sha,
    system_ovmf_template,
)
from gaslux_popos_six_gpt_contract import (
    BOOLEANS,
    CONSENT,
    COUNT,
    DISK_GUID,
    DISTINST_SHA256,
    ISO_SHA256,
    PARTS,
    PROTECTED,
    PROTECTED_ESP_FILE,
    SCENARIO,
    SECTOR,
    SERIAL,
    SIZE,
    SYSTEM76_GPG_FPR,
    UNALLOCATED_CANARIES,
    canonical_digest,
    validate_geometry,
    validate_plan,
)

BASE_NAME = "prepared-six.raw"
CHILD_NAME = "owned-six-child.qcow2"
PLAN_NAME = "pop-six-transaction.json"
TRANSACTION_NAME = "transaction.id"
OVMF_NAME = "ovmf-original-install.fd"
OVMF_BOOT_NAME = "ovmf-original-firstboot.fd"
ESP_MARKER = b"GASLUX SIX-GPT SYNTHETIC PROTECTED ESP - NO WINDOWS FILES\n"


def hosted(work: Path) -> None:
    need(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("GASLUX_POP_SIX_GPT_CONSENT") == CONSENT,
        "REFUSE_IDENTITY_MISMATCH: hosted no-writer consent missing",
    )
    parent = Path(os.environ.get("RUNNER_TEMP", "/not-a-runner"))
    need(
        parent.is_absolute()
        and parent.is_dir()
        and not parent.is_symlink()
        and Path(os.path.realpath(parent)) == parent
        and work.parent == parent
        and work.name.startswith("gaslux-pop-six-gpt-")
        and work.is_dir()
        and not work.is_symlink()
        and work.stat().st_uid == os.geteuid()
        and stat.S_IMODE(work.stat().st_mode) == 0o700,
        "REFUSE_IDENTITY_MISMATCH: untrusted private runner directory",
    )


def sha_region(path: Path, sector: int, count: int) -> str:
    regular(path, length=SIZE)
    need(
        type(sector) is int
        and type(count) is int
        and sector >= 0
        and count > 0
        and sector + count <= COUNT,
        "REFUSE_IDENTITY_MISMATCH: invalid protected sector window",
    )
    h = hashlib.sha256()
    with path.open("rb", buffering=0) as f:
        f.seek(sector * SECTOR)
        remaining = count * SECTOR
        while remaining:
            data = f.read(min(remaining, 8 * 1024**2))
            need(data, "REFUSE_IDENTITY_MISMATCH: short protected window")
            h.update(data)
            remaining -= len(data)
    return h.hexdigest()


def sector_bytes(path: Path, lba: int) -> bytes:
    regular(path, length=SIZE)
    need(0 <= lba < COUNT, "REFUSE_IDENTITY_MISMATCH: invalid canary sector")
    with path.open("rb", buffering=0) as f:
        f.seek(lba * SECTOR)
        data = f.read(SECTOR)
    need(len(data) == SECTOR, "REFUSE_IDENTITY_MISMATCH: missing canary")
    return data


def write_canary(path: Path, lba: int, txid: str, role: str) -> dict:
    # Only during preparation, on a NEW disposable RAW, never after freeze.
    need(
        role in {"protected-msr", "protected-data", "protected-recovery", "unallocated"}
        and 0 < lba < COUNT - 33,
        "REFUSE_OUT_OF_WRITESET: invalid precheckpoint canary",
    )
    label = f"GASLUX_SYNTHETIC_CANARY:{txid}:{role}:{lba}".encode("ascii")
    payload = (label + b"\n" + b"\xa5" * SECTOR)[:SECTOR]
    with path.open("r+b", buffering=0) as f:
        f.seek(lba * SECTOR)
        need(f.write(payload) == SECTOR, "synthetic canary short write")
        os.fsync(f.fileno())
    return {"lba": lba, "role": role, "sectorSha256": hashlib.sha256(payload).hexdigest()}


def verify_sfdisk_gpt(path: Path) -> dict:
    """Use authoritative sgdisk CRC verification + sfdisk JSON; NO GPT parser."""
    regular(path, length=SIZE)
    command("sgdisk", "--verify", str(path), timeout=120)
    table = json.loads(command("sfdisk", "--json", str(path), timeout=60))["partitiontable"]
    need(
        table.get("label") == "gpt"
        and table.get("id", "").lower() == DISK_GUID
        and table.get("unit") == "sectors",
        "REFUSE_IDENTITY_MISMATCH: disk GPT identity/table missing",
    )
    rows = table.get("partitions", [])
    need(len(rows) == 6, "REFUSE_IDENTITY_MISMATCH: unexpected GPT entries")
    for expected, actual in zip(PARTS, rows, strict=True):
        need(
            type(actual.get("start")) is int
            and type(actual.get("size")) is int
            and actual["start"] == expected.start
            and actual["size"] == expected.count
            and str(actual.get("type", "")).lower() == expected.type_guid
            and str(actual.get("uuid", "")).lower() == expected.partuuid,
            "REFUSE_IDENTITY_MISMATCH: GPT LBA/type/PARTUUID changed",
        )
    return {
        "diskGuid": DISK_GUID,
        "primaryAndBackupCrcVerified": True,
        "pmbrAndPrimary": region_hash(path, 0, 34),
        "secondary": region_hash(path, COUNT - 33, 33),
        "partitions": [p.as_dict() for p in PARTS],
    }


def verify_esp_canary(base: Path, expected_hash: str, work: Path) -> None:
    # Read protected simulated ESP via mtools without any write to disk image.
    output = work / "readback-protected-esp-canary.tmp"
    need(
        not output.exists() and not output.is_symlink(),
        "REFUSE_IDENTITY_MISMATCH: foreign ESP readback resource",
    )
    try:
        command(
            "mcopy",
            "-i",
            f"{base}@@{PARTS[0].start * SECTOR}",
            PROTECTED_ESP_FILE,
            str(output),
            timeout=60,
        )
        need(
            sha(regular(output)) == expected_hash,
            "REFUSE_OUT_OF_WRITESET: protected ESP file changed",
        )
    finally:
        if output.exists():
            regular(output).unlink()


def verify_fs_types(base: Path) -> dict:
    # blkid reads windows on a regular file; no /dev/loop or physical devices.
    results = {}
    for p, expected in ((PARTS[0], "vfat"), (PARTS[4], "vfat"), (PARTS[5], "ext4")):
        found = command(
            "blkid",
            "-p",
            "-s",
            "TYPE",
            "-o",
            "value",
            "-O",
            str(p.start * SECTOR),
            "-S",
            str(p.count * SECTOR),
            str(base),
        )
        need(found.strip() == expected, "REFUSE_IDENTITY_MISMATCH: synthetic FAT32/ext4 unexpected")
        results[str(p.index)] = found.strip()
    return results


def verify_canaries(base: Path, plan: dict, work: Path) -> None:
    for p in PROTECTED:
        need(
            sha_region(base, p.start, p.count) == plan["protectedPartitionHashes"][str(p.index)],
            "REFUSE_OUT_OF_WRITESET: protected partition changed",
        )
    for item in plan["canaries"]:
        need(
            hashlib.sha256(sector_bytes(base, item["lba"])).hexdigest() == item["sectorSha256"],
            "REFUSE_OUT_OF_WRITESET: protected/unallocated canary changed",
        )
    verify_esp_canary(base, plan["protectedEspFileSha256"], work)


class ProtectedFaultDetected(Exception):
    """A specific owned QCOW2 extent was independently proven allocated."""


def parse_qcow_map(raw: str, *, require_full: bool = True) -> list[dict]:
    try:
        rows = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise Refusal("REFUSE_RECOVERY_UNPROVEN: malformed qemu-img JSON") from exc
    need(isinstance(rows, list) and bool(rows), "REFUSE_RECOVERY_UNPROVEN: absent qemu-img map")
    cursor = 0
    allowed = {"start", "length", "depth", "data", "zero", "offset", "present"}
    for row in rows:
        need(
            isinstance(row, dict)
            and {"start", "length", "depth", "data", "zero"} <= row.keys()
            and row.keys() <= allowed,
            "REFUSE_RECOVERY_UNPROVEN: unknown/incomplete extent keys="
            + str(sorted(row) if isinstance(row, dict) else type(row).__name__),
        )
        start, length, depth = (row[k] for k in ("start", "length", "depth"))
        need(
            all(type(v) is int for v in (start, length, depth))
            and type(row["data"]) is bool
            and type(row["zero"]) is bool
            and start == cursor
            and length > 0
            and depth >= 0
            and start + length <= SIZE,
            "REFUSE_RECOVERY_UNPROVEN: inconsistent extent geometry",
        )
        if "offset" in row:
            need(
                type(row["offset"]) is int and row["offset"] >= 0,
                "REFUSE_RECOVERY_UNPROVEN: invalid extent offset",
            )
        if "present" in row:
            need(type(row["present"]) is bool, "REFUSE_RECOVERY_UNPROVEN: invalid present flag")
        cursor += length
    if require_full:
        need(cursor == SIZE, "REFUSE_RECOVERY_UNPROVEN: incomplete QCOW2 map")
    return rows


def child_owned_extents(child: Path, base: Path) -> list[dict]:
    chain(child, base)
    rows = parse_qcow_map(command("qemu-img", "map", "--output=json", str(child), timeout=120))
    # depth=0 data=false zero=true is an allocated overlay mask, not empty.
    return [
        r for r in rows if r["depth"] == 0 and (r["data"] or r["zero"] or r.get("present") is True)
    ]


def ensure_empty_child(child: Path, base: Path) -> None:
    need(
        not child_owned_extents(child, base),
        "REFUSE_RECOVERY_UNPROVEN: synthetic child contains owned extents",
    )


def verify_injected_fault(child: Path, base: Path, offset: int, length: int) -> None:
    need(
        type(offset) is int
        and type(length) is int
        and offset >= 0
        and length == 4096
        and offset + length <= SIZE,
        "REFUSE_RECOVERY_UNPROVEN: invalid injected interval",
    )
    owned = child_owned_extents(child, base)
    need(
        any(
            r["start"] <= offset
            and r["start"] + r["length"] >= offset + length
            and r["data"] is True
            for r in owned
        ),
        "REFUSE_RECOVERY_UNPROVEN: injected write not materialized",
    )
    raise ProtectedFaultDetected("independent protected child allocation observed")


def private_ovmf_copy(template: Path, out: Path) -> str:
    template = system_ovmf_template(template)
    need(
        not out.exists() and not out.is_symlink(),
        "REFUSE_IDENTITY_MISMATCH: foreign OVMF VARS file",
    )
    new_file(out, template.stat().st_size)
    with template.open("rb") as source, out.open("r+b") as dest:
        shutil.copyfileobj(source, dest)
        dest.flush()
        os.fsync(dest.fileno())
    need(sha(out) == sha(template), "REFUSE_RECOVERY_UNPROVEN: OVMF copy differs")
    return sha(out)


def prepare(work: Path, template: Path) -> dict:
    hosted(work)
    validate_geometry()
    base = new_file(work / BASE_NAME, SIZE)
    txid = str(uuid.uuid4())
    for p in PARTS:
        need(p.start % 2048 == 0, "GPT LBA not 1MiB aligned")
    args = ["sgdisk", "--zap-all", "--clear", "--disk-guid=" + DISK_GUID]
    for p in PARTS:
        args.extend(
            (
                f"--new={p.index}:{p.start}:{p.end}",
                f"--typecode={p.index}:{p.type_guid}",
                f"--partition-guid={p.index}:{p.partuuid}",
                f"--change-name={p.index}:GASLUX-SYNTHETIC-{p.index}",
            )
        )
    command(*args, str(base), timeout=120)
    baseline = verify_sfdisk_gpt(base)
    # All formatters touch only this new, private, precheckpoint regular file.
    for p, label in ((PARTS[0], "SYNPROTESP"), (PARTS[4], "SYNPOPESP")):
        command(
            "mkfs.fat",
            "-F",
            "32",
            "-s",
            "8",
            "-n",
            label,
            "--offset=" + str(p.start),
            str(base),
            str(p.count // 2),
            timeout=600,
        )
        need(verify_sfdisk_gpt(base) == baseline, "REFUSE_OUT_OF_WRITESET: FAT32 changed GPT")
    root = PARTS[5]
    command(
        "mkfs.ext4",
        "-F",
        "-q",
        "-b",
        "4096",
        "-L",
        "SYNPOPROOT",
        "-E",
        "offset=" + str(root.start * SECTOR),
        str(base),
        str(root.count // 8),
        timeout=600,
    )
    need(verify_sfdisk_gpt(base) == baseline, "REFUSE_OUT_OF_WRITESET: ext4 changed GPT")
    # Protected ESP contains a SIMULATED canary, not a Windows bootloader.
    marker = work / "synthetic-esp-marker.tmp"
    with os.fdopen(
        os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb"
    ) as out:
        out.write(ESP_MARKER + txid.encode("ascii") + b"\n")
        out.flush()
        os.fsync(out.fileno())
    esp_image = f"{base}@@{PARTS[0].start * SECTOR}"
    command("mmd", "-i", esp_image, "::/EFI")
    command("mmd", "-i", esp_image, "::/EFI/Microsoft")
    command("mcopy", "-i", esp_image, str(marker), PROTECTED_ESP_FILE)
    file_hash = sha(marker)
    marker.unlink()
    entries = []
    for p in PARTS[1:4]:
        entries.append(
            write_canary(base, p.start + 8, txid, "protected-" + p.role.rsplit("-", 1)[-1])
        )
    for sector in UNALLOCATED_CANARIES:
        entries.append(write_canary(base, sector, txid, "unallocated"))
    need(len(entries) == 7, "synthetic canary inventory incomplete")
    need(
        verify_sfdisk_gpt(base) == baseline,
        "REFUSE_OUT_OF_WRITESET: synthetic canaries changed GPT",
    )
    filesystem_types = verify_fs_types(base)
    protected_hashes = {str(p.index): sha_region(base, p.start, p.count) for p in PROTECTED}
    os.chmod(base, 0o400)
    backing_sha = sha(base)
    template = system_ovmf_template(template)
    ovmf_hash = sha(template)
    private_ovmf_copy(template, work / OVMF_NAME)
    private_ovmf_copy(template, work / OVMF_BOOT_NAME)
    make_child(work / CHILD_NAME, base)
    plan = {
        "schemaVersion": 1,
        "scenario": SCENARIO,
        "transactionId": txid,
        "disk": {
            "sizeBytes": SIZE,
            "logicalSectorBytes": SECTOR,
            "guid": DISK_GUID,
            "virtioSerial": SERIAL,
        },
        "partitions": [p.as_dict() for p in PARTS],
        "media": {
            "isoSha256": ISO_SHA256,
            "distinstSha256": DISTINST_SHA256,
            "system76GpgFingerprint": SYSTEM76_GPG_FPR,
            "isoIndependentlyAuthenticatedHere": False,
        },
        "distinstReuseArgv": [
            "--no-efi-vars",
            "--use",
            ":5:reuse:mount=/boot/efi",
            "--use",
            ":6:reuse:mount=/",
        ],
        "gpt": {"pmbrAndPrimary": baseline["pmbrAndPrimary"], "secondary": baseline["secondary"]},
        "backingSha256": backing_sha,
        "protectedPartitionHashes": protected_hashes,
        "protectedEspFileSha256": file_hash,
        "canaries": entries,
        "ovmfTemplateSha256": ovmf_hash,
        "filesystems": filesystem_types,
        "onlyWritableGuestDisk": "owned-qcow2-child",
        "recoveryMode": "discard-private-child-recreate",
        "windowsAttached": False,
        "physicalDisksAttached": False,
        **BOOLEANS,
    }
    plan["manifestSha256"] = canonical_digest(plan)
    write_json_exclusive(work / PLAN_NAME, plan)
    write_text_exclusive(work / TRANSACTION_NAME, txid + "\n")
    validate_plan(plan, txid)
    verify_checkpoint(work, template)
    print("GASLUX_POP_SIX_GPT_PREPARED_NO_INSTALL=1", flush=True)
    return plan


def write_text_exclusive(path: Path, text: str) -> None:
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w"
    ) as out:
        out.write(text)
        out.flush()
        os.fsync(out.fileno())


def write_json_exclusive(path: Path, document: dict) -> None:
    write_text_exclusive(path, json.dumps(document, sort_keys=True, indent=2) + "\n")


def read_plan(work: Path) -> dict:
    txid = regular(work / TRANSACTION_NAME).read_text().strip()
    plan = json.loads(regular(work / PLAN_NAME).read_text())
    validate_plan(plan, txid)
    return plan


def verify_checkpoint(work: Path, template: Path) -> dict:
    hosted(work)
    plan = read_plan(work)
    base = regular(work / BASE_NAME, length=SIZE)
    need(
        stat.S_IMODE(base.stat().st_mode) == 0o400,
        "REFUSE_RECOVERY_UNPROVEN: backing not read-only",
    )
    need(sha(base) == plan["backingSha256"], "REFUSE_RECOVERY_UNPROVEN: backing SHA mismatch")
    gpt = verify_sfdisk_gpt(base)
    need(
        {k: gpt[k] for k in ("pmbrAndPrimary", "secondary")} == plan["gpt"],
        "REFUSE_OUT_OF_WRITESET: GPT primary/backup changed",
    )
    verify_canaries(base, plan, work)
    need(
        verify_fs_types(base) == plan["filesystems"],
        "REFUSE_RECOVERY_UNPROVEN: filesystem type changed",
    )
    template = system_ovmf_template(template)
    need(
        sha(template) == plan["ovmfTemplateSha256"],
        "REFUSE_RECOVERY_UNPROVEN: OVMF template changed",
    )
    for file in (OVMF_NAME, OVMF_BOOT_NAME):
        need(
            sha(regular(work / file)) == plan["ovmfTemplateSha256"],
            "REFUSE_RECOVERY_UNPROVEN: private OVMF variables altered",
        )
    ensure_empty_child(regular(work / CHILD_NAME, write=True), base)
    return {
        "status": "PREWRITE_ONLY",
        "sixPartitionsIdentityVerified": True,
        "protectedPartCanariesVerified": True,
        "backingImmutable": True,
        "gptPrimaryAndSecondaryVerified": True,
        "ovmfVarsPrivate": True,
        "childHasNoAllocations": True,
        "filesystemTypeIdentityVerified": True,
        "observationComplete": False,
        **BOOLEANS,
    }


def rehearse_recovery(work: Path, template: Path) -> dict:
    plan = read_plan(work)
    verify_checkpoint(work, template)
    base = regular(work / BASE_NAME, length=SIZE)
    fault = work / "fault-injected-child.qcow2"
    make_child(fault, base)
    sector = PARTS[2].start + 4096  # protected SIMULATED data partition
    ensure_empty_child(fault, base)
    command("qemu-io", "-f", "qcow2", "-c", f"write -P 0x5a {sector * SECTOR} 4096", str(fault))
    try:
        verify_injected_fault(fault, base, sector * SECTOR, 4096)
    except ProtectedFaultDetected:
        pass
    else:
        raise Refusal("REFUSE_RECOVERY_UNPROVEN: injected fault not detected")
    # Preserve injected child for forensic inspection; no pathname unlink.
    # Reconstruct a NEW transaction-owned COW with O_EXCL, then prove empty.
    recovered_child = work / "reconstructed-child.qcow2"
    make_child(recovered_child, base)
    ensure_empty_child(recovered_child, base)
    # Independent disposable fault-injected VARS. Never overwrite reference.
    template = system_ovmf_template(template)
    broken_vars = work / "fault-injected-vars.fd"
    private_ovmf_copy(template, broken_vars)
    with broken_vars.open("r+b") as f:
        f.seek(2048)
        f.write(b"GASLUX-SIX-OVMF-FAULT")
        f.flush()
        os.fsync(f.fileno())
    need(
        sha(broken_vars) != plan["ovmfTemplateSha256"],
        "REFUSE_RECOVERY_UNPROVEN: OVMF fault injection ineffective",
    )
    recovered_vars = work / "reconstructed-vars.fd"
    private_ovmf_copy(template, recovered_vars)
    need(
        sha(recovered_vars) == plan["ovmfTemplateSha256"],
        "REFUSE_RECOVERY_UNPROVEN: private VARS not restored",
    )
    # Both original and faulted artefacts are retained for runner disposal.
    verified = verify_checkpoint(work, template)
    proof = {
        "schemaVersion": 1,
        "scenario": SCENARIO,
        "transactionId": plan["transactionId"],
        "manifestSha256": plan["manifestSha256"],
        "independentProtectedFaultDetected": True,
        "ownedFaultChildDiscarded": False,
        "ownedFaultChildPreservedForForensics": True,
        "ownedFaultChildReconstructedEmpty": True,
        "backingAndProtectedRegionsRestoredByteExact": True,
        "gptAndPartuuidRestored": True,
        "privateOvmfVariablesRecovered": True,
        "filesystemIntegrityRecoveredByUnchangedCheckpoint": True,
        "preflight": verified,
        "observationComplete": False,
        "sixGptQemuInstallationExecuted": False,
        **BOOLEANS,
    }
    write_json_exclusive(work / "recovery-proof.json", proof)
    print("GASLUX_POP_SIX_GPT_CHECKPOINT_RECOVERY_PROVEN=1", flush=True)
    return proof


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["prepare", "preflight", "recover"])
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--ovmf-template", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            prepare(args.work, args.ovmf_template)
        elif args.action == "preflight":
            print(json.dumps(verify_checkpoint(args.work, args.ovmf_template), sort_keys=True))
        else:
            rehearse_recovery(args.work, args.ovmf_template)
    except (
        Refusal,
        OSError,
        ValueError,
        KeyError,
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
    ) as exc:
        print("GASLUX_POP_SIX_GPT_REFUSED=" + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
