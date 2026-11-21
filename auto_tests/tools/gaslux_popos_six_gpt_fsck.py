#!/usr/bin/env python3
"""Read-only FAT32/ext4 fsck on disposable six-GPT partition image copies.

Never opens a real block device; never writes the frozen RAW or child QCOW2.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from gaslux_popos_reuse_snapshot_gate import Refusal, command, need, new_file, regular, sha
from gaslux_popos_six_gpt_contract import BOOLEANS, PARTS, SECTOR, SIZE
from gaslux_popos_six_gpt_lab import (
    BASE_NAME,
    hosted,
    read_plan,
    verify_fs_types,
    verify_sfdisk_gpt,
    write_json_exclusive,
)


def copy_owned_partition(base: Path, dest: Path, start: int, sectors: int) -> None:
    """Extract byte-exact sparse copy into an exclusive regular file."""
    regular(base, length=SIZE)
    need(
        dest.parent == base.parent
        and dest.name
        in {f"fsck-{phase}-{number}.img" for phase in ("before", "after") for number in (1, 5, 6)}
        and type(start) is int
        and type(sectors) is int
        and start > 0
        and sectors > 0
        and start + sectors <= SIZE // SECTOR,
        "REFUSE_RECOVERY_UNPROVEN: invalid filesystem extraction resource/bounds",
    )
    output = new_file(dest, sectors * SECTOR)
    with base.open("rb", buffering=0) as src, output.open("r+b", buffering=0) as dst:
        src.seek(start * SECTOR)
        left = sectors * SECTOR
        while left:
            data = src.read(min(left, 4 * 1024**2))
            need(data, "REFUSE_RECOVERY_UNPROVEN: truncated filesystem source")
            if data.count(0) == len(data):
                dst.seek(len(data), os.SEEK_CUR)
            else:
                need(
                    dst.write(data) == len(data),
                    "REFUSE_RECOVERY_UNPROVEN: extracted filesystem short write",
                )
            left -= len(data)
        dst.flush()
        os.fsync(dst.fileno())


def verify_read_only_fsck(work: Path, phase: str) -> dict:
    hosted(work)
    need(phase in {"before", "after"}, "REFUSE_RECOVERY_UNPROVEN: unknown fsck phase")
    plan = read_plan(work)
    base = regular(work / BASE_NAME, length=SIZE)
    need(
        sha(base) == plan["backingSha256"],
        "REFUSE_RECOVERY_UNPROVEN: checkpoint changed before fsck",
    )
    gpt = verify_sfdisk_gpt(base)
    need(
        gpt["pmbrAndPrimary"] == plan["gpt"]["pmbrAndPrimary"]
        and gpt["secondary"] == plan["gpt"]["secondary"],
        "REFUSE_OUT_OF_WRITESET: GPT changed before fsck",
    )
    results = {}
    for number, filesystem in ((1, "vfat"), (5, "vfat"), (6, "ext4")):
        p = PARTS[number - 1]
        image = work / f"fsck-{phase}-{number}.img"
        try:
            copy_owned_partition(base, image, p.start, p.count)
            if filesystem == "vfat":
                command("fsck.fat", "-n", str(image), timeout=300)
            else:
                command("e2fsck", "-fn", str(image), timeout=900)
            results[str(number)] = {
                "filesystem": filesystem,
                "readOnlyFsckPassed": True,
                "startLba": p.start,
                "endLba": p.end,
            }
        finally:
            if image.exists():
                regular(image, length=p.count * SECTOR).unlink()
    need(
        verify_fs_types(base) == plan["filesystems"],
        "REFUSE_RECOVERY_UNPROVEN: filesystem type identity changed",
    )
    proof = {
        "schemaVersion": 1,
        "scenario": plan["scenario"],
        "transactionId": plan["transactionId"],
        "manifestSha256": plan["manifestSha256"],
        "phase": phase,
        "readOnlyFsckAllPassed": True,
        "filesystems": results,
        "frozenBackingSha256": plan["backingSha256"],
        "gptPrimarySecondaryUnchanged": True,
        "observationComplete": False,
        "sixGptQemuInstallationExecuted": False,
        **BOOLEANS,
    }
    write_json_exclusive(work / f"filesystem-fsck-{phase}.json", proof)
    print("GASLUX_POP_SIX_GPT_FSCK_READONLY_" + phase.upper() + "=1", flush=True)
    return proof


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--phase", choices=["before", "after"], required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify_read_only_fsck(args.work, args.phase), sort_keys=True))
    except (Refusal, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print("GASLUX_POP_SIX_GPT_FSCK_REFUSED=" + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
