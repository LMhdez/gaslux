#!/usr/bin/env python3
"""Read-only Windows EFI file integrity gate for a disposable shared-ESP lab.

This checks a synthetic Windows subtree, NOT a Windows installation or dual boot.
It does not write to the QEMU disk or authorize an actual shared-ESP install.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from gaslux_popos_gpt_ownership import DISK_SIZE, SECTOR_SIZE, GptRefusal, _header
from gaslux_popos_native_mock_windows_gpt_reconcile import (
    WINDOWS_ESP_END,
    WINDOWS_ESP_START,
    _validate_entries,
)

_BYTES = (WINDOWS_ESP_END - WINDOWS_ESP_START + 1) * SECTOR_SIZE
_REQUIRED = frozenset({"boot/bootmgfw.efi", "boot/bcd"})
_SNAPSHOT_KEYS = frozenset(
    {"version", "diskGuid", "espPartuuid", "espSha256", "windowsFiles"}
)


def _owned_image(image: Path) -> None:
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("CI") != "true"
        or os.environ.get("GASLUX_POP_SHARED_ESP_AUDIT") != "1"
    ):
        raise GptRefusal("Explicit GitHub Actions shared-ESP lab consent required")
    root = os.environ.get("RUNNER_TEMP")
    if (
        not root
        or image.name != "pop-target.raw"
        or not re.fullmatch(r"gaslux-pop-native-shared-[A-Za-z0-9]+", image.parent.name)
        or image.is_symlink()
        or image.parent.is_symlink()
        or not image.parent.is_relative_to(Path(root).resolve())
    ):
        raise GptRefusal("Not a strictly owned disposable VM raw disk")
    info = image.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_size != DISK_SIZE
        or info.st_nlink != 1
    ):
        raise GptRefusal("Unexpected VM disk type, capacity or hardlink count")


def _files_in_microsoft_tree(folder: Path) -> list[dict]:
    microsoft = folder / "Microsoft"
    if not microsoft.is_dir() or microsoft.is_symlink():
        raise GptRefusal("Windows EFI Microsoft directory missing")
    files = []
    seen: set[str] = set()
    total = 0
    for path in sorted(microsoft.rglob("*")):
        if path.is_symlink():
            raise GptRefusal("EFI extraction contains an unexpected symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise GptRefusal("EFI extraction contains a non-file")
        relative = path.relative_to(microsoft).as_posix()
        folded = relative.casefold()
        if folded in seen or any(p in {"", ".", ".."} for p in path.relative_to(microsoft).parts):
            raise GptRefusal("Ambiguous or unsafe EFI file name")
        seen.add(folded)
        size = path.stat().st_size
        total += size
        if size <= 0 or size > 128 * 1024 * 1024 or total > 256 * 1024 * 1024:
            raise GptRefusal("EFI file size outside bounded lab policy")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        files.append({"path": relative, "size": size, "sha256": digest.hexdigest()})
    if not _REQUIRED.issubset(seen):
        raise GptRefusal("Windows loader or BCD canary missing")
    return sorted(files, key=lambda value: value["path"].casefold())


def capture(image: Path) -> dict:
    _owned_image(image)
    with tempfile.TemporaryDirectory(prefix="efi-readonly-", dir=image.parent) as name:
        temp = Path(name)
        esp = temp / "windows-esp.img"
        with image.open("rb") as disk:
            mbr = disk.read(SECTOR_SIZE)
            primary, entries = _header(disk, 1)
            backup, mirrored = _header(disk, DISK_SIZE // SECTOR_SIZE - 1)
            if (
                len(mbr) != SECTOR_SIZE
                or mbr[510:512] != b"\x55\xaa"
                or mbr[450] != 0xEE
                or entries != mirrored
                or primary["diskGuid"] != backup["diskGuid"]
                or primary["current"] != 1
                or backup["current"] != DISK_SIZE // SECTOR_SIZE - 1
                or primary["alternate"] != backup["current"]
                or backup["alternate"] != 1
            ):
                raise GptRefusal("Protective MBR or GPT mirror mismatch")
            rows = [entries[n : n + 128].hex() for n in range(0, len(entries), 128)]
            _validate_entries(rows, installed=True)
            # The ONLY disk-region read is the known synthetic Windows ESP.
            # mtools sees a detached copy, never the original raw disk.
            disk.seek(WINDOWS_ESP_START * SECTOR_SIZE)
            digest = hashlib.sha256()
            remaining = _BYTES
            with esp.open("xb") as copy:
                while remaining:
                    block = disk.read(min(4 * 1024 * 1024, remaining))
                    if not block:
                        raise GptRefusal("Truncated synthetic Windows ESP")
                    copy.write(block)
                    digest.update(block)
                    remaining -= len(block)
        dest = temp / "extracted"
        dest.mkdir(mode=0o700)
        try:
            subprocess.run(
                ["mcopy", "-s", "-i", str(esp), "::/EFI/Microsoft", str(dest)],
                check=True,
                capture_output=True,
                timeout=60,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            raise GptRefusal("Cannot extract Windows EFI tree read-only") from exc
        from gaslux_popos_gpt_ownership import _root_entry

        return {
            "version": 1,
            "diskGuid": primary["diskGuid"],
            "espPartuuid": _root_entry(rows[0])["guid"],
            "espSha256": digest.hexdigest(),
            "windowsFiles": _files_in_microsoft_tree(dest),
        }


def verify(before: dict, after: dict) -> dict:
    if any(
        type(snapshot) is not dict or set(snapshot) != _SNAPSHOT_KEYS
        for snapshot in (before, after)
    ):
        raise GptRefusal("Unrecognised EFI snapshot schema")
    if before["version"] != 1 or after["version"] != 1:
        raise GptRefusal("Unsupported EFI snapshot version")
    for key in ("diskGuid", "espPartuuid"):
        if not isinstance(before[key], str) or not before[key] or before[key] != after[key]:
            raise GptRefusal(f"Windows EFI disk/partition identity changed: {key}")
    for snapshot in (before, after):
        if not isinstance(snapshot["espSha256"], str) or not re.fullmatch(
            "[0-9a-f]{64}", snapshot["espSha256"]
        ):
            raise GptRefusal("Malformed ESP content hash")
        files = snapshot["windowsFiles"]
        if (
            type(files) is not list
            or not files
            or any(
                type(f) is not dict
                or set(f) != {"path", "size", "sha256"}
                or type(f["path"]) is not str
                or not f["path"]
                or type(f["size"]) is not int
                or f["size"] <= 0
                or not isinstance(f["sha256"], str)
                or re.fullmatch("[0-9a-f]{64}", f["sha256"]) is None
                for f in files
            )
        ):
            raise GptRefusal("Malformed Microsoft EFI file manifest")
        names = [f["path"].casefold() for f in files]
        if len(set(names)) != len(names) or not _REQUIRED.issubset(names):
            raise GptRefusal("Duplicate or missing Windows EFI witnesses")
    if before["windowsFiles"] != after["windowsFiles"]:
        raise GptRefusal("Windows Microsoft EFI subtree was modified")
    return {
        "microsoftEfiFilesIdentical": True,
        "espWholePartitionBytesIdentical": before["espSha256"] == after["espSha256"],
        "windowsDualBootProven": False,
        "productionInstallationAuthorized": False,
    }


def main(arguments: list[str]) -> int:
    if len(arguments) != 3 or arguments[0] not in {"capture", "verify"}:
        raise GptRefusal("Usage: capture RAW_IMAGE esp-before.json | verify before.json after.json")
    a, b = map(Path, arguments[1:])
    if a.parent != b.parent or not re.fullmatch(
        r"gaslux-pop-native-shared-[A-Za-z0-9]+", a.parent.name
    ):
        raise GptRefusal("Evidence must remain inside the single disposable lab")
    if arguments[0] == "capture":
        if b.name not in {"esp-before.json", "esp-after.json"}:
            raise GptRefusal("Unexpected snapshot output path")
        snapshot = capture(a)
        b.write_text(json.dumps(snapshot, sort_keys=True) + "\n", encoding="utf-8")
    else:
        if a.name != "esp-before.json" or b.name != "esp-after.json":
            raise GptRefusal("Unexpected snapshot input path")
        proof = verify(
            json.loads(a.read_text(encoding="utf-8")),
            json.loads(b.read_text(encoding="utf-8")),
        )
        print("GASLUX_POP_SHARED_ESP_MICROSOFT_FILES_INTACT=1")
        print(json.dumps(proof, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (GptRefusal, OSError, ValueError, TypeError, KeyError) as error:
        print(f"GASLUX_POP_SHARED_ESP_REFUSAL: {error}", file=sys.stderr)
        sys.exit(1)
