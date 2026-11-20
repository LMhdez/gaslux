#!/usr/bin/env python3
"""Typed historical root candidate; not a signed installation plan or writer."""
from __future__ import annotations

import argparse
from dataclasses import dataclass, asdict
import json
from pathlib import Path


class TargetIdentityError(ValueError):
    pass


@dataclass(frozen=True)
class ObservedLinuxTarget:
    disk_guid_sha256: str
    disk_bytes: int
    logical_sector_bytes: int
    partition_index: int
    first_lba: int
    last_lba: int
    partuuid: str
    ext4_uuid: str
    gpt_label: str

    def validate(self) -> "ObservedLinuxTarget":
        if (self.disk_guid_sha256 !=
            "154c4cb5880b403f46877f178cf8cee987e3379428ae32fd59318d3efaa2c324"
            or type(self.disk_bytes) is not int or self.disk_bytes != 128 * 1024**3
            or type(self.logical_sector_bytes) is not int or self.logical_sector_bytes != 512
            or type(self.partition_index) is not int or self.partition_index != 5
            or type(self.first_lba) is not int or self.first_lba != 154707968
            or type(self.last_lba) is not int or self.last_lba != 205039615
            or self.partuuid != "99a1212c-0662-450f-a082-291f4ba71a15"
            or self.ext4_uuid != "6ffb16ae-6802-47a6-a766-0c49d2468581"
            or self.gpt_label != "GASLUX-CACHYOS-ROOT"):
            raise TargetIdentityError("historical fifth root identity changed")
        return self


def proposed_readonly_target(target: ObservedLinuxTarget) -> dict:
    t = target.validate()
    return {
        "schemaVersion": 1, "distribution": "zorin", "backend": "debian-squashfs",
        "mode": "READ_ONLY_CANDIDATE", "sourceAction": "44730944403",
        "sourceArtifact": "14627774087",
        "fifthEvidenceSha256": "b7da9a0d00b2367cc472cc79af4dea9408996dbe029c15ea5ae23d30815e1414",
        "gptEvidenceSha256": "cd1fe2df2ce7f6841fdf4bcee19969496fa8c17b996f5491ee72428821ff8ded",
        "target": asdict(t),
        "offsetBytes": t.first_lba * t.logical_sector_bytes,
        "sizeBytes": (t.last_lba-t.first_lba+1)*t.logical_sector_bytes,
        "requiredZorinOwnerLabel": "GASLUX-ZORIN-ROOT",
        "rawDiskGuidAuthenticated": False, "transactionOwned": False,
        "snapshotIndependentlyRestorable": False,
        "writeOperations": [], "authorization": "DENY_NO_WRITER",
        "nativeInstallerInvoked": False, "stable": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    obj = json.loads(args.fixture.read_text(encoding="utf-8"))
    if type(obj) is not dict or set(obj) != set(ObservedLinuxTarget.__dataclass_fields__):
        raise TargetIdentityError("missing or ambiguous target fields")
    args.out.write_text(json.dumps(proposed_readonly_target(ObservedLinuxTarget(**obj)),
                                   indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("DENY_NO_WRITER: historical root has a foreign GPT owner")


if __name__ == "__main__":
    main()
