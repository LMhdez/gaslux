#!/usr/bin/env python3
"""Read-only Pop live witness for the EXACT six-GPT genuine Win10 QEMU child.

Runs from the hash-checked, read-only, separately booted laboratory FAT media.
NEVER format, mount Windows or an owned partition, install Linux or touch EFI.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

from windows10_popos_live_readonly_gpt_probe import (
    VM_ONLY_CONSENT, probe_linux_guest_gpt,
)
from windows_x64_installed_gpt_ro_audit import DiskAuditError, require


def run() -> dict:
    require(os.geteuid() == 0, "Pop live witness requires guest root")
    info = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if line.startswith(("ID=", "VERSION_ID=")):
            key, value = line.split("=", 1)
            info[key] = value.strip().strip('"')
    require(info.get("ID") == "pop" and info.get("VERSION_ID") == "24.04",
            "the authenticated media did not boot Pop 24.04 live")
    control = Path("/run/gaslux-pop-lab")
    require(control.is_dir() and not control.is_symlink(),
            "trusted lab control mount missing")
    require(
        os.environ.get("GASLUX_POP_LIVE_GPT_RO_CONSENT") == VM_ONLY_CONSENT,
        "read-only guest GPT consent missing",
    )
    with (control / "win10-six-gpt-input.json").open(encoding="utf-8") as source:
        evidence = json.load(source)
    require(type(evidence) is dict
            and set(evidence) == {
                "before", "after", "plan", "stageReport", "media", "guest",
            },
            "unexpected signed-input-shaped Windows lab control document")
    media = evidence["media"]
    require(type(media) is dict
            and media.get("upstreamId") == "pop"
            and media.get("version") == "24.04",
            "untrusted Pop live guest media identity claim")
    agent = Path("/usr/bin/distinst")
    require(agent.is_file() and not agent.is_symlink(),
            "native System76 distinst absent in Pop live guest")
    with agent.open("rb") as file:
        actual_agent_sha = hashlib.file_digest(file, "sha256").hexdigest()
    require(actual_agent_sha == media.get("distinstSha256"),
            "live System76 native installer differs from authenticated ISO bytes")
    output = probe_linux_guest_gpt(
        evidence["before"], evidence["after"], evidence["plan"],
        evidence["stageReport"], media, evidence["guest"],
    )
    require(output.get("primaryAndBackupGptCrcVerified") is True
            and output.get("diskWritePerformed") is False
            and output.get("distinstExecutionAuthorized") is False
            and output.get("hostedGuestIdentityAttested") is False
            and output["candidate"]["distinstExecutionAuthorized"] is False,
            "live guest readonly audit must never issue installation authority")
    return {
        "schemaVersion": 1,
        "source": "popos-24.04-intel-verified-live-guest",
        "nativeAgentSha256": actual_agent_sha,
        "guestGpt": output,
        "nativeInstallationExecuted": False,
        "rollbackVerified": False,
    }


if __name__ == "__main__":
    try:
        result = run()
    except (DiskAuditError, ValueError, OSError, KeyError, TypeError) as exc:
        print("GASLUX_POP_LIVE_WINDOWS_GPT_REFUSED=" + str(exc), flush=True)
        sys.exit(1)
    print(
        "GASLUX_POP_LIVE_WINDOWS_GPT_EVIDENCE_JSON="
        + json.dumps(result, sort_keys=True, separators=(",", ":")),
        flush=True,
    )
    print("GASLUX_POP_LIVE_GENUINE_WIN10_COW_GPT_VERIFIED=1", flush=True)
