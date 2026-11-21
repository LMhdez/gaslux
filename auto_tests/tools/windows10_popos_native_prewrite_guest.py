#!/usr/bin/env python3
"""Prewrite gate for native System76 on a separate QEMU child of real Win10.

OFF by default and incapable of formatting partitions or launching distinst.
The signed per-job plan is NOT valid as a production authorization, and a
public key delivered on lab control media is NOT a production trust anchor.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from windows10_popos_live_readonly_gpt_probe import (
    VM_ONLY_CONSENT, probe_linux_guest_gpt,
)
from windows10_popos_native_readonly_handoff_candidate import LAB_VIRTIO_SERIAL
from windows_x64_installed_gpt_ro_audit import require, DiskAuditError

WRITE_VM_CONSENT = "I_ACCEPT_DISPOSABLE_POP_NATIVE_ONLY_OWNED_PARTITIONS"
CONTROLLER_DIR = Path("/run/gaslux-pop-lab")
PLAN_FILE = CONTROLLER_DIR / "win10-six-gpt-input.json"
SIGNATURE_FILE = CONTROLLER_DIR / "native-lab-plan.ed25519.sig"
PUBLIC_KEY_FILE = CONTROLLER_DIR / "native-lab-plan.ed25519.pub"


def require_lab_plan_signature(plan: Path, signature: Path, key: Path) -> None:
    """Bound exact JSON bytes to job-generated Ed25519 key; no shell or writes."""
    require(
        plan == PLAN_FILE and signature == SIGNATURE_FILE
        and key == PUBLIC_KEY_FILE
        and plan.is_file() and not plan.is_symlink()
        and signature.is_file() and not signature.is_symlink()
        and key.is_file() and not key.is_symlink()
        and 500 <= plan.stat().st_size <= 30000
        and 60 <= signature.stat().st_size <= 80
        and 90 <= key.stat().st_size <= 300,
        "untrusted native guest handoff files or identity",
    )
    result = subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(key),
         "-rawin", "-in", str(plan), "-sigfile", str(signature)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=12, check=False,
    )
    require(result.returncode == 0,
            "Ed25519 signed native VM handoff authentication failed")


def prewrite_check() -> dict:
    require(
        os.geteuid() == 0
        and os.environ.get("GASLUX_POP_NATIVE_COW_WRITER_CONSENT") == WRITE_VM_CONSENT
        and os.environ.get("GASLUX_POP_LIVE_GPT_RO_CONSENT") == VM_ONLY_CONSENT,
        "explicit VM native writer/prewrite consent missing",
    )
    with Path("/etc/os-release").open(encoding="utf-8") as source:
        identity = dict(line.split("=", 1) for line in source.read().splitlines()
                        if line.startswith(("ID=", "VERSION_ID=")))
    require(
        identity.get("ID", "").strip().strip('"') == "pop"
        and identity.get("VERSION_ID", "").strip().strip('"') == "24.04",
        "native guest media is not verified Pop 24.04",
    )
    require_lab_plan_signature(PLAN_FILE, SIGNATURE_FILE, PUBLIC_KEY_FILE)
    with PLAN_FILE.open(encoding="utf-8") as stream:
        document = json.load(stream)
    require(type(document) is dict and set(document) == {
        "before", "after", "plan", "stageReport", "media", "guest",
        "nativeGuestWriteAuthorization",
    }, "ambiguous signed native plan document")
    authorization = document["nativeGuestWriteAuthorization"]
    require(
        type(authorization) is dict and
        set(authorization) == {
            "onlyDisposableQcOw2Child", "hostedRunner",
            "onlyOwnedPopPartitionIndexes", "doNotModifyWindows",
            "secureBootDisabled", "efiNvrAMWriteAllowed",
            "productionInstallationAuthorized", "signedIsoGpgVerified",
        }
        and authorization["onlyDisposableQcOw2Child"] is True
        and authorization["hostedRunner"] is True
        and authorization["onlyOwnedPopPartitionIndexes"] == [5, 6]
        and authorization["doNotModifyWindows"] is True
        and authorization["secureBootDisabled"] is True
        and authorization["efiNvrAMWriteAllowed"] is False
        and authorization["productionInstallationAuthorized"] is False
        and authorization["signedIsoGpgVerified"] is True,
        "signed native install authorization may write foreign Windows resources",
    )
    media = document["media"]
    agent = Path("/usr/bin/distinst")
    require(agent.is_file() and not agent.is_symlink()
            and media["upstreamId"] == "pop"
            and media["version"] == "24.04",
            "native System76 installer does not match signed media")
    with agent.open("rb") as stream:
        agent_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    require(agent_sha == media["distinstSha256"],
            "native System76 ELF differs from GPG-verified squashfs")
    # This reused gate opens the exact 128-GiB virtio target O_RDONLY. Its
    # Linux fd is O_RDONLY even though the host's child QCOW2 is writable for
    # a *separate* future installer process. The host must verify backing.
    observed = probe_linux_guest_gpt(
        document["before"], document["after"], document["plan"],
        document["stageReport"], media, document["guest"],
    )
    require(
        observed["diskWritePerformed"] is False
        and observed["primaryAndBackupGptCrcVerified"] is True
        and observed["candidate"]["protectedWindowsPartitionIndexes"]
        == [1, 2, 3, 4]
        and observed["candidate"]["ownedEsp"]["partitionIndex"] == 5
        and observed["candidate"]["ownedRoot"]["partitionIndex"] == 6
        and observed["candidate"]["productionInstallationAuthorized"] is False,
        "real Win10 owner GPT did not survive native guest read-only preflight",
    )
    return {
        "vmNativeSystem76PrewriteGatePassed": True,
        "diskSerial": LAB_VIRTIO_SERIAL,
        "diskGuid": observed["diskGuid"],
        "ownedEspPartition": 5, "ownedRootPartition": 6,
        "nativeSystem76AgentSha256": agent_sha,
        "windowsProtectedPartitionIndexes": [1, 2, 3, 4],
        "linuxPartitionFormatterInvoked": False,
        "distinstInvoked": False,
        "productionInstallationAuthorized": False,
        "dualBootVerified": False,
        "rollbackVerified": False,
    }


if __name__ == "__main__":
    try:
        proof = prewrite_check()
    except (OSError, ValueError, TypeError, KeyError,
            subprocess.TimeoutExpired) as exc:
        print("GASLUX_POP_NATIVE_WIN10_PREWRITE_REFUSED=" + str(exc), flush=True)
        raise SystemExit(1)
    print("GASLUX_POP_NATIVE_WIN10_GUEST_PREWRITE_JSON="
          + json.dumps(proof, sort_keys=True, separators=(",", ":")), flush=True)
    print("GASLUX_POP_NATIVE_WIN10_GUEST_PREWRITE_VERIFIED=1", flush=True)
