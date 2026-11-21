#!/usr/bin/env python3
"""Read-only Pop ISO distinst ELF/CLI observer, only in isolated QEMU live guest.

This DOES NOT show actual install write operations: --help exits before install.
No --block / --use / --new-table, never starts native installer, and no writes
to disks. Runs only with the signed ISO agent SHA previously observed in QEMU.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from windows_x64_installed_gpt_ro_audit import require, DiskAuditError

PINNED_DISTINST_SHA256 = "8bfedbc2d6921c440449ec1fda8c4e4d1c0078d69db5aa5832d9a7bf8b13e1a5"
AGENT = Path("/usr/bin/distinst")
CONSENT = "I_ACCEPT_READONLY_DISTINST_ELF_HELP_INSPECTION"
SAFE_ARGS = ("--help",)
BLOCK_WRITER_PATTERNS = ("--new-table", "--delete", "--move", "--new", "--modify-boot")


def require_readonly_distinst_environment() -> None:
    require(os.geteuid() == 0 and
            os.environ.get("GASLUX_POP_DISTINST_READONLY_CONSENT") == CONSENT
            and os.environ.get("GASLUX_POP_SIGNED_ISO_GPG_VERIFIED") == "1",
            "Pop signed ISO verification or read-only observation consent absent")
    release = Path("/etc/os-release").read_text(encoding="utf-8")
    require(re.search(r'^ID="?pop"?$', release, re.MULTILINE)
            and re.search(r'^VERSION_ID="?24[.]04"?$', release, re.MULTILINE),
            "not live Pop 24.04")
    virt = subprocess.run(["systemd-detect-virt", "--vm"], text=True,
                          capture_output=True, check=False, timeout=5)
    require(virt.returncode == 0 and virt.stdout.strip() in ("qemu", "kvm"),
            "read-only observer may run only in QEMU/KVM")
    require(AGENT.is_file() and not AGENT.is_symlink()
            and stat.S_ISREG(AGENT.stat().st_mode), "native ELF missing")
    with AGENT.open("rb") as fd:
        require(hashlib.file_digest(fd, "sha256").hexdigest() ==
                PINNED_DISTINST_SHA256, "actual ELF not pinned System76 agent")
    with AGENT.open("rb") as fd:
        require(fd.read(4) == b"\x7fELF", "not a valid ELF header")


def inspect_distinst_help() -> dict:
    """No disk argument, no diskinst option configuring partitions."""
    require_readonly_distinst_environment()
    obj = subprocess.run([str(AGENT), *SAFE_ARGS],
                         capture_output=True, text=True, timeout=12, check=False)
    require(obj.returncode == 0 and len(obj.stdout) < 100_000,
            "System76 distinst help failed closed")
    help_text = obj.stdout
    for token in ("--use", "--no-efi-vars", "--modify-boot", "--block"):
        require(token in help_text, "native CLI help lacks expected option " + token)
    require(len(obj.stderr) < 8000, "unbounded native CLI stderr")
    options = [line.strip() for line in help_text.splitlines()
               if line.strip().startswith("-")]
    require(4 <= len(options) <= 100
            and all(len(line) <= 260 for line in options),
            "missing or unbounded actual System76 CLI option inventory")
    return {
        "cliElfExecutedForHelp": True,
        "cliHelpExitCode": obj.returncode,
        "cliHelpOutputSha256": hashlib.sha256(
            help_text.encode("utf-8")).hexdigest(),
        "cliHelpStderrSha256": hashlib.sha256(
            obj.stderr.encode("utf-8")).hexdigest(),
        "cliOptionLines": options,
        "source": "pinned-pop-24.04-build-20-live-guest",
        "agentSha256": PINNED_DISTINST_SHA256,
        "argv": [str(AGENT), "--help"],
        "observerExecutedInstaller": False,
        "diskWritesIndependentlyTraced": False,
        "efiNvrAMObserved": False,
        "nativeInstallObserved": False,
        "writeSetConfinementEstablished": False,
        "distinstExecutionAuthorized": False,
        "supportedFlagsPresent": ["--use", "--no-efi-vars",
                                  "--modify-boot", "--block"],
    }


if __name__ == "__main__":
    try:
        result = inspect_distinst_help()
    except (DiskAuditError, OSError, ValueError, subprocess.TimeoutExpired) as ex:
        print("GASLUX_POP_DISTINST_READONLY_REFUSED=" + str(ex), flush=True)
        raise SystemExit(1)
    print("GASLUX_POP_DISTINST_READONLY_OBSERVER_JSON=" +
          json.dumps(result, sort_keys=True), flush=True)
