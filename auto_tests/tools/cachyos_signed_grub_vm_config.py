#!/usr/bin/env python3
"""Produce a disposable QEMU boot config FROM the verified signed GRUB entry.

LAB ONLY. A temporary signing key and synthetic disk identity cannot establish
trust in a Windows boot chain. No physical disks, EFI variables or NVRAM writes.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUTH_PATH = ROOT / "assets/live/cachyos-handoff-auth.py"
SPEC = importlib.util.spec_from_file_location("gaslux_signed_lab_auth", AUTH_PATH)
assert SPEC and SPEC.loader
AUTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTH)

LAB_RUN_ID = "lab-real-iso-signed-20261116"
LAB_ROOT_UUID = "01234567-89ab-cdef-0123-456789abcdef"
LAB_ISO_UUID = "fedcba98-7654-4321-aaaa-111111111111"
LAB_DISK_ID = "QEMU-SYNTHETIC-TRANSACTION-ONLY"
LAB_CONSOLE_FLAGS = (
    " console=tty0 console=ttyS0,115200n8"
    " systemd.log_target=console systemd.log_level=info"
    " systemd.unit=multi-user.target"
)
SHA = re.compile(r"[0-9a-f]{64}\Z")
KERNEL = "    linux (gaslux_iso)/arch/boot/x86_64/vmlinuz-linux-cachyos-lts "
INITRD = "    initrd (gaslux_iso)/arch/boot/x86_64/initramfs-linux-cachyos-lts.img"


class LabBootError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise LabBootError(reason)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regular(path: Path, limit: int) -> bytes:
    require(path.is_file() and not path.is_symlink(), "missing or linked lab evidence: " + path.name)
    require(0 < path.stat().st_size <= limit, "invalid lab evidence length: " + path.name)
    return path.read_bytes()


def prepare(evidence: Path, pinned_iso_sha256: str) -> tuple[str, str, str]:
    require(evidence.is_dir() and not evidence.is_symlink(), "missing signed evidence directory")
    require(bool(SHA.fullmatch(pinned_iso_sha256)), "invalid pinned ISO SHA-256")
    names = {
        "test-only-handoff.json": 16384,
        "test-only-handoff.sig": 64,
        "test-only-public.pem": 4096,
        "test-only-grub.cfg": 16384,
        "attestation.json": 16384,
        "SHA256SUMS": 4096,
    }
    data = {name: regular(evidence / name, limit) for name, limit in names.items()}
    # Independently check the evidence manifest before consuming any boot file.
    checksums = data["SHA256SUMS"].decode("ascii").splitlines()
    seen: set[str] = set()
    for line in checksums:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        require(match is not None, "malformed evidence SHA256SUMS")
        expected, filename = match.groups()
        require(filename in data and filename != "SHA256SUMS" and filename not in seen,
                "unknown or repeated signed evidence artifact")
        seen.add(filename)
        require(digest(data[filename]) == expected, "signed evidence checksum mismatch: " + filename)
    require(seen == (names.keys() - {"SHA256SUMS"}), "incomplete signed evidence checksums")

    document = json.loads(data["test-only-handoff.json"])
    AUTH.validate_document(document)
    require(AUTH.canonical(document) == data["test-only-handoff.json"], "noncanonical signed plan")
    attestation = json.loads(data["attestation.json"])
    require(attestation.get("signedPlanVerified") is True and
            attestation.get("realOfficialIsoSha256Verified") is True and
            attestation.get("realOfficialIsoLayoutVerified") is True,
            "signed fixture lacks verified ISO evidence")
    require(attestation.get("officialIsoSha256") == pinned_iso_sha256 ==
            document["isoSha256"], "signed plan differs from pinned official ISO")
    require(attestation.get("signedGrubEntrySha256") == digest(data["test-only-grub.cfg"]),
            "signed entry differs from attested GRUB")
    require(attestation.get("ephemeralTestSignerPublicKeySha256") ==
            digest(data["test-only-public.pem"]), "ephemeral signer mismatch")
    require(all(attestation.get(field) is False for field in (
        "windowsPhysicalDiskIdentityVerified", "windowsBootChainAuthenticated",
        "windowsRecoveryVerified", "installedLinuxBootVerified", "stableForPhysicalDisks",
    )), "unexpected real-system readiness assertion")
    require(document["runId"] == LAB_RUN_ID and
            document["rootUuid"] == LAB_ROOT_UUID and
            document["isoStorageUuid"] == LAB_ISO_UUID and
            document["targetDiskId"] == LAB_DISK_ID and
            document["windowsLoaderSha256"] == "0" * 64 and
            document["isoRelativePath"] == "/cachyos.iso" and
            document["isoStorageFilesystem"] == "ext4", "not the disposable CI transaction")

    entry = data["test-only-grub.cfg"].decode("utf-8")
    lines = entry.splitlines(keepends=True)
    linux = [i for i, line in enumerate(lines) if line.startswith(KERNEL)]
    require(len(linux) == 1 and entry.count(INITRD) == 1 and
            entry.count("menuentry 'CachyOS Archiso (experimental)'") == 1,
            "unexpected signed GRUB boot structure")
    kernel_line = lines[linux[0]]
    require(kernel_line.endswith("\n") and "console=" not in kernel_line and
            "systemd.unit=" not in kernel_line, "unexpected existing test console arguments")
    boot = AUTH.parse_cmdline(kernel_line.removeprefix(KERNEL))
    expected = {
        "gaslux.run": LAB_RUN_ID,
        "gaslux.nonce": document["bootNonce"],
        "gaslux.plan_sha256": digest(data["test-only-handoff.json"]),
        "gaslux.key_sha256": digest(data["test-only-public.pem"]),
    }
    require(boot == expected, "signed GRUB kernel arguments are not plan-bound")
    # Check every executable GRUB instruction, not just the kernel args.
    # A compromised test attestation must not be able to smuggle extra GRUB
    # commands into a VM boot even if its SHA256SUMS were also rewritten.
    cmdline = " ".join(f"{key}={value}" for key, value in expected.items())
    expected_entry = (
        "# Gaslux CachyOS Archiso handoff — lab-only, not a production installer\n"
        f"# Transaction {LAB_RUN_ID}\n"
        "menuentry 'CachyOS Archiso (experimental)' --id gaslux-cachyos-archiso {\n"
        "    insmod part_gpt\n"
        "    insmod ext2\n"
        "    insmod iso9660\n"
        f"    search --no-floppy --fs-uuid --set=gaslux_iso_dev {LAB_ISO_UUID}\n"
        "    set gaslux_iso_path='/cachyos.iso'\n"
        "    if [ ! -f ($gaslux_iso_dev)$gaslux_iso_path ]; then\n"
        "        echo 'Verified CachyOS ISO location is missing'\n"
        "        sleep 10\n"
        "        reboot\n"
        "    fi\n"
        "    loopback gaslux_iso ($gaslux_iso_dev)$gaslux_iso_path\n"
        "    if [ ! -f (gaslux_iso)/arch/boot/x86_64/vmlinuz-linux-cachyos-lts ]; then\n"
        "        echo 'CachyOS ISO kernel is missing'\n"
        "        sleep 10\n"
        "        reboot\n"
        "    fi\n"
        f"{KERNEL}archisobasedir=arch img_dev=UUID={LAB_ISO_UUID} "
        f"img_loop=/cachyos.iso cow_spacesize=10G copytoram=auto {cmdline}\n"
        f"{INITRD}\n"
        "}\n"
    )
    require(entry == expected_entry, "signed GRUB instructions differ from pinned lab template")
    result = AUTH.verify(
        evidence / "test-only-handoff.json",
        evidence / "test-only-handoff.sig",
        evidence / "test-only-public.pem",
        " ".join(f"{k}={v}" for k, v in expected.items()),
        expected_run_id=LAB_RUN_ID,
        expected_root_uuid=LAB_ROOT_UUID,
    )
    require(result["verified"] is True, "Ed25519 signature verification failed")
    # Only a known static serial-console suffix is added, for observation in
    # CI. The original signed plan arguments remain byte-for-byte unchanged.
    lines[linux[0]] = kernel_line[:-1] + LAB_CONSOLE_FLAGS + "\n"
    grub = (
        "serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1\n"
        "terminal_input serial\nterminal_output serial\n"
        "set default=0\nset timeout=0\n"
        + "".join(lines)
    )
    proof = json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n"
    return LAB_ISO_UUID, grub, proof


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--iso-sha256", required=True)
    parser.add_argument("--output-grub", type=Path, required=True)
    parser.add_argument("--output-boot-proof", type=Path, required=True)
    args = parser.parse_args()
    try:
        uuid, grub, proof = prepare(args.evidence_dir, args.iso_sha256)
        for path, content in (
            (args.output_grub, grub),
            (args.output_boot_proof, proof),
        ):
            # No clobber and no symlinks; the caller supplies a fresh VM tempdir.
            with path.open("x", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        print(uuid)
    except (OSError, UnicodeError, ValueError, KeyError, TypeError, AUTH.AuthError) as error:
        print("GASLUX_SIGNED_GRUB_LAB_REFUSED: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
