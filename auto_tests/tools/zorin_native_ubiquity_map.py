#!/usr/bin/env python3
"""Read-only evidence map of Ubiquity code in the SHA-pinned Zorin 18.1 ISO.

All source reads use unsquashfs -cat; no Python from the guest is imported or
executed. Source-code references are NOT evidence of safe unattended writes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from zorin_native_installer_discovery import (
    NativeDiscoveryError, read_member, require,
)
from windows_zorin_synthetic_cow_root import verify_official_zorin

ISO_SHA = "44649b97bd307fc4c8529205d098ebbf98575a1e1ba2ee7d7005b697af1721d5"
UBIQUITY_VERSION = "24.04.5+zorin2"
UBIQUITY_EXEC_SHA = "5819ac97c623085d08e55c08afc12e7d70be98795e603b27807bea165fad0b1b"
STATUS_SHA = "cccc80c9d5875e8d82f07edafbc8731135fdc7190f84d8a0594e8264fdeac86f"
FILE_LIMIT = 112
SOURCE_LIMIT = 512 * 1024
MAX_TOTAL_SOURCE = 24 * 1024 * 1024
MAX_OWNER_LIST = 2 * 1024 * 1024
MAX_MANIFEST = 8 * 1024 * 1024
MAX_STATUS = 16 * 1024 * 1024
OWNER_PACKAGES = re.compile(
    r"^(?:ubiquity(?:-[a-z0-9-]+)?|partman(?:-[a-z0-9-]+)?|"
    r"grub-installer|user-setup|localechooser|console-setup|"
    r"tzsetup|os-prober|grub-common|grub-efi-amd64-bin|"
    r"grub-efi-amd64-signed|shim-signed|efibootmgr|parted)$"
)
SOURCE_PATH = re.compile(r"^/(?:usr/(?:bin|lib|share)|lib|etc)/(?:[A-Za-z0-9_.+@/-]+)$")
SOURCE_EXT = re.compile(r"(?:\.py|\.sh|\.cfg|\.conf|\.service|\.desktop|\.postinst|\.templates)$")
IN_SCOPE_PATH = re.compile(
    r"ubiquity|partman|grub-installer|user-setup|localechooser|"
    r"keyboard|tzsetup|preseed|grub|efi|installer|os-prober",
    re.I,
)
SYMBOL = re.compile(r"^\s*(?:async )?def\s+([A-Za-z_]\w*)\s*\(|"
                    r"^\s*class\s+([A-Za-z_]\w*)\s*[:(]|"
                    r"^\s*(?:function\s+)?([A-Za-z_]\w*)\s*\(\)\s*\{?")
RULES = {
    "diskSelection": r"\b(?:selected_device|selected_disk|disk_choice|"
                     r"bootdev|device_combo|partition_device|disk_names)\b",
    "existingPartitions": r"\b(?:partman|partition_list|partition_tree|"
                          r"mountpoint|use_as|format_choice)\b",
    "gptModification": r"\b(?:parted_server|partman|write_table|"
                       r"parted|partition_table|commit)\b",
    "rootFilesystem": r"\b(?:mkfs|format_partition|mountpoint|"
                      r"filesystem|set_mountpoint)\b",
    "espSelection": r"\b(?:efi_system_partition|efi_partition|"
                    r"/boot/efi|/target/boot/efi|efi_dir)\b",
    "nvram": r"\b(?:efibootmgr|BootOrder|BootNext|efivar|"
             r"efi_boot_manager)\b",
    "grub": r"\b(?:grub-install|grub-installer|grub-pc|"
            r"grub-efi|grub_target|grub_device)\b",
    "account": r"\b(?:user-setup|username|password|userfullname|"
               r"user_info|hostname)\b",
    "language": r"\b(?:language|localechooser|set_locale)\b",
    "keyboard": r"\b(?:keyboard|console-setup|xkb)\b",
    "timezone": r"\b(?:timezone|tzsetup|time_zone)\b",
    "preseedAutomation": r"\b(?:preseed|automatic|noninteractive|"
                         r"debconf|debconf-set-selections)\b",
    "postInstall": r"\b(?:success_command|late_command|"
                   r"postinstall|post_install|chroot)\b",
    "windowsBoot": r"\b(?:os-prober|bootmgfw\.efi|"
                   r"Windows Boot Manager|chainloader)\b",
}
WRITE_SURFACES = {
    "gptAndPartitionMetadata": ("gptModification", "diskSelection"),
    "filesystemFormatting": ("rootFilesystem",),
    "linuxTargetRoot": ("rootFilesystem", "postInstall"),
    "espFiles": ("espSelection", "grub"),
    "nvramEntries": ("nvram", "grub"),
    "grubConfiguration": ("grub",),
    "postInstallChanges": ("postInstall", "account"),
}
CRITICAL_SOURCE_PREFIX = (
    "/usr/lib/ubiquity/", "/usr/share/ubiquity/",
    "/usr/lib/python3/dist-packages/ubiquity/",
    "/usr/bin/ubiquity", "/usr/lib/partman/",
    "/lib/partman/", "/usr/lib/grub-installer/",
)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def package_status(raw: bytes) -> dict[str, dict]:
    require(len(raw) <= MAX_STATUS, "oversized dpkg status")
    installed = {}
    for block in re.split(r"\n\s*\n", raw.decode("utf-8", "strict")):
        fields = {}
        for line in block.splitlines():
            if ": " in line and not line.startswith((" ", "\t")):
                key, value = line.split(": ", 1)
                fields[key] = value
        name = fields.get("Package", "")
        if not OWNER_PACKAGES.fullmatch(name):
            continue
        require(name not in installed, "duplicate relevant package")
        if fields.get("Status") == "install ok installed":
            require(bool(fields.get("Version") and fields.get("Architecture")),
                    "installed package missing version/architecture")
            installed[name] = {
                "version": fields["Version"], "architecture": fields["Architecture"],
            }
    return installed


def casper_versions(raw: bytes) -> dict[str, str]:
    require(len(raw) <= MAX_MANIFEST, "oversized Casper manifest")
    versions = {}
    for line in raw.decode("utf-8", "strict").splitlines():
        fields = line.split()
        if len(fields) != 2 or not OWNER_PACKAGES.fullmatch(fields[0]):
            continue
        require(fields[0] not in versions, "duplicate Casper package")
        versions[fields[0]] = fields[1]
    return versions


def owned_sources(package: str, raw: bytes) -> list[str]:
    require(len(raw) <= MAX_OWNER_LIST, "oversized package file list")
    result = []
    seen = set()
    for path in raw.decode("utf-8", "strict").splitlines():
        if not IN_SCOPE_PATH.search(path):
            continue
        require(bool(SOURCE_PATH.fullmatch(path))
                and ".." not in path.split("/")
                and "//" not in path, "untrusted dpkg path traversal")
        if (path in seen or not (SOURCE_EXT.search(path) or
                                path == "/usr/bin/ubiquity")):
            continue
        seen.add(path)
        result.append(path)
    return result


def priority(path: str) -> tuple:
    preferred = ("ubi-partman", "partman", "ubi-grub", "grub-installer",
                 "ubi-usersetup", "ubi-language", "ubi-console-setup",
                 "ubi-timezone", "ubiquity", "preseed", "efi")
    name = path.lower()
    return (next((i for i, value in enumerate(preferred) if value in name),
                 len(preferred)), name)


def extract_signals(data: bytes, path: str, package: str, owner_sha: str) -> list[dict]:
    try:
        lines = data.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError:
        return []
    signals = []
    latest = "<module>"
    for number, line in enumerate(lines, 1):
        match = SYMBOL.match(line)
        if match:
            latest = next(g for g in match.groups() if g is not None)
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        for capability, expression in RULES.items():
            hit = re.search(expression, line, flags=re.I)
            if hit:
                signals.append({
                    "capability": capability, "path": path.lstrip("/"),
                    "package": package, "function": latest,
                    "line": number, "token": hit.group(0)[:48],
                    "sourceSha256": owner_sha,
                    "basis": "STATIC_CODE_REFERENCE_ONLY",
                })
                if len(signals) >= 256:
                    return signals
    return signals


def build_map(rootfs: Path, prior: dict, manifest: bytes,
              reader=read_member) -> dict:
    require(prior.get("authorization") == "DENY_NO_WRITER"
            and prior.get("staticInstallerCandidate") == "ubiquity"
            and prior.get("iso", {}).get("sha256") == ISO_SHA
            and prior.get("packages", {}).get("ubiquity", {}).get("version")
                == UBIQUITY_VERSION
            and any(x.get("path") == "usr/bin/ubiquity"
                    and x.get("sha256") == UBIQUITY_EXEC_SHA
                    and x.get("ownerVerified") is True
                    for x in prior.get("executables", [])),
            "previous pinned discovery/installer evidence mismatch")
    status = reader(rootfs, "var/lib/dpkg/status", MAX_STATUS)
    require(status is not None and digest(status) == STATUS_SHA,
            "previous dpkg status changed or untrusted")
    packages = package_status(status)
    versions = casper_versions(manifest)
    require(packages.get("ubiquity", {}).get("version") == UBIQUITY_VERSION
            and versions.get("ubiquity") == UBIQUITY_VERSION,
            "Ubiquity version not identical in dpkg status and Casper")
    sources = []
    owner_lists = []
    unverified_owners = []
    for package, info in sorted(packages.items()):
        path = "var/lib/dpkg/info/" + package + ".list"
        raw = reader(rootfs, path, MAX_OWNER_LIST, optional=True)
        if raw is None:
            unverified_owners.append(package)
            continue
        sources.append({"scope": "squashfs", "path": path,
                        "sha256": digest(raw), "package": package})
        if versions.get(package) != info["version"]:
            unverified_owners.append(package)
            continue
        for candidate in owned_sources(package, raw):
            if (candidate.startswith(CRITICAL_SOURCE_PREFIX)
                or "partman" in candidate or "grub-installer" in candidate
                or "preseed" in candidate or "user-setup" in candidate):
                owner_lists.append((candidate, package))
    owner_lists.sort(key=lambda record: priority(record[0]))
    # Prefer only a single owner for each file; ambiguity MUST be rejected.
    owners = {}
    for path, package in owner_lists:
        require(path not in owners or owners[path] == package,
                "same executable/script has multiple package owners")
        owners[path] = package
    chosen = sorted(owners.items(), key=lambda x: priority(x[0]))
    too_many = len(chosen) > FILE_LIMIT
    chosen = chosen[:FILE_LIMIT]
    modules = []
    signals = []
    unreadable = []
    total = 0
    for path, package in chosen:
        data = reader(rootfs, path.lstrip("/"), SOURCE_LIMIT, optional=True)
        if data is None:
            unreadable.append(path.lstrip("/"))
            continue
        total += len(data)
        require(total <= MAX_TOTAL_SOURCE, "oversized aggregate source evidence")
        sha = digest(data)
        modules.append({"path": path.lstrip("/"), "package": package,
                        "packageVersion": packages[package]["version"],
                        "sha256": sha, "sizeBytes": len(data),
                        "ownerVerified": True})
        signals.extend(extract_signals(data, path, package, sha))
    primary = next((x for x in modules if x["path"] == "usr/bin/ubiquity"), None)
    require(primary is not None and primary["sha256"] == UBIQUITY_EXEC_SHA,
            "native executable changed or missing from source map")
    observations = {}
    for capability in RULES:
        evidence = [x for x in signals if x["capability"] == capability][:15]
        observations[capability] = {
            "status": "SUPPORTED_STATICALLY" if evidence else "UNOBSERVED",
            "evidence": evidence,
            "runtimeBehaviorVerified": False,
        }
    effects = {}
    for surface, capabilities in WRITE_SURFACES.items():
        affected = [x for x in signals if x["capability"] in capabilities][:12]
        effects[surface] = {
            "classification": "CONDITIONAL_CODE_REFERENCE" if affected else "UNKNOWN",
            "writeSetLimitedToOwnedLinuxRoot": False,
            "observedWrites": False,
            "evidence": affected,
        }
    return {
        "schemaVersion": 1,
        "distribution": "zorin",
        "installer": {"name": "ubiquity", "version": UBIQUITY_VERSION,
                      "executable": "usr/bin/ubiquity", "sha256": UBIQUITY_EXEC_SHA},
        "isoSha256": ISO_SHA, "casperManifestSha256": digest(manifest),
        "dpkgStatusSha256": digest(status),
        "modules": modules, "unreadablePaths": unreadable,
        "unverifiedPackageOwners": unverified_owners,
        "sourceEnumerationTruncated": too_many,
        "selectedSourceCount": len(chosen), "totalSelectedSourceCount": len(owners),
        "capabilities": observations, "potentialWriteSurfaces": effects,
        "outsideLinuxTargetWriteSetAuthenticated": False,
        "partitionLockdownVerified": False,
        "efiAndNvramPreservationVerified": False,
        "automationSafeForUnattendedInstall": False,
        "nativeInstallerExecuted": False,
        "hostGuestIndependentObserver": False,
        "authorization": "DENY_NO_WRITER",
        "stable": False,
    }


def map_authenticated_iso(iso: Path, mounted: Path, prior: dict) -> dict:
    verify_official_zorin(iso)
    require(mounted.is_dir() and not mounted.is_symlink()
            and (mounted / "casper/filesystem.squashfs").is_file()
            and not (mounted / "casper/filesystem.squashfs").is_symlink(),
            "untrusted ISO9660 mount/rootfs")
    mount = subprocess.run(["findmnt", "-rn", "-M", str(mounted),
                            "-o", "FSTYPE,OPTIONS"], capture_output=True,
                           text=True, check=False, timeout=10)
    require(mount.returncode == 0 and mount.stdout.startswith("iso9660 ")
            and "ro" in mount.stdout.split(" ", 1)[1].split(","),
            "ISO not mounted as iso9660 read-only")
    manifest_path = mounted / "casper/filesystem.manifest"
    require(manifest_path.is_file() and not manifest_path.is_symlink()
            and manifest_path.stat().st_size <= MAX_MANIFEST,
            "invalid Casper manifest")
    manifest = manifest_path.read_bytes()
    require(digest(manifest) ==
            "cc206a10d7de5cd8d373634f1b91ac35e030f5d4075acda7edcbb2b0318ee948",
            "Casper manifest fingerprint mismatch")
    return build_map(mounted / "casper/filesystem.squashfs", prior, manifest)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--mounted", type=Path, required=True)
    parser.add_argument("--previous", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    require(args.previous.is_file() and not args.previous.is_symlink()
            and args.out.parent.resolve() == workspace / "zorin-native-evidence"
            and args.out.parent.is_dir() and not args.out.parent.is_symlink()
            and not args.out.exists() and not args.out.is_symlink(),
            "untrusted evidence input/output")
    prior = json.loads(args.previous.read_text(encoding="utf-8"))
    report = map_authenticated_iso(args.iso, args.mounted, prior)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    print("PASS: Ubiquity static map completed; DENY_NO_WRITER; no installer executed")


if __name__ == "__main__":
    main()
