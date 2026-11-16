#!/usr/bin/env python3
"""Read-only evidence inventory of Calamares inside a pinned Q4OS live SquashFS.

This is not an installer. It never authorizes disk or bootloader mutations.
"""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

import yaml

PINNED_Q4OS_SHA256 = "1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d"
CONFIG_CANDIDATES = (
    "etc/calamares/settings.conf",
    "usr/share/calamares/settings.conf",
)
VERSION_CANDIDATES = (
    "etc/q4os_version",
    "usr/share/q4os/q4os_version",
)
MAX_CONFIG_BYTES = 131072
MAX_CONFIG_FILES = 100
SAFE_PATH = re.compile(r"^[a-zA-Z0-9_./+@-]+$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def listing_paths(squashfs: Path) -> dict[str, str]:
    result = subprocess.run(
        ["unsquashfs", "-ll", str(squashfs)],
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )
    files = {}
    for line in result.stdout.splitlines():
        if "squashfs-root/" not in line:
            continue
        attrs = line.split(maxsplit=1)[0]
        name = line.split("squashfs-root/", 1)[1].split(" -> ", 1)[0].strip()
        if SAFE_PATH.fullmatch(name) and ".." not in Path(name).parts:
            files[name] = attrs[0]
    return files


def squashfs_cat(squashfs: Path, name: str) -> bytes:
    if not SAFE_PATH.fullmatch(name) or ".." in Path(name).parts:
        raise ValueError("Unsafe SquashFS evidence path")
    result = subprocess.run(
        ["unsquashfs", "-cat", str(squashfs), name],
        check=True,
        capture_output=True,
        timeout=40,
    )
    if len(result.stdout) > MAX_CONFIG_BYTES:
        raise ValueError(f"Oversized Calamares evidence: {name}")
    return result.stdout


def modules_in_sequence(settings: object) -> dict[str, list[str]]:
    sequences = {"show": [], "exec": []}
    if not isinstance(settings, dict):
        return sequences
    for phase in settings.get("sequence", []):
        if not isinstance(phase, dict):
            continue
        for stage in sequences:
            modules = phase.get(stage)
            if isinstance(modules, list):
                sequences[stage].extend(m for m in modules if isinstance(m, str))
    return sequences



def verify_iso_mount_binding(iso: Path, squashfs: Path, mount_root: Path) -> None:
    """Prove that the read-only SquashFS is on a loop mount of the hashed ISO."""
    if mount_root.is_symlink() or not mount_root.is_mount():
        raise ValueError("ISO root is not a real mounted filesystem")
    root = mount_root.resolve(strict=True)
    actual_squash = squashfs.resolve(strict=True)
    if not actual_squash.is_relative_to(root):
        raise ValueError("SquashFS is outside the mounted official ISO")
    result = subprocess.run(
        ["findmnt", "-n", "-M", str(root), "-o", "SOURCE,FSTYPE"],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    parts = result.stdout.strip().split()
    if len(parts) != 2 or parts[1] != "iso9660" or not re.fullmatch(r"/dev/loop[0-9]+", parts[0]):
        raise ValueError("Expected a dedicated loop-backed ISO9660 mount")
    result = subprocess.run(
        ["losetup", "-n", "-O", "BACK-FILE", parts[0]],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    backing = result.stdout.strip()
    if not backing or not Path(backing).samefile(iso):
        raise ValueError("ISO mount backing file differs from the SHA-256-verified image")

def inventory(iso: Path, squashfs: Path, out: Path, mount_root: Path) -> dict:
    if iso.is_symlink() or squashfs.is_symlink():
        raise ValueError("Refusing symlinked ISO or SquashFS")
    iso_hash = sha256_file(iso)
    if iso_hash != PINNED_Q4OS_SHA256:
        raise ValueError("Actual ISO does not match pinned Q4OS 6.10 r2 SHA-256")
    if not squashfs.is_file():
        raise ValueError("Missing live SquashFS from verified ISO")
    verify_iso_mount_binding(iso, squashfs, mount_root)
    paths = listing_paths(squashfs)
    settings_path = next((p for p in CONFIG_CANDIDATES if paths.get(p) == "-"), None)
    version_path = next((p for p in VERSION_CANDIDATES if paths.get(p) == "-"), None)
    module_paths = sorted(
        p
        for p, kind in paths.items()
        if kind == "-"
        and p.endswith(".conf")
        and p.startswith(("etc/calamares/modules/", "usr/share/calamares/modules/"))
    )
    evidence_paths = sorted(
        set(module_paths[:MAX_CONFIG_FILES])
        | {p for p in (settings_path, version_path, "etc/os-release") if p}
    )
    out.mkdir(parents=True, exist_ok=True)
    manifest = {}
    captured = {}
    for path in evidence_paths:
        if paths.get(path) != "-":
            continue
        data = squashfs_cat(squashfs, path)
        destination = out / "source" / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        captured[path] = data
        manifest[path] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    settings = None
    if settings_path and settings_path in captured:
        settings = yaml.safe_load(captured[settings_path])
    stages = modules_in_sequence(settings)
    version = captured.get(version_path or "", b"").decode("utf-8", errors="replace").strip()
    has_binary = any(
        paths.get(p) in ("-", "l")
        for p in ("usr/bin/calamares", "bin/calamares", "usr/sbin/calamares")
    )
    report = {
        "distribution": "q4os",
        "pinnedIsoSha256": iso_hash,
        "source": "same-pinned-official-iso-live-squashfs",
        "q4osVersionFile": version_path,
        "q4osVersionText": version[:120],
        "calamaresBinaryPresent": has_binary,
        "calamaresSettingsFile": settings_path,
        "calamaresDontChroot": settings.get("dont-chroot") if isinstance(settings, dict) else None,
        "sequence": stages,
        "moduleConfigCount": len(module_paths),
        "configInventoryTruncated": len(module_paths) > MAX_CONFIG_FILES,
        "manifest": manifest,
        "installationAuthorized": False,
        "nativeInstallationProven": False,
        "firstBootProven": False,
        "windowsPreservationProven": False,
    }
    (out / "calamares-inventory.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--squashfs", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--mount-root", type=Path, required=True)
    args = parser.parse_args()
    report = inventory(args.iso, args.squashfs, args.out, args.mount_root)
    print("Q4OS pinned ISO SHA-256:", report["pinnedIsoSha256"])
    print("Q4OS identity path:", report["q4osVersionFile"])
    print("Calamares binary:", report["calamaresBinaryPresent"])
    print("Calamares settings:", report["calamaresSettingsFile"])
    print("Calamares exec modules:", ", ".join(report["sequence"]["exec"]))
    print("INSTALLATION_AUTHORIZED=false")
    if not (report["calamaresBinaryPresent"] and report["calamaresSettingsFile"]):
        print("FAIL: native Calamares binary/config not positively identified")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
