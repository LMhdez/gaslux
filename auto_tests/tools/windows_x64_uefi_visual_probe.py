#!/usr/bin/env python3
"""Read-only QEMU HMP display probe for disposable Windows ISO CI runs.

Captures a bounded VGA framebuffer from the already running, ISO-verified
Windows QEMU lab. Does not send keys, alter guest storage, or prove Windows
installation/first boot. No host or real-disk paths may be supplied.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import time

PROFILES = ("win10_22h2_en_us_x64", "win11_26h2_en_us_x64")
LABELS = ("00-dvd", "01-setup", "02-later")
RUNNER_ROOT = Path("/home/runner/work/_temp")
MAX_PPM_BYTES = 16 * 1024 * 1024


class ProbeError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ProbeError(reason)


def validate_monitor_path(path: Path, root: Path = RUNNER_ROOT) -> None:
    require(path.is_absolute() and root.is_absolute()
            and root == RUNNER_ROOT, "monitor must be on the hosted runner")
    require(path.name == "initial-installer-hmp.sock"
            and re.fullmatch(r"gaslux-win-x64-[A-Za-z0-9_-]+", path.parent.name) is not None
            and path.parent.parent == root, "unowned QEMU monitor path")
    require(not path.is_symlink() and path.is_socket(), "missing/foreign HMP socket")
    folder = path.parent
    require(not folder.is_symlink() and folder.resolve() == folder
            and stat.S_IMODE(folder.stat().st_mode) == 0o700
            and folder.stat().st_uid == os.getuid(), "unsafe QEMU workspace")


def validate_ci(evidence: Path) -> None:
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_OS") == "Linux"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux",
            "disposable hosted GitHub runner required")
    require(os.environ.get("RUNNER_TEMP") == str(RUNNER_ROOT),
            "unknown runner temporary directory")
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", ""))
    require(workspace.is_absolute() and workspace.is_dir()
            and evidence == workspace / "windows-x64-tcg-evidence"
            and evidence.is_dir() and not evidence.is_symlink()
            and evidence.resolve() == evidence, "invalid evidence directory")


def find_monitor(timeout_seconds: int = 900) -> Path:
    until = time.monotonic() + timeout_seconds
    while time.monotonic() < until:
        paths = list(RUNNER_ROOT.glob("gaslux-win-x64-*/initial-installer-hmp.sock"))
        require(len(paths) <= 1, "ambiguous QEMU monitor candidates")
        if paths:
            validate_monitor_path(paths[0])
            return paths[0]
        time.sleep(1)
    raise ProbeError("verified ISO QEMU monitor never appeared")


def read_hmp_prompt(hmp: socket.socket) -> bytes:
    """Drain HMP's readline echo until a complete new (qemu) prompt.

    A single recv() returns only the first echoed character on QEMU 8.2.
    Closing the connection there can cancel the pending screendump.
    """
    response = bytearray()
    while len(response) < 131072:
        chunk = hmp.recv(8192)
        require(bool(chunk), "QEMU monitor disconnected before command completed")
        response.extend(chunk)
        if b"(qemu) " in response:
            return bytes(response)
    raise ProbeError("QEMU HMP response exceeded bounded prompt limit")


def snapshot(monitor: Path, evidence: Path, profile: str, label: str) -> dict:
    validate_monitor_path(monitor)
    require(profile in PROFILES and label in LABELS, "invalid screenshot label")
    dest = evidence / f"{profile}-{label}.ppm"
    temp = monitor.parent / f"gaslux-{label}.ppm"
    require(not dest.exists() and not dest.is_symlink()
            and not temp.exists() and not temp.is_symlink(),
            "refusing screenshot overwrite")
    # HMP syntax accepts a single absolute filename; all components are
    # derived from validated private workspace and a hardcoded label.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as hmp:
        hmp.settimeout(10)
        hmp.connect(str(monitor))
        banner = read_hmp_prompt(hmp)
        require(b"QEMU" in banner, "unexpected QEMU monitor banner")
        hmp.sendall(("screendump " + str(temp) + "\n").encode("ascii"))
        response = read_hmp_prompt(hmp).lower()
        require(all(term not in response for term in (
                    b"unknown command", b"error:", b"no graphical console",
                    b"failed to", b"could not")),
                "QEMU screendump failed; see bounded QEMU HMP diagnostic")
    for _ in range(25):
        if temp.is_file() and temp.stat().st_size > 16:
            break
        time.sleep(.2)
    require(temp.is_file() and not temp.is_symlink()
            and stat.S_ISREG(temp.stat().st_mode)
            and 16 < temp.stat().st_size <= MAX_PPM_BYTES, "missing/oversized VGA image")
    with temp.open("rb") as handle:
        require(handle.read(3) in (b"P6\n", b"P6\r"), "unexpected framebuffer format")
    shutil.copyfile(temp, dest)
    temp.unlink()
    require(dest.stat().st_size <= MAX_PPM_BYTES, "oversized diagnostic artifact")
    with dest.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    return {"file": dest.name, "sha256": digest, "bytes": dest.stat().st_size}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", choices=PROFILES, required=True)
    args = ap.parse_args()
    evidence = Path(os.environ.get("GASLUX_WINDOWS_EVIDENCE", ""))
    validate_ci(evidence)
    monitor = find_monitor()
    images = []
    # All screenshots are host-side read-only probes. The Windows test process
    # retains exclusive ownership of its disposable QCOW2 and is not modified.
    for label, delay in zip(LABELS, (25, 90, 90)):
        time.sleep(delay)
        images.append(snapshot(monitor, evidence, args.profile, label))
    manifest = evidence / f"{args.profile}-display-probe.json"
    require(not manifest.exists() and not manifest.is_symlink(),
            "existing screenshot manifest")
    manifest.write_text(json.dumps({
        "profile": args.profile,
        "source": "qemu-hmp-guest-display-diagnostic-v1",
        "diagnosticOnly": True,
        "windowsClientBootVerified": False,
        "dualBootVerified": False,
        "rollbackVerified": False,
        "screenshots": images,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("GASLUX_WINDOWS_VISUAL_DIAGNOSTIC_CAPTURED=3")
    print("Neither Windows setup nor dual boot is accepted by screenshots.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ProbeError, OSError, TimeoutError) as exc:
        raise SystemExit(f"GASLUX_WINDOWS_VISUAL_PROBE_FAILED: {exc}")
