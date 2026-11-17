#!/usr/bin/env python3
"""Read-only evidence of Windows Setup caching Autounattend.xml after DVD stage.

Only a freshly created CI-owned file-backed QCOW2 is inspected. The cached
answer may contain passwords: NEVER print/archive its bytes or any guest logs.
This diagnostic cannot establish Windows firstboot, BCD, WinRE or dual boot.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path


class PantherProbeError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PantherProbeError(message)


def validate_owned_disk(disk: Path) -> None:
    parent = disk.parent
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and disk.is_absolute()
        and disk.name == "only-disposable-windows-target.qcow2"
        and parent.parent == Path("/home/runner/work/_temp")
        and parent.name.startswith("gaslux-win-x64-")
        and parent.is_dir() and not parent.is_symlink()
        and parent.resolve() == parent
        and parent.stat().st_uid == os.getuid()
        and stat.S_IMODE(parent.stat().st_mode) == 0o700
        and disk.is_file() and not disk.is_symlink()
        and disk.stat().st_uid == os.getuid()
        and stat.S_ISREG(disk.stat().st_mode),
        "offline Panther probe refused unowned or physical disk",
    )


def guestfish_command(disk: Path, *args: str) -> list[str]:
    return ["/usr/bin/guestfish", "--ro", "--format=qcow2",
            "-a", str(disk), *args]


def inspect_cached_oobe_answer(
    disk: Path, *, runner=subprocess.run
) -> dict[str, object]:
    """Inspect only the cached Windows Setup XML; never write a guest disk.

    All guestfish invocations are read-only, bounded and completed before
    any second Windows guest launches. Data is processed only in memory.
    """
    validate_owned_disk(disk)
    require(Path("/usr/bin/guestfish").is_file(),
            "guestfish read-only diagnostic dependency missing")
    safe_env = dict(os.environ)
    safe_env.update(LIBGUESTFS_BACKEND="direct", LIBGUESTFS_MEMSIZE="512")

    def execute(*args: str):
        return runner(guestfish_command(disk, *args),
                      check=False, capture_output=True, timeout=95,
                      env=safe_env)

    try:
        filesystems = execute("run", ":", "list-filesystems")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PantherProbeError("offline guestfish could not inspect QCOW2") from exc
    require(filesystems.returncode == 0
            and len(filesystems.stdout) <= 16_384,
            "offline filesystem enumeration failed")
    # These identifiers exist ONLY inside libguestfs's private virtual
    # appliance, never on the host. Refuse anything not a guest partition.
    volumes = []
    for line in filesystems.stdout.decode("ascii", "replace").splitlines():
        matched = re.fullmatch(r"(/dev/sda[1-9][0-9]*): ntfs", line.strip())
        if matched:
            volumes.append(matched.group(1))
    require(0 < len(volumes) <= 4 and len(set(volumes)) == len(volumes),
            "Windows guest NTFS partition inventory ambiguous")

    # Windows Setup caches the answer under Windows/Panther on installed OS.
    # A USB answer file by itself is NOT evidence Windows ever read it.
    targets = (
        "/Windows/Panther/Unattend.xml",
        "/Windows/Panther/Autounattend.xml",
        "/$WINDOWS.~BT/Sources/Panther/Unattend.xml",
        "/$WINDOWS.~BT/Sources/Panther/Autounattend.xml",
    )
    for volume in volumes:
        for path in targets:
            try:
                # Bound guest-origin bytes BEFORE reading an unattend file,
                # whose content may contain confidential lab credentials.
                length = execute("-m", volume + ":/", "filesize", path)
                if length.returncode != 0 or len(length.stdout) > 12:
                    continue
                size = length.stdout.strip()
                if not re.fullmatch(rb"[0-9]{1,6}", size) or not (
                    0 < int(size) <= 256_000
                ):
                    continue
                result = execute("-m", volume + ":/", "cat", path)
            except (OSError, subprocess.TimeoutExpired):
                continue
            if result.returncode != 0:
                continue
            # guestfish 'cat' writes file bytes to stdout and appends ONE
            # presentation LF even when the original XML already ends in LF.
            # The filesize response is the guest-file authority. Accept
            # exactly N bytes or N+1 with a sole CLI LF, never arbitrary
            # trailing bytes or a shortened/altered file.
            expected_size = int(size)
            if len(result.stdout) == expected_size:
                payload = result.stdout
            elif (len(result.stdout) == expected_size + 1
                  and result.stdout.endswith(b"\n")):
                payload = result.stdout[:-1]
            else:
                continue
            try:
                root = ET.fromstring(payload)
            except ET.ParseError:
                continue
            ns = "{urn:schemas-microsoft-com:unattend}"
            if root.tag != ns + "unattend":
                continue
            oobe = [e for e in root.findall(ns + "settings")
                    if e.attrib.get("pass") == "oobeSystem"]
            if len(oobe) != 1:
                continue
            # The Windows-cached answer is annotated; only prove it exists
            # and retained an OOBE pass. Not proof the pass was applied.
            print("GASLUX_WINDOWS_STAGE1_PANTHER_CACHED_OOBE_FOUND=1",
                  flush=True)
            return {
                "cachedWindowsAnswerObserved": True,
                "cachedAnswerOobePassPresent": True,
                "cachedAnswerSha256": hashlib.sha256(payload).hexdigest(),
                "cachedAnswerSource": "installedWindowsPanther",
                "windowsClientBootVerified": False,
            }
    print("GASLUX_WINDOWS_STAGE1_PANTHER_CACHED_OOBE_FOUND=0",
          flush=True)
    return {
        "cachedWindowsAnswerObserved": False,
        "cachedAnswerOobePassPresent": False,
        "windowsClientBootVerified": False,
    }
