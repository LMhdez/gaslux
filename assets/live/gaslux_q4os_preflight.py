#!/usr/bin/env python3
"""Q4OS native-live diagnostics. Never invoke Calamares or Windows WinSetup."""

from __future__ import annotations

import re
from pathlib import Path

from gaslux_lab_media_probe import ProbeRefusal, diagnostic, read_os_release_evidence

BOOTLOADERS = {"bios/mbr": "grub", "uefi/gpt": "grub"}
_Q4OS_VERSION = re.compile(r"6\.[0-9]+(?:-deb[0-9]+u[0-9]+)?\Z")


def probe_q4os(
    *,
    iso_path: str,
    iso_size: int,
    iso_sha256: str,
    os_release_path: str,
    q4os_version_path: str,
    firmware: str,
    partition_style: str,
    secure_boot_enabled: bool,
    bootloader: str,
    source_kind: str,
) -> dict:
    """Inspect native candidate media with Q4OS-specific extra marker checks.

    Q4OS 6.9 reports ID=debian, not ID=q4os, so require separate version
    evidence; no trust binding between that evidence and the ISO exists here.
    """
    if source_kind != "native-live-calamares":
        raise ProbeRefusal("Windows-folder WinSetup is not a native Q4OS ISO installation")
    if type(q4os_version_path) is not str or not Path(q4os_version_path).is_absolute():
        raise ProbeRefusal("Q4OS version evidence path must be absolute")
    version_file = Path(q4os_version_path)
    if version_file.is_symlink() or not version_file.is_file() or version_file.stat().st_size > 128:
        raise ProbeRefusal("Invalid Q4OS version evidence file")
    try:
        q4os_version = version_file.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise ProbeRefusal("Unreadable Q4OS version evidence") from exc
    if _Q4OS_VERSION.fullmatch(q4os_version) is None:
        raise ProbeRefusal("Unexpected Q4OS native release identity")
    identity = read_os_release_evidence(os_release_path)
    if identity["ID"] != "debian" or identity.get("VERSION_ID") != "13":
        raise ProbeRefusal("Unexpected Q4OS Debian 13 live base")
    result = diagnostic(
        iso_path=iso_path,
        expected_size=iso_size,
        expected_sha256=iso_sha256,
        os_release_path=os_release_path,
        expected_os_id="debian",
        firmware=firmware,
        partition_style=partition_style,
        secure_boot_enabled=secure_boot_enabled,
        bootloader=bootloader,
        backend="q4os-native",
        allowed_modes=BOOTLOADERS,
        require_secure_boot_disabled=True,
    )
    result["q4osVersionEvidence"] = q4os_version
    result["calamaresPayloadVerified"] = False
    result["q4osIdentityBoundToIso"] = False
    return result
