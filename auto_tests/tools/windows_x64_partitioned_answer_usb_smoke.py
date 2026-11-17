#!/usr/bin/env python3
"""GitHub-hosted CI: create and read a *synthetic* FAT32 MBR answer FILE.

No Microsoft ISO, Windows guest, KVM, Linux installer, partitioned host disk,
device node or real credentials are read or written by this test.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile

from windows_x64_partitioned_answer_usb import (
    CONSENT, IMAGE_BYTES, build_partitioned_answer,
    inspect_partitioned_image, require,
)


def run() -> None:
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "Linux"
            and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
            and os.environ.get("GASLUX_PARTITIONED_ANSWER_CONSENT") == CONSENT
            and os.environ.get("RUNNER_TEMP") == "/home/runner/work/_temp",
            "synthetic FAT32 MBR smoke requires hosted GitHub runner consent")
    with tempfile.TemporaryDirectory(
        prefix="gaslux-win-x64-", dir="/home/runner/work/_temp"
    ) as tmp:
        workspace = Path(tmp)
        require(workspace.stat().st_mode & 0o777 == 0o700,
                "synthetic owned temporary workspace must be private")
        xml = workspace / "Autounattend.xml"
        ps = workspace / "GASLUX.PS1"
        xml.write_bytes(
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<unattend xmlns="urn:schemas-microsoft-com:unattend"/>'
        )
        ps.write_bytes(b"Write-Output 'SYNTHETIC_NOT_WINDOWS'\n")
        image = workspace / "only-disposable-answer-usb.img"
        build_partitioned_answer(image, xml, ps)
        inspect_partitioned_image(image)
        require(image.stat().st_size == IMAGE_BYTES,
                "synthetic FAT32 MBR file size changed")
        print("GASLUX_SYNTHETIC_FAT32_MBR_USB_OWNED_READBACK_OK=1")
        print("GASLUX_WINDOWS_CLIENT_FIRSTBOOT_VERIFIED=0")
        print("GASLUX_SAME_DISK_DUALBOOT_VERIFIED=0")


if __name__ == "__main__":
    run()
