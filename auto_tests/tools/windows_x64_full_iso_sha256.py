#!/usr/bin/env python3
"""Verify actual Microsoft x64 evaluation ISO bytes in disposable GitHub Actions.

No Windows installation, QEMU or physical disk access; source ISO is deleted,
never uploaded. A successful hash is NOT an installed Windows boot.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import urllib.error
from pathlib import Path

from windows_x64_qemu_host_gate import EXPECTED, load_catalog
from windows_x64_tcg_firstboot import LabError, download_verified_iso

# Independently observed official Microsoft HTTPS response sizes, 2026-11-17.
# Treat size changes as a blocker pending re-verification; never trust JSON
# to change these values silently.
EXPECTED_BYTES = {
    "win10_22h2_en_us_x64": 5550497792,
    "win11_26h2_en_us_x64": 8225329152,
}
CONSENT = "DISPOSABLE_GITHUB_ISO_BYTES_ONLY"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=sorted(EXPECTED), required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    key = args.profile
    report = {
        "schemaVersion": 1, "profile": key, "isoSha256Verified": False,
        "windows10InstalledAndBooted": False,
        "windows11InstalledAndBooted": False,
        "windowsClientFirstBootVerified": False,
        "dualBootVerified": False,
        "windowsRecoveryVerified": False,
        "stable": False,
    }

    root = args.evidence_dir
    tmp = Path(os.environ.get("RUNNER_TEMP", ""))
    if not (os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_OS") == "Linux" and
            os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux" and
            os.environ.get("GASLUX_ISO_BYTES_CONSENT") == CONSENT and
            tmp == Path("/home/runner/work/_temp") and tmp.is_dir() and
            not tmp.is_symlink() and
            root.is_absolute() and root.is_dir() and
            not root.is_symlink() and root.resolve() == root and
            root.name == "windows-iso-digest-evidence"):
        print("refused: no authorized disposable GitHub-hosted Linux ISO lab",
              file=sys.stderr)
        return 2
    output = root / f"{key}-sha256.json"
    if output.exists() or output.is_symlink():
        print("refusing to overwrite earlier evidence", file=sys.stderr)
        return 2

    status = 1
    try:
        profile = load_catalog()["profiles"][key]
        expected_sha = EXPECTED[key]
        expected_size = EXPECTED_BYTES[key]
        if profile["sha256"] != expected_sha:
            raise LabError("untrusted SHA-256 metadata")
        if shutil.disk_usage(tmp).free < expected_size + 4 * 1024**3:
            raise LabError("not enough runner temporary storage for ISO hash check")
        with tempfile.TemporaryDirectory(prefix="gaslux-win-iso-",
                                         dir=tmp) as workspace:
            iso = Path(workspace) / "official-microsoft-evaluation.iso"
            observed_hash, observed_size = download_verified_iso(profile, iso)
            if observed_size != expected_size or observed_hash != expected_sha:
                raise LabError("ISO length/hash fails independently pinned baseline")
            report.update(
                isoSha256Verified=True,
                isoSha256=observed_hash,
                isoBytes=observed_size,
            )
        status = 0
    except (LabError, urllib.error.HTTPError, urllib.error.URLError,
            OSError, ValueError, TimeoutError):
        # Never print upstream exceptions: URLs can contain signed access tokens.
        report["blocker"] = "Microsoft ISO download/integrity/storage failure"
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return status


if __name__ == "__main__":
    sys.exit(main())
