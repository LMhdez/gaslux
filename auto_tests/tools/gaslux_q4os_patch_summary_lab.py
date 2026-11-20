#!/usr/bin/env python3
"""Inject a fail-closed, auditable no-write Summary hook into pinned VM lab COPY.

The upstream script and production installer are never committed/changed.
The exact original anchored line must be present ONCE, or patch is refused.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

OLD = "            echo 'NOT PERFORMED: user creation, password entry, Summary, Install or any exec job.'"
NEW = '''            if [[ "${GASLUX_Q4OS_SUMMARY_READONLY:-}" == 1 ]]; then
              [[ -f "${GASLUX_Q4OS_SUMMARY_READONLY_HOOK:-}" ]] ||
                die "Missing fail-closed Q4OS Summary experiment hook"
              . "$GASLUX_Q4OS_SUMMARY_READONLY_HOOK"
            else
              echo 'NOT PERFORMED: user creation, password entry, Summary, Install or any exec job.'
            fi'''


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Expected exact pinned Q4OS lab script path")
    path = Path(sys.argv[1])
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise SystemExit("Cannot patch non-regular or non-absolute VM lab script")
    original = path.read_text(encoding="utf-8")
    if original.count(OLD) != 1 or original.count("calamares_users_view_verified=1") != 1:
        raise SystemExit("Pinned Q4OS source anchor changed; refused to patch")
    replacement = original.replace(OLD, NEW, 1)
    if replacement.count(NEW) != 1:
        raise SystemExit("Patched lab hook not unique")
    path.write_text(replacement, encoding="utf-8")
    print("GASLUX_Q4OS_SUMMARY_EXPERIMENT_PATCH_BASE_SHA256="+hashlib.sha256(
        original.encode("utf-8")
    ).hexdigest())
    print("GASLUX_Q4OS_SUMMARY_EXPERIMENT_PATCHED_SHA256="+hashlib.sha256(
        replacement.encode("utf-8")
    ).hexdigest())
    print("GASLUX_Q4OS_PRODUCTION_INSTALLER_UNCHANGED=true")


if __name__ == "__main__":
    main()
