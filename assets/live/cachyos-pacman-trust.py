#!/usr/bin/env python3
"""Fail-closed signed-package policy guard for experimental CachyOS pacstrap.

Pacman, NOT a homegrown INI parser, resolves Include directives, inherited
SigLevel and per-repository overrides. Checks are read-only. No trust bypass,
key import, package download, or installer execution is performed.

This guard is necessary but NOT sufficient for real-disk readiness:
the Windows/Archiso boot transaction and root disk ownership remain unproven.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable

_ALLOWED = {
    "Required",
    "PackageRequired",
    "DatabaseRequired",
    "DatabaseOptional",
    "TrustedOnly",
    "PackageTrustedOnly",
    "DatabaseTrustedOnly",
}
_PACKAGE_REQUIRED = {"Required", "PackageRequired"}
_REPO = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_MINIMUM_REPOS = {"core", "extra", "cachyos"}


class PolicyError(ValueError):
    """Pacman configuration cannot prove required trusted package signatures."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise PolicyError(reason)


def verify_tokens(value: str, *, label: str) -> list[str]:
    # pacman-conf outputs the effective directives without a label when
    # invoked without --verbose. Refuse duplicate, unknown or weakening
    # tokens; any PackageOptional/Never/TrustAll undermines our contract.
    require(isinstance(value, str) and len(value) < 4096, f"{label}: invalid SigLevel")
    tokens = value.strip().split()
    require(bool(tokens) and len(set(tokens)) == len(tokens),
            f"{label}: missing or duplicated SigLevel tokens")
    require(set(tokens).issubset(_ALLOWED),
            f"{label}: weak or unknown SigLevel token")
    require(bool(set(tokens).intersection(_PACKAGE_REQUIRED)),
            f"{label}: package signatures are not mandatory")
    return tokens


def assess(
    config: Path,
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, object]:
    require(config.is_absolute() and config.is_file() and not config.is_symlink(),
            "pacman configuration must be a regular explicit absolute file")
    require(0 < config.stat().st_size < 2_000_000, "invalid pacman configuration size")
    require(config.resolve() == config, "pacman configuration is not a canonical path")

    def query(*args: str) -> str:
        try:
            result = run(
                ["pacman-conf", "--config", str(config), *args],
                capture_output=True, text=True, timeout=12, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise PolicyError("pacman-conf is unavailable or did not finish") from error
        require(result.returncode == 0 and isinstance(result.stdout, str),
                "pacman-conf rejected configuration or repository")
        require(len(result.stdout) < 24_000, "unexpectedly large pacman configuration response")
        return result.stdout.strip()

    global_level = verify_tokens(query("SigLevel"), label="global options")
    raw_repos = query("--repo-list").splitlines()
    require(3 <= len(raw_repos) <= 40, "unexpected number of active package repositories")
    repos: dict[str, list[str]] = {}
    for raw in raw_repos:
        repo = raw.strip()
        require(_REPO.fullmatch(repo) is not None and repo not in repos,
                "invalid or duplicated repository identity")
        repos[repo] = verify_tokens(
            query("--repo", repo, "SigLevel"), label=f"repository {repo}"
        )
    require(_MINIMUM_REPOS.issubset(repos),
            "Arch core/extra and CachyOS signed repositories are required")
    # Digest is evidence about the exact file inspected; no claim of its
    # trustworthiness is made, and included file digests are not calculated.
    return {
        "ok": True,
        "pacmanConfigSha256": hashlib.sha256(config.read_bytes()).hexdigest(),
        "packageSignaturesMandatory": True,
        "configuredRepositories": sorted(repos),
        "globalSigLevel": global_level,
        "repositorySigLevels": repos,
        "windowsInstallerStable": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    options = parser.parse_args(argv)
    try:
        result = assess(options.config)
    except (PolicyError, OSError, UnicodeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
