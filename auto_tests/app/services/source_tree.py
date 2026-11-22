from __future__ import annotations

import re
import subprocess
from pathlib import Path


class LocalSourceTree:
    """Policy for selecting files copied by source=local."""

    @staticmethod
    def repository_root() -> Path:
        return Path(__file__).resolve().parents[3]


    @staticmethod
    def verified_gaslux_checkout(root: Path) -> tuple[str, str]:
        """Record Git origin and HEAD, denying a wrong or nested source checkout.

        Git configuration is an operator-controlled identity check, not independent
        cryptographic attestation of the worktree or its remote history.
        """

        allowed = {
            "https://github.com/LMhdez/gaslux",
            "https://github.com/LMhdez/gaslux.git",
            "git@github.com:LMhdez/gaslux.git",
            "ssh://git@github.com/LMhdez/gaslux.git",
        }

        def git(*arguments: str) -> str:
            try:
                completed = subprocess.run(
                    ["git", "-C", str(root), *arguments],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise RuntimeError("Gaslux checkout Git inspection failed") from error
            if completed.returncode != 0:
                raise RuntimeError(
                    "Gaslux checkout Git inspection failed: "
                    + completed.stderr.strip()[:300]
                )
            return completed.stdout.strip()

        try:
            checkout_root = Path(git("rev-parse", "--show-toplevel")).resolve(strict=True)
            expected_root = root.resolve(strict=True)
        except OSError as error:
            raise RuntimeError("Gaslux checkout root is unavailable") from error
        if checkout_root != expected_root:
            raise RuntimeError("Gaslux source is not the root of its Git checkout")

        configured_origin = git("config", "--local", "--get", "remote.origin.url")
        effective_origin = git("remote", "get-url", "origin")
        if configured_origin not in allowed or effective_origin not in allowed:
            raise RuntimeError("Gaslux checkout origin must be LMhdez/gaslux")
        revision = git("rev-parse", "--verify", "HEAD")
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise RuntimeError("Gaslux checkout HEAD is not a complete commit SHA")
        return effective_origin, revision

    @staticmethod
    def selected_files(root: Path) -> tuple[Path, ...]:
        """Return tracked and non-ignored files from the current Git worktree."""

        completed = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            check=False,
            capture_output=True,
        )
        if completed.returncode != 0:
            diagnostic = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"Git could not enumerate the local source tree: {diagnostic}")

        selected: list[Path] = []
        for raw_relative in completed.stdout.split(b"\0"):
            if not raw_relative:
                continue
            relative = Path(raw_relative.decode("utf-8", errors="strict"))
            if relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError(f"Git returned an unsafe source path: {relative}")
            path = root / relative
            if path.is_file() or path.is_symlink():
                selected.append(path)
        return tuple(sorted(selected, key=lambda path: path.as_posix()))
