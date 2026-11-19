"""Negative tests for independent Q4OS artifact hash and pair-integrity verifier."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "auto_tests/tools/q4os_ui_pair_verify.py"
SPEC = importlib.util.spec_from_file_location("q4os_pair_test", MODULE)
assert SPEC is not None and SPEC.loader is not None
pair = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pair)


def write_files(root: Path, names: dict[str, bytes], *, reverse: bool = False) -> None:
    root.mkdir()
    for name, content in names.items():
        (root / name).write_bytes(content)
    ordered = sorted(names, reverse=reverse)
    (root / "evidence.sha256").write_text(
        "".join(f"{hashlib.sha256(names[name]).hexdigest()}  {name}\n" for name in ordered)
    )


def test_valid_checksum_manifest_only(tmp_path: Path) -> None:
    root = tmp_path / "valid"
    write_files(root, {"a.txt": b"synthetic", "b.txt": b"synthetic two"})
    digests = pair.verify_manifest(root)
    assert set(digests) == {"a.txt", "b.txt"}


def test_original_png_mutation_refused(tmp_path: Path) -> None:
    root = tmp_path / "mutated"
    write_files(root, {"vnc-users-page.png": b"fixture-not-a-real-screenshot"})
    (root / "vnc-users-page.png").write_bytes(b"changed")
    with pytest.raises(pair.PairProofError, match="changed"):
        pair.verify_manifest(root)


def test_manifest_missing_or_extra_png_refused(tmp_path: Path) -> None:
    root = tmp_path / "extra"
    write_files(root, {"a.txt": b"a"})
    (root / "rogue.png").write_bytes(b"added")
    with pytest.raises(pair.PairProofError, match="unlisted"):
        pair.verify_manifest(root)


def test_manifest_sort_and_symlink_refused(tmp_path: Path) -> None:
    root = tmp_path / "unsorted"
    write_files(root, {"a.txt": b"a", "b.txt": b"b"}, reverse=True)
    with pytest.raises(pair.PairProofError, match="Unsorted"):
        pair.verify_manifest(root)
    other = tmp_path / "symlink"
    other.mkdir()
    (other / "linked.txt").symlink_to(root / "a.txt")
    with pytest.raises(pair.PairProofError):
        pair.read_regular(other, "linked.txt")


def test_not_two_guest_artifacts_refused(tmp_path: Path) -> None:
    with pytest.raises(pair.PairProofError, match="Exactly two"):
        pair.verify_pair([], tmp_path / "no-map.json", tmp_path / "no-gate.py")
