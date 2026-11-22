"""Real upstream source pin tests; valid documents never grant installation."""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))
from bazzite_native_route_readback import (  # noqa: E402
    NO_WRITE,
    SOURCE_PINS,
    Refusal,
    classify,
    git_blob,
    read_sources,
)


@pytest.fixture(scope="module")
def official():
    location = os.environ.get("GASLUX_BAZZITE_NATIVE_SOURCES")
    assert location, "Pinned upstream Git source readback required"
    root = Path(location)
    assert root.is_dir()
    return root


def test_actual_upstream_blobs_verified(official):
    source = read_sources(official)
    assert set(source) == set(SOURCE_PINS)
    for name, item in source.items():
        assert item["gitBlob"] == SOURCE_PINS[name][3]
        assert item["runtimeAttested"] is False
        assert len(item["sha256"]) == 64


def test_six_routes_fail_closed_after_readback(official):
    decision = classify(read_sources(official))
    assert {r["route"]: r["status"] for r in decision["routes"]} == {
        "ISO45_CUSTOM_GPT_4_6": "INCOMPATIBLE_ROUTE",
        "ISO45_AUTOMATIC_WINDOWS": "BLOCKED_BY_SAFETY_CONTRACT",
        "LEGACY_BLIVET": "BLOCKED_BY_SAFETY_CONTRACT",
        "BOOTC_TO_DISK": "INCOMPATIBLE_ROUTE",
        "BOOTC_TO_EXISTING_ROOT": "INCOMPATIBLE_ROUTE",
        "BOOTC_TO_FILESYSTEM": "BLOCKED_BY_SAFETY_CONTRACT",
    }
    assert decision["guestAuthenticated"] is False
    assert decision["anacondaDbusObserved"] is False
    assert decision["bootcRuntimeProven"] is False
    assert all(decision[k] is False for k in NO_WRITE)
    for route in decision["routes"]:
        assert route["nativeWriteSetObserved"] is False
        assert route["windowsPreservationProven"] is False
        assert route["bazziteRuntimeCompatibilityProven"] is False
        assert all(route[k] is False for k in NO_WRITE)


@pytest.mark.parametrize("name", list(SOURCE_PINS))
def test_tampered_source_bytes_refused(official, tmp_path, name):
    for item in official.iterdir():
        shutil.copy2(item, tmp_path / item.name)
    path = tmp_path / f"{name}.md"
    path.write_bytes(path.read_bytes() + b"\nattacker")
    with pytest.raises(Refusal, match="Changed official Git blob"):
        read_sources(tmp_path)


def test_extra_missing_and_symlink_sources_refused(official, tmp_path):
    for item in official.iterdir():
        shutil.copy2(item, tmp_path / item.name)
    (tmp_path / "unknown.md").write_text("unexpected")
    with pytest.raises(Refusal, match="Unexpected or absent"):
        read_sources(tmp_path)
    (tmp_path / "unknown.md").unlink()
    (tmp_path / "modern.md").unlink()
    with pytest.raises(Refusal, match="Unexpected or absent"):
        read_sources(tmp_path)
    (tmp_path / "modern.md").symlink_to(official / "modern.md")
    with pytest.raises(Refusal, match="Symlink"):
        read_sources(tmp_path)


def test_mismatched_commit_or_forged_attestation_rejected(official):
    source = read_sources(official)
    forged = copy.deepcopy(source)
    forged["to-filesystem"]["commit"] = "0" * 40
    with pytest.raises(Refusal, match="Substituted"):
        classify(forged)
    forged = copy.deepcopy(source)
    forged["modern"]["runtimeAttested"] = True
    with pytest.raises(Refusal, match="forged"):
        classify(forged)


def test_blob_hash_includes_git_header():
    assert git_blob(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_valid_source_cli_always_returns_exit_2(official):
    script = ROOT / "auto_tests" / "bazzite_native_route_readback.py"
    args = [sys.executable, str(script), "--sources-dir", str(official)]
    for _ in range(2):
        call = subprocess.run(
            args, capture_output=True, text=True, check=False, timeout=10
        )
        assert call.returncode == 2
        report = json.loads(call.stdout)
        assert all(report[key] is False for key in NO_WRITE)


def test_invalid_source_cli_exit_3(tmp_path):
    script = ROOT / "auto_tests" / "bazzite_native_route_readback.py"
    call = subprocess.run(
        [sys.executable, str(script), "--sources-dir", str(tmp_path)],
        capture_output=True, text=True, check=False, timeout=10,
    )
    assert call.returncode == 3
    assert "REFUSED_SOURCE" in call.stderr
