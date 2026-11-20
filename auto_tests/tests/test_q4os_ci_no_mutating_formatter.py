"""Prevent CI from silently reformatting Q4OS sources before checking the commit."""

from __future__ import annotations

import re
from pathlib import Path

WORKFLOW = (
    Path(__file__).resolve().parents[2] / ".github/workflows/gaslux-q4os-windows-boundary.yml"
)


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_ruff_format_is_non_modifying_and_applies_to_committed_sources():
    commands = [
        line.strip()
        for line in _workflow().splitlines()
        if re.search(r"\bruff\s+format\b", line) and not line.lstrip().startswith("#")
    ]
    assert len(commands) == 1, "Unexpected Ruff formatter step added to CI"
    assert "ruff format --check " in commands[0]
    assert "--fix" not in commands[0]
    for path in (
        "assets/live/gaslux_q4os_windows_boundary.py",
        "assets/live/gaslux_q4os_safety_adapter.py",
        "auto_tests/tests/test_q4os_windows_boundary.py",
        "auto_tests/tests/test_q4os_safety_adapter.py",
        "auto_tests/tests/test_q4os_safety_actual_contract.py",
        "auto_tests/tests/test_q4os_ci_no_mutating_formatter.py",
    ):
        assert path in commands[0], f"Missing Ruff format --check target: {path}"


def test_ci_asserts_clean_working_tree_and_uses_pinned_safety_source():
    workflow = _workflow()
    assert "git diff --exit-code" in workflow
    assert "f55633c90973f633dda678f583f7730fc2cdc0ce" in workflow
    assert "GASLUX_Q4OS_PINNED_SAFETY_SOURCE_DIR" in workflow
    assert "test_q4os_safety_actual_contract.py" in workflow


def test_no_other_known_code_formatting_mutators_in_workflow():
    workflow = _workflow()
    for dangerous in (
        "ruff check --fix",
        "ruff format --config",
        "black ",
        "autopep8 ",
        "yapf -i",
        "isort ",
        "sed -i ",
    ):
        assert dangerous not in workflow, f"Mutating CI command found: {dangerous}"
