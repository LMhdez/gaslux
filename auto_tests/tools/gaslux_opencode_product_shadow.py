#!/usr/bin/env python3
"""Exact dev source replay and regression in a disposable namespace.

This is shadow evaluation of an existing lifecycle task, not new feature
admission, not a product checkout write, and never a Factory publisher input.
"""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile
import time

import gaslux_agent_feature_factory as factory
import gaslux_opencode_parent_boundary as boundary
import gaslux_opencode_trial as trial
import gaslux_opencode_workspace as broker

MAX_TREE = 32 * 1024**2
MAX_MEMBERS = 2048
MAX_BLOB = 2 * 1024**2
MAX_PRODUCT_ROUNDS = 2
PRODUCT_BUDGET_SECONDS = 2100
MIN_REPAIR_SECONDS = 300
ARCHIVE_PATHS = ("assets/live", "auto_tests/tests", "schemas",
                 "release-config.json", "auto_tests/app/filepool/catalog.json",
                 "iso-tools", "auto_tests/pyproject.toml")


def read_tree(repo, base, destination):
    if not factory.SHA.fullmatch(base) or factory.git(repo, "rev-parse", "HEAD") != base:
        raise ValueError("SHADOW_BASE_MISMATCH")
    # No .git, credentials, worktree edits or untracked files copied.
    result = subprocess.run(
        ["git", "-C", str(repo), "archive", "--format=tar", base, "--", *ARCHIVE_PATHS],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=True)
    if len(result.stdout) > MAX_TREE:
        raise ValueError("SHADOW_ARCHIVE_LIMIT")
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if (len(seen) >= MAX_MEMBERS or path.is_absolute() or ".." in path.parts
                    or not path.parts or path in seen or not (member.isdir() or member.isfile())
                    or member.size > MAX_BLOB):
                raise ValueError("SHADOW_ARCHIVE_MEMBER")
            if not any(path == PurePosixPath(prefix) or PurePosixPath(prefix) in path.parents
                       or (member.isdir() and path in PurePosixPath(prefix).parents)
                       for prefix in ARCHIVE_PATHS):
                raise ValueError("SHADOW_ARCHIVE_SCOPE")
            seen.add(path)
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source:
                    raw = source.read(MAX_BLOB + 1)
                if len(raw) != member.size:
                    raise ValueError("SHADOW_ARCHIVE_TRUNCATED")
                broker.write_new(target, raw)
    if not seen:
        raise ValueError("SHADOW_ARCHIVE_EMPTY")


def source_task(tree, role, base):
    target = tree / factory.TASKS[role][0]
    raw = broker.read_bounded(target, 25000)
    if b"\r" in raw or f"def assess_{role}_lifecycle(".encode() in raw:
        raise ValueError("SHADOW_SCOPE_ALREADY_IMPLEMENTED_OR_INVALID")
    return {"source_base": base, "source_sha256": factory.sha256(raw),
            "source_text": raw.decode("utf-8"),
            "product_replay": True, "product_edit_authorized": False,
            "task": factory.TASKS[role][2],
            "style_contract": "Ruff: double quotes; gates tuple and return dict on separate lines, "
                              "trailing commas, max 100 columns; one function only."}


def regression_counts(raw, code):
    # pytest emits duration after "passed"; parse the structured JUnit witness
    # instead of depending on terminal formatting, ANSI escapes or duration.
    import xml.etree.ElementTree as ET
    result = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0,
              "exit_code": code, "accepted": False}
    if not raw or len(raw) > 2 * 1024**2 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        return result
    try:
        root = ET.fromstring(raw)
        suites = [root] if root.tag == "testsuite" else list(root) if root.tag == "testsuites" else []
        if len(suites) != 1 or suites[0].tag != "testsuite":
            return result
        suite = suites[0]
        counts = {k: int(suite.attrib[k]) for k in ("tests", "failures", "errors", "skipped")}
        cases = suite.findall("testcase")
        if not 0 < counts["tests"] <= 10000 or len(cases) != counts["tests"]:
            return result
        observed = {k: sum(case.find(tag) is not None for case in cases)
                    for k, tag in (("failures", "failure"), ("errors", "error"), ("skipped", "skipped"))}
        if any(counts[k] != n for k, n in observed.items()):
            return result
        passed = counts["tests"] - sum(observed.values())
        if passed < 0 or any(sum(case.find(tag) is not None for tag in ("failure", "error", "skipped")) > 1
                             for case in cases):
            return result
        result.update(passed=passed, failed=counts["failures"], errors=counts["errors"],
                      skipped=counts["skipped"])
        result["accepted"] = code == 0 and passed > 0 and not any(observed.values())
    except (ET.ParseError, ValueError, KeyError):
        pass
    return result


def regression(tree, dependencies, role, work):
    suite = factory.TASKS[role][1]
    if not dependencies.is_dir() or dependencies.is_symlink():
        raise ValueError("SHADOW_TEST_DEPENDENCIES")
    with tempfile.TemporaryDirectory(prefix="regression-", dir=work) as tmp:
        scratch = Path(tmp)
        argv = boundary.sandbox_base() + [
            "--ro-bind", str(tree), "/product", "--ro-bind", str(dependencies), "/deps",
            "--bind", str(scratch), "/scratch", "--setenv", "HOME", "/scratch",
            "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "PYTHONPATH", "/deps",
            "--setenv", "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1",
            "--setenv", "PYTHONDONTWRITEBYTECODE", "1", "--chdir", "/product",
            "/usr/bin/python3", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
            "--junitxml=/scratch/result.xml", "auto_tests/tests/" + suite]
        code, _, _ = trial.bounded_process(argv, scratch, {"PATH": "/usr/bin:/bin"}, timeout=120)
        try:
            raw = broker.read_bounded(scratch / "result.xml", 2 * 1024**2)
        except (OSError, ValueError):
            raw = b""
        return regression_counts(raw, code)


def style_check(tree, dependencies, role, work):
    ruff = dependencies / "bin" / "ruff"
    if not ruff.is_file() or ruff.is_symlink():
        raise ValueError("SHADOW_RUFF_UNAVAILABLE")
    prefix = boundary.sandbox_base() + [
        "--ro-bind", str(tree), "/product", "--ro-bind", str(dependencies), "/deps",
        "--bind", str(work), "/scratch", "--setenv", "HOME", "/scratch",
        "--setenv", "XDG_CACHE_HOME", "/scratch", "--setenv", "PATH", "/usr/bin:/bin",
        "--chdir", "/product", "/deps/bin/ruff"]
    target = factory.TASKS[role][0]
    results = {}
    for label, args in (("lint", ["check", "--no-cache"]),
                        ("format", ["format", "--check", "--no-cache"])):
        code, _, _ = trial.bounded_process(
            prefix + args + ["--config", "/product/auto_tests/pyproject.toml", target],
            work, {"PATH": "/usr/bin:/bin"}, timeout=60)
        results[label] = code
    results["accepted"] = all(code == 0 for code in results.values())
    return results


def factory_contract(repo, role, base, task, addition, expected, directory):
    # Exercise the existing independent verifier's exact report/byte contract
    # without exporting a publishable artifact or enabling the publisher.
    artifact = {"scope": "lifecycle", "composition": "opencode-python-v1", "role": role, "base": base,
                "target": factory.TASKS[role][0], "task": factory.TASKS[role][2],
                "model": factory.MODEL, "model_digest": factory.MODEL_DIGEST,
                "addition_sha256": factory.sha256(addition.encode()),
                "source_sha256": task["source_sha256"],
                "candidate_sha256": expected["product_candidate_sha256"]}
    broker.write_new(directory / "addition.py", addition.encode())
    broker.write_new(directory / "report.json", json.dumps(artifact, sort_keys=True).encode())
    verified = factory.verify(repo, directory, role, base, execute=False, scope="lifecycle")
    if verified != artifact:
        raise ValueError("SHADOW_FACTORY_CONTRACT_MISMATCH")
    return factory.sha256((directory / "report.json").read_bytes())


def apply_candidate(tree, role, task, addition):
    original, proposed = factory.expected_source(tree, role, addition, formatted_repair=True)
    if factory.sha256(original) != task["source_sha256"]:
        raise ValueError("SHADOW_SOURCE_CHANGED")
    broker.validate_source(role, addition)
    if broker.isolated_test(role, addition) != "PASS":
        raise ValueError("SHADOW_FUNCTIONAL_REJECTED")
    target = tree / factory.TASKS[role][0]
    # Private controller-owned archive copy, never host checkout. Replace
    # atomically after exact base/hash/AST checks; no model path argument.
    temporary = target.with_name(target.name + ".candidate")
    broker.write_new(temporary, proposed)
    os.replace(temporary, target)
    if broker.read_bounded(target, 32000) != proposed:
        raise ValueError("SHADOW_READBACK")
    return {"source_sha256": factory.sha256(original),
            "addition_sha256": factory.sha256(addition.encode()),
            "product_candidate_sha256": factory.sha256(proposed)}


def repair_feedback(round_report, addition):
    # Never retry resource/sandbox/proxy errors, failed baseline, unknown
    # status, or a candidate whose actual tests did not execute.
    stage = round_report.get("stage")
    category = None
    if stage == "style_and_factory_contract":
        style = round_report.get("style", {})
        codes = [style.get("lint"), style.get("format")]
        if all(type(code) is int and code in (0, 1) for code in codes) and 1 in codes:
            category = "STYLE_REJECTED"
    elif stage == "candidate_regression":
        result = round_report.get("candidate_regression", {})
        if (result.get("exit_code") == 1 and type(result.get("failed")) is int
                and result["failed"] > 0):
            category = "REGRESSION_REJECTED"
    if category is None or type(addition) is not str:
        return None
    return {"category": category, "prior_source": addition,
            "prior_addition_sha256": factory.sha256(addition.encode())}


def run_round(binary, repo, base, dependencies, role, context, round_root, task, feedback,
              remaining, selected_artifacts=None):
    import gaslux_opencode_iterative as iterative
    tree, tests, verification = (round_root / n for n in ("tree", "tests", "verification"))
    for path in (tree, tests, verification):
        path.mkdir(mode=0o700)
    row = {"accepted": False, "stage": "exact_source", "product_regressions_run": False}
    read_tree(repo, base, tree)
    current = source_task(tree, role, base)
    if current != task:
        raise ValueError("SHADOW_SOURCE_CHANGED")
    context_data = {**task}
    if feedback is not None:
        context_data["repair_feedback"] = feedback
    row["stage"] = "native_iteration"
    selected = []
    iteration = iterative.run(binary, role, context, product=context_data,
                              accepted_source=selected, timeout=min(1200, remaining))
    row["iteration"] = iteration
    if not iteration["accepted"] or len(selected) != 1:
        row["failure"] = "SHADOW_ITERATION_RED"
        return row, None
    addition = selected[0]
    row["stage"] = "candidate_composition"
    expected = apply_candidate(tree, role, task, addition)
    row.update(expected)
    row["stage"] = "style_and_factory_contract"
    row["style"] = style_check(tree, dependencies, role, tests)
    if not row["style"]["accepted"]:
        row["failure"] = "SHADOW_STYLE_RED"
        return row, repair_feedback(row, addition)
    row["factory_static_verification_sha256"] = factory_contract(
        repo, role, base, task, addition, expected, verification)
    row["factory_artifact_contract_verified"] = True
    row["stage"] = "candidate_regression"
    candidate = regression(tree, dependencies, role, tests)
    row["candidate_regression"] = candidate
    row["product_regressions_run"] = True
    if not candidate["accepted"]:
        row["failure"] = "SHADOW_CANDIDATE_RED"
        return row, repair_feedback(row, addition)
    row["accepted"] = True
    if selected_artifacts is not None:
        selected_artifacts.append((broker.read_bounded(verification / "addition.py", broker.MAX_SOURCE),
                                   broker.read_bounded(verification / "report.json", 32768)))
    row["stage"] = None
    return row, None


def evaluate(binary, repo, base, dependencies, role, context, *, selected_artifacts=None):
    started = time.monotonic()
    deadline = started + PRODUCT_BUDGET_SECONDS
    report = {"kind": "opencode_exact_dev_shadow_v2", "base": base, "role": role,
              "accepted": False, "product_regressions_run": False,
              "rounds": [], "maximum_rounds": MAX_PRODUCT_ROUNDS,
              "budget_seconds": PRODUCT_BUDGET_SECONDS,
              "product_edit_authorized": False, "publish_authorized": False,
              "merge_authorized": False, "writer_authorized": False, "release_eligible": False}
    try:
        with tempfile.TemporaryDirectory(prefix="gaslux-product-shadow-") as temp:
            root = Path(temp)
            tree, tests = root / "tree", root / "tests"
            tree.mkdir(mode=0o700)
            tests.mkdir(mode=0o700)
            report["stage"] = "exact_source"
            read_tree(repo, base, tree)
            task = source_task(tree, role, base)
            report["source_sha256"] = task["source_sha256"]
            report["stage"] = "baseline_style"
            report["baseline_style"] = style_check(tree, dependencies, role, tests)
            if not report["baseline_style"]["accepted"]:
                raise ValueError("SHADOW_BASELINE_STYLE_RED")
            report["stage"] = "baseline_regression"
            baseline = regression(tree, dependencies, role, tests)
            report["baseline_regression"] = baseline
            if not baseline["accepted"]:
                raise ValueError("SHADOW_BASELINE_RED")
            feedback = None
            for number in range(MAX_PRODUCT_ROUNDS):
                remaining = int(deadline - time.monotonic())
                if remaining < MIN_REPAIR_SECONDS:
                    raise ValueError("SHADOW_BUDGET_EXHAUSTED")
                round_root = root / f"round-{number + 1}"
                round_root.mkdir(mode=0o700)
                report["stage"] = "product_round"
                row, feedback = run_round(binary, repo, base, dependencies, role, context,
                                          round_root, task, feedback, remaining, selected_artifacts)
                report["rounds"].append(row)
                report["product_regressions_run"] |= row["product_regressions_run"]
                report["stage"] = row["stage"]
                if row["accepted"]:
                    if row["candidate_regression"]["passed"] != baseline["passed"]:
                        raise ValueError("SHADOW_TEST_COUNT_MISMATCH")
                    report["accepted"] = True
                    report["factory_artifact_contract_verified"] = True
                    report["candidate_sha256"] = row["product_candidate_sha256"]
                    break
                report["failure"] = row["failure"]
                if feedback is None or number + 1 == MAX_PRODUCT_ROUNDS:
                    break
            if report["accepted"]:
                report.pop("failure", None)
    except (ValueError, TypeError, KeyError, SyntaxError, OSError, RuntimeError,
            subprocess.SubprocessError, tarfile.TarError) as error:
        allowed = {"SHADOW_BASE_MISMATCH", "SHADOW_ARCHIVE_LIMIT", "SHADOW_ARCHIVE_MEMBER",
                   "SHADOW_ARCHIVE_SCOPE", "SHADOW_ARCHIVE_TRUNCATED", "SHADOW_ARCHIVE_EMPTY",
                   "SHADOW_SCOPE_ALREADY_IMPLEMENTED_OR_INVALID", "SHADOW_TEST_DEPENDENCIES",
                   "SHADOW_SOURCE_CHANGED", "SHADOW_FUNCTIONAL_REJECTED", "SHADOW_READBACK",
                   "SHADOW_BASELINE_RED", "SHADOW_ITERATION_RED", "SHADOW_CANDIDATE_RED",
                   "SHADOW_STYLE_RED", "SHADOW_RUFF_UNAVAILABLE", "SHADOW_FACTORY_CONTRACT_MISMATCH",
                   "SHADOW_BASELINE_STYLE_RED", "SHADOW_BUDGET_EXHAUSTED", "SHADOW_TEST_COUNT_MISMATCH"}
        report["failure"] = str(error) if type(error) is ValueError and str(error) in allowed else type(error).__name__
    report["elapsed_seconds"] = round(time.monotonic() - started, 2)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--dependencies", required=True, type=Path)
    parser.add_argument("--role", required=True, choices=tuple(factory.TASKS))
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    report = evaluate(args.binary.resolve(strict=True), args.repo.resolve(strict=True), args.base,
                      args.dependencies.resolve(strict=True), args.role, trial.COMPACT_CONTEXT)
    broker.write_new(args.report, (json.dumps(report, sort_keys=True, indent=2) + "\n").encode())
    print(json.dumps(report, sort_keys=True))
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
