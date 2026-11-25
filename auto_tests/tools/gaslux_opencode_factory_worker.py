#!/usr/bin/env python3
"""Route only admitted tasks; export exact native candidate after isolated checks."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import tempfile
import gaslux_agent_feature_factory as factory
import gaslux_opencode_product_shadow as shadow
import gaslux_opencode_trial as trial
import gaslux_opencode_workspace as broker


def route(plan):
    if type(plan) is not dict or plan.get("status") not in ("pending", "idle", "blocked"):
        raise ValueError("Invalid planner state")
    if plan["status"] != "pending":
        return "none"
    role, base, scope = plan.get("role"), plan.get("base"), plan.get("scope")
    if role not in factory.TASKS or type(base) is not str or not factory.SHA.fullmatch(base):
        raise ValueError("Invalid task identity")
    number, head = plan.get("repair_pr"), plan.get("repair_head")
    if number is not None or head is not None:
        if scope != "lifecycle" or not factory.repair_identity(number, head):
            raise ValueError("Invalid repair routing")
        return "repair"
    if scope == "lifecycle" and plan.get("task") == factory.TASKS[role][2]:
        return "opencode"
    if scope == factory.SCOPE2B_ID and role == "mint" and plan.get("task") == factory.SCOPE2B_TASK:
        return "direct"
    if scope == factory.SUPERVISED_TEST_SCOPE:
        if (plan.get("task") == "Add missing persistent lifecycle helper regression"
                and plan.get("code_authorized") == "canonical-test-only"
                and plan.get("installation_authorized") is False
                and plan.get("release_eligible") is False):
            return "canonical"
    if scope == factory.SUPERVISED_MEDIA_SCOPE and role in factory.SUPERVISED_MEDIA:
        if (plan.get("task") == "Add missing pinned release descriptor comparison"
                and plan.get("code_authorized") == "canonical-read-only-product"
                and plan.get("installation_authorized") is False
                and plan.get("release_eligible") is False):
            return "canonical"
    raise ValueError("Unadmitted scope")


def export(repo, role, base, result, artifacts, destination):
    if (result.get("accepted") is not True or result.get("product_regressions_run") is not True
            or result.get("factory_artifact_contract_verified") is not True
            or result.get("base") != base or result.get("role") != role or len(artifacts) != 1):
        raise ValueError("OpenCode product checks incomplete")
    addition, report = artifacts[0]
    row = json.loads(report)
    if (row.get("composition") != "opencode-python-v1"
            or row.get("candidate_sha256") != result.get("candidate_sha256")):
        raise ValueError("OpenCode final artifact mismatch")
    if destination.exists() or destination.is_symlink():
        raise ValueError("Candidate destination must be new")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".candidate-", dir=destination.parent) as tmp:
        stage = Path(tmp) / "verified"
        stage.mkdir(mode=0o700)
        broker.write_new(stage / "addition.py", addition)
        broker.write_new(stage / "report.json", report)
        factory.verify(repo, stage, role, base, execute=False, scope="lifecycle")
        os.rename(stage, destination)


def main():
    p = argparse.ArgumentParser()
    for arg in ("binary", "repo", "dependencies", "evidence"):
        p.add_argument("--" + arg, required=True, type=Path)
    p.add_argument("--base", required=True)
    p.add_argument("--role", required=True, choices=tuple(factory.TASKS))
    p.add_argument("--scope", required=True)
    a = p.parse_args()
    if (os.getenv("GITHUB_REPOSITORY") != factory.REPO
            or os.getenv("GITHUB_REF") != "refs/heads/main"
            or os.getenv("GASLUX_AUTONOMY_PAUSED", "").strip().lower() == "true"
            or a.scope != "lifecycle" or not factory.SHA.fullmatch(a.base)
            or factory.git(a.repo, "rev-parse", "HEAD") != a.base):
        raise ValueError("Trusted exact main lifecycle task required")
    artifacts = []
    result = shadow.evaluate(a.binary.resolve(strict=True), a.repo.resolve(strict=True),
                             a.base, a.dependencies.resolve(strict=True), a.role,
                             trial.COMPACT_CONTEXT, selected_artifacts=artifacts)
    print(json.dumps(result, sort_keys=True), flush=True)
    export(a.repo, a.role, a.base, result, artifacts, a.evidence)


if __name__ == "__main__":
    main()
