"""Synthetic authorization, workflow and fail-closed evidence contracts (NO QEMU)."""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from auto_tests.tools.observer_gpt_qemu_one_shot import (
    ACTOR,
    AUDITED,
    FILE,
    REF,
    REPO,
    SAFETY,
    Refused,
    expected_approval,
    validate_git,
    validate_trigger,
    verify_evidence,
)

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github/workflows/observer-gpt-qemu-one-shot.yml"


@pytest.fixture
def authorized():
    before = "a" * 40
    after = "b" * 40
    event = {
        "ref": REF,
        "repository": {"full_name": REPO},
        "created": False,
        "deleted": False,
        "forced": False,
        "before": before,
        "after": after,
        "commits": [
            {
                "id": after,
                "added": [FILE],
                "modified": [],
                "removed": [],
            }
        ],
        "head_commit": {"id": after},
    }
    env = {
        "GITHUB_ACTOR": ACTOR,
        "GITHUB_REPOSITORY": REPO,
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
    }
    return event, expected_approval(), env


def test_one_explicit_addition_passes_pure_gate(authorized):
    event, approval, env = authorized
    assert validate_trigger(event, approval, env) is None
    assert approval["approvedCodeSha"] == AUDITED
    assert approval["safetySourceSha"] == SAFETY
    assert approval["productionInstallationAuthorized"] is False


@pytest.mark.parametrize(
    ("where", "field", "value"),
    [
        ("env", "GITHUB_ACTOR", "someone-else"),
        ("env", "GITHUB_REPOSITORY", "other/repo"),
        ("env", "GITHUB_RUN_ATTEMPT", "2"),
        ("env", "RUNNER_ENVIRONMENT", "self-hosted"),
        ("event", "ref", "refs/heads/main"),
        ("event", "created", True),
        ("event", "forced", True),
        ("event", "deleted", True),
        ("event", "before", "0" * 40),
        ("event", "after", "0" * 40),
        ("approval", "approvedCodeSha", "f" * 40),
        ("approval", "safetySourceSha", "f" * 40),
        ("approval", "humanApproved", False),
        ("approval", "singleRun", False),
        ("approval", "diskWritesAuthorized", True),
        ("approval", "inputAuthorized", True),
        ("approval", "productionInstallationAuthorized", True),
        ("approval", "productionWriteAuthorized", True),
    ],
)
def test_denies_unsafe_explicit_authorization(authorized, where, field, value):
    event, approval, env = copy.deepcopy(authorized)
    {"env": env, "event": event, "approval": approval}[where][field] = value
    with pytest.raises(Refused):
        validate_trigger(event, approval, env)


@pytest.mark.parametrize(
    "change",
    [
        "missing-commit",
        "extra-commit",
        "modified-file",
        "wrong-added-file",
        "removed-file",
        "wrong-event-repository",
        "mismatching-head",
    ],
)
def test_denies_nonexclusive_authorization_commit(authorized, change):
    event, approval, env = copy.deepcopy(authorized)
    if change == "missing-commit":
        event["commits"] = []
    elif change == "extra-commit":
        event["commits"].append(copy.deepcopy(event["commits"][0]))
    elif change == "modified-file":
        event["commits"][0]["modified"] = [FILE]
    elif change == "wrong-added-file":
        event["commits"][0]["added"] = ["auto_tests/installer_observer/gpt_lab_provenance.py"]
    elif change == "removed-file":
        event["commits"][0]["removed"] = ["some-file"]
    elif change == "wrong-event-repository":
        event["repository"]["full_name"] = "someone/fork"
    elif change == "mismatching-head":
        event["head_commit"]["id"] = "c" * 40
    with pytest.raises(Refused):
        validate_trigger(event, approval, env)


def test_untrusted_qemu_workflow_is_hard_disabled():
    workflow = yaml.load(WORKFLOW_PATH.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert set(workflow["jobs"]) == {"qemu-disabled"}
    job = workflow["jobs"]["qemu-disabled"]
    assert job["if"] == "${{ false }}"
    assert job["runs-on"] == "ubuntu-24.04"
    assert all("uses" not in step for step in job["steps"])
    for step in job["steps"]:
        command = step["run"]
        assert "qemu-system-" not in command
        assert "guestfs" not in command
        assert "exit 1" in command
        subprocess.run(["bash", "-n"], input=command, text=True, check=True)


def test_evidence_verifier_fails_closed_when_not_a_completed_real_run(tmp_path):
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "status": "LABORATORY_ONLY",
                "classification": "NOT_INDEPENDENT",
                "safetyAssessment": "DIAGNOSTIC_ONLY",
                "sourceCommitSafety": SAFETY,
                "diskSynthetic": True,
                "windowsGenuine": False,
                "diskWritesAuthorized": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "safety-gpt-provenance-v1.json").write_text(
        json.dumps({"writeAuthorized": False}),
        encoding="utf-8",
    )
    with pytest.raises(Refused, match="FORBIDDEN_AUTHORIZATION"):
        verify_evidence(tmp_path)


@pytest.fixture
def authorization_git_repo(tmp_path):
    """Create a disposable local git history, never a remote authorization branch."""

    root = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    for key, value in (
        ("user.email", "synthetic-gpt@example.invalid"),
        ("user.name", "Synthetic GPT Test"),
    ):
        subprocess.run(["git", "-C", str(root), "config", key, value], check=True)

    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()

    (root / "README").write_text("Synthetic only\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "README"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "synthetic base"], check=True)
    before = git("rev-parse", "HEAD")
    return root, before


def test_git_preflight_accepts_one_real_added_approval_file(authorization_git_repo):
    root, before = authorization_git_repo
    approval = root / FILE
    approval.parent.mkdir(parents=True)
    approval.write_text(json.dumps(expected_approval()), encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", FILE], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "synthetic authorization"], check=True)
    after = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    assert (
        validate_git(
            root,
            {"before": before, "after": after},
            trusted_preparation_sha=before,
            trusted_authorization_sha=after,
            unused_external_grant=True,
        )
        is None
    )


@pytest.mark.parametrize("extra_file", ["README", "other.json"])
def test_git_preflight_refuses_authorization_with_other_diff(
    authorization_git_repo,
    extra_file,
):
    root, before = authorization_git_repo
    approval = root / FILE
    approval.parent.mkdir(parents=True)
    approval.write_text(json.dumps(expected_approval()), encoding="utf-8")
    (root / extra_file).write_text("Extra change\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "invalid multi-file push"], check=True)
    after = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    with pytest.raises(Refused, match="GIT_DIFF_NOT_EXCLUSIVE_APPROVAL"):
        validate_git(
            root,
            {"before": before, "after": after},
            trusted_preparation_sha=before,
            trusted_authorization_sha=after,
            unused_external_grant=True,
        )


def test_git_preflight_refuses_forged_previous_sha(authorization_git_repo):
    root, before = authorization_git_repo
    approval = root / FILE
    approval.parent.mkdir(parents=True)
    approval.write_text(json.dumps(expected_approval()), encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", FILE], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "synthetic authorization"], check=True)
    after = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    with pytest.raises(Refused, match="UNAPPROVED_PREPARATION_PARENT"):
        validate_git(
            root,
            {"before": "a" * 40, "after": after},
            trusted_preparation_sha=before,
            trusted_authorization_sha=after,
            unused_external_grant=True,
        )


def _git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *arguments], text=True).strip()


def _commit_synthetic(root: Path, message: str, changes: dict[str, str]) -> str:
    for name, content in changes.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", name], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", message], check=True)
    return _git(root, "rev-parse", "HEAD")


@pytest.mark.parametrize("tamper", ("workflow", "preflight", "both"))
def test_unreviewed_intermediate_ancestor_is_denied(authorization_git_repo, authorized, tamper):
    """Same three real-Git histories reproduced by Safety (NO QEMU)."""
    root, _ = authorization_git_repo
    approved = _commit_synthetic(root, "reviewed preparation", {"README": "Reviewed\n"})
    workflow = ".github/workflows/observer-gpt-qemu-one-shot.yml"
    gate = "auto_tests/tools/observer_gpt_qemu_one_shot.py"
    files = {}
    if tamper in ("workflow", "both"):
        files[workflow] = "name: unreviewed unsafe workflow\n"
    if tamper in ("preflight", "both"):
        files[gate] = "print('unreviewed gate')\n"
    attacker_parent = _commit_synthetic(root, "unreviewed insertion", files)
    after = _commit_synthetic(root, "approval file only", {FILE: json.dumps(expected_approval())})
    event, approval, env = copy.deepcopy(authorized)
    event["before"] = attacker_parent
    event["after"] = after
    event["head_commit"]["id"] = after
    event["commits"][0]["id"] = after
    assert validate_trigger(event, approval, env) is None
    # The final commit changes ONLY the JSON, just like Safety's 3/3 bypass.
    assert _git(root, "diff-tree", "--no-commit-id", "--name-status", "-r", after) == ("A\t" + FILE)
    with pytest.raises(Refused, match="UNAPPROVED_PREPARATION_PARENT"):
        validate_git(
            root,
            event,
            trusted_preparation_sha=approved,
            trusted_authorization_sha=after,
            unused_external_grant=True,
        )


def test_absent_external_parent_and_lease_fail_closed(authorization_git_repo):
    root, parent = authorization_git_repo
    after = _commit_synthetic(root, "approval", {FILE: json.dumps(expected_approval())})
    event = {"before": parent, "after": after}
    with pytest.raises(Refused, match="TRUSTED_PREPARATION_MISSING"):
        validate_git(root, event)
    with pytest.raises(Refused, match="TRUSTED_AUTHORIZATION_COMMIT_MISSING"):
        validate_git(root, event, trusted_preparation_sha=parent)
    with pytest.raises(Refused, match="EXTERNAL_SINGLE_USE_GRANT_MISSING_OR_CONSUMED"):
        validate_git(
            root,
            event,
            trusted_preparation_sha=parent,
            trusted_authorization_sha=after,
        )


def test_untrusted_json_cannot_self_certify_preparation(authorized, authorization_git_repo):
    event, approval, env = copy.deepcopy(authorized)
    approval["approvedPreparationSha"] = "a" * 40
    with pytest.raises(Refused, match="APPROVAL_CONTENT_INVALID"):
        validate_trigger(event, approval, env)
    root, parent = authorization_git_repo
    after = _commit_synthetic(root, "approval", {FILE: json.dumps(approval)})
    with pytest.raises(Refused, match="TRUSTED_PREPARATION_MISSING"):
        validate_git(root, {"before": parent, "after": after})


def test_reused_authorization_is_denied_without_external_grant(authorization_git_repo):
    root, parent = authorization_git_repo
    after = _commit_synthetic(root, "approval", {FILE: json.dumps(expected_approval())})
    with pytest.raises(Refused, match="EXTERNAL_SINGLE_USE_GRANT_MISSING_OR_CONSUMED"):
        validate_git(
            root,
            {"before": parent, "after": after},
            trusted_preparation_sha=parent,
            trusted_authorization_sha=after,
            unused_external_grant=False,
        )


def test_authorization_commit_must_match_protected_pin(authorization_git_repo):
    root, parent = authorization_git_repo
    after = _commit_synthetic(root, "approval", {FILE: json.dumps(expected_approval())})
    with pytest.raises(Refused, match="UNAPPROVED_AUTHORIZATION_COMMIT"):
        validate_git(
            root,
            {"before": parent, "after": after},
            trusted_preparation_sha=parent,
            trusted_authorization_sha="f" * 40,
            unused_external_grant=True,
        )


def test_forged_event_before_cannot_hide_unreviewed_real_git_parent(
    authorization_git_repo,
):
    root, _ = authorization_git_repo
    reviewed = _commit_synthetic(root, "reviewed", {"README": "Reviewed\n"})
    _commit_synthetic(root, "unreviewed", {"untrusted.txt": "modify workflow later\n"})
    after = _commit_synthetic(root, "authorization", {FILE: json.dumps(expected_approval())})
    # The event lies about the previous SHA; git HEAD^ exposes actual parent.
    with pytest.raises(Refused, match="UNEXPECTED_PARENT_COMMIT"):
        validate_git(
            root,
            {"before": reviewed, "after": after},
            trusted_preparation_sha=reviewed,
            trusted_authorization_sha=after,
            unused_external_grant=True,
        )


def test_protected_main_controller_template_is_not_an_executable_workflow():
    template = ROOT / "docs/INSTALLER_OBSERVER_GPT_PROTECTED_CONTROLLER.template.yml"
    assert template.is_file()
    assert not str(template.relative_to(ROOT)).startswith(".github/workflows/")
    config = yaml.load(template.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert set(config["on"]) == {"workflow_dispatch"}
    assert config["jobs"]["protected-gpt-readonly"]["if"] == "${{ false }}"
    job = config["jobs"]["protected-gpt-readonly"]
    assert job["environment"] == "gaslux-gpt-qemu-human-reviewed"
    assert job["runs-on"] == "ubuntu-24.04"
    assert all("qemu" not in step.get("run", "").lower() for step in job["steps"])


def test_branch_cli_rejects_even_valid_untrusted_request_without_trusted_controller(
    authorized, authorization_git_repo, tmp_path
):
    import sys

    root, before = authorization_git_repo
    after = _commit_synthetic(root, "approval", {FILE: json.dumps(expected_approval())})
    event, _, env = copy.deepcopy(authorized)
    event["before"] = before
    event["after"] = after
    event["head_commit"]["id"] = after
    event["commits"][0]["id"] = after
    request = tmp_path / "event.json"
    request.write_text(json.dumps(event), encoding="utf-8")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "auto_tests.tools.observer_gpt_qemu_one_shot",
            "preflight",
            "--checkout",
            str(root),
            "--evidence",
            str(evidence),
        ],
        text=True,
        capture_output=True,
        check=False,
        env={**__import__("os").environ, **env, "GITHUB_EVENT_PATH": str(request)},
    )
    assert process.returncode == 2
    assert "TRUSTED_PREPARATION_MISSING" in process.stderr
    assert not (evidence / "authorization-intent.json").exists()
