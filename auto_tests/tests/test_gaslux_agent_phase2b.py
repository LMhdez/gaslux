"""Phase 2B: reviewed source-pin code scope, independent AST/behavior contract."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "tools/gaslux_agent_feature_factory.py"
SPEC = importlib.util.spec_from_file_location("gaslux_phase2b_factory", SCRIPT)
assert SPEC and SPEC.loader
factory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(factory)


def accepted() -> str:
    return (
        "def match_mint_223_iso_descriptor(candidate: dict) -> dict:\n"
        "    matched = isinstance(candidate, dict) and "
        "candidate.get('id') == 'mint' and "
        "candidate.get('isoInstaller') == "
        "'https://pub.linuxmint.io/stable/22.3/linuxmint-22.3-cinnamon-64bit.iso' "
        "and candidate.get('isoInstallerSha256') == "
        "'a081ab202cfda17f6924128dbd2de8b63518ac0531bcfe3f1a1b88097c459bd4' "
        "and candidate.get('isoInstallerSizeBytes') == 3091660800\n"
        "    return {'backend': 'mint', 'pinnedDescriptorMatches': matched, "
        "'sourceAuthenticityVerified': False, 'installationAuthorized': False, "
        "'releaseEligible': False}\n"
    )


def fixture_repo(root: Path) -> None:
    source = root / factory.SCOPE2B_TARGET
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("# Original read-only product source\n", encoding="utf-8")
    (root / "release-config.json").write_text(json.dumps({
        "distributions": [dict(factory.SCOPE2B_PINS)],
    }), encoding="utf-8")


def issue_row(*, author: str = "github-actions[bot]", number: int = 404) -> dict:
    return {
        "number": number,
        "state": "open",
        "repository_url": "https://api.github.com/repos/LMhdez/gaslux",
        "user": {"login": author, "type": "Bot", "id": 41898282},
        "title": "[GASLUX-AUTO] mint / windows10-bios-mbr / source-authenticity: scope & acceptance",
        "body": (
            "<!-- GASLUX-AUTOTASK:mint:windows10-bios-mbr:source-authenticity -->\n"
            "NEEDS_SCOPE_REVIEW"
        ),
    }


class Scope2BTests(unittest.TestCase):
    def test_pins_match_existing_signed_release_descriptor_without_attestation(self):
        main = SCRIPT.parents[2]
        release = json.loads((main / "release-config.json").read_text())
        mint = next(x for x in release["distributions"] if x["id"] == "mint")
        for key, pinned in factory.SCOPE2B_PINS.items():
            self.assertEqual(mint[key], pinned)
            self.assertIs(type(mint[key]), type(pinned))
        self.assertEqual(factory.SCOPE2B_ISSUE, 404)
        self.assertEqual(factory.SCOPE2B_GATE, "source-authenticity")

    def test_model_code_matches_full_mint_descriptor_but_never_attests_source(self):
        factory.validate_addition(
            "mint", accepted(), execute=True, scope=factory.SCOPE2B_ID
        )
        self.assertFalse("sourceAuthenticityVerified': True" in accepted())
        self.assertFalse("installationAuthorized': True" in accepted())

    def test_wrong_backend_unknown_scope_and_synthetic_authority_rejected(self):
        for role, scope in [
            ("zorin", factory.SCOPE2B_ID),
            ("mint", "unknown"),
        ]:
            with self.subTest(role=role, scope=scope), self.assertRaises(ValueError):
                factory.validate_addition(role, accepted(), execute=True, scope=scope)
        wrong = accepted().replace("'sourceAuthenticityVerified': False",
                                   "'sourceAuthenticityVerified': True")
        with self.assertRaises(ValueError):
            factory.validate_addition("mint", wrong, execute=True,
                                      scope=factory.SCOPE2B_ID)

    def test_ast_side_effects_and_false_positive_candidate_rejected(self):
        bad = [
            accepted().replace("    matched =", "    open('/tmp/pwn', 'w')\n    matched ="),
            "import os\n" + accepted(),
            accepted().replace("    matched =", "    candidate['id'] = 'mint'\n    matched ="),
            accepted().replace("    matched =", "    for _ in (): pass\n    matched ="),
            accepted().replace("candidate.get('isoInstallerSha256') == ",
                               "candidate.get('isoInstallerSha256') != "),
            accepted().replace("candidate.get('isoInstallerSizeBytes') == 3091660800",
                               "True"),
            accepted().replace("'pinnedDescriptorMatches': matched",
                               "'pinnedDescriptorMatches': True"),
            accepted().replace("'sourceAuthenticityVerified': False",
                               "'sourceAuthenticityVerified': (candidate == {})"),
            accepted().replace("'installationAuthorized': False",
                               "'installationAuthorized': (candidate.get('hidden') is True)"),
        ]
        for item in bad:
            with self.subTest(item=item[:90]), self.assertRaises((SyntaxError, ValueError)):
                factory.validate_addition(
                    "mint", item, execute=True, scope=factory.SCOPE2B_ID
                )

    def test_pinned_issue_authenticated_before_selecting_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture_repo(root)
            calls = []
            def subprocess_stub(args, **kwargs):
                calls.append(args)
                if "/issues/404" in args[-1]:
                    return SimpleNamespace(returncode=0, stdout=json.dumps(issue_row()), stderr="")
                return SimpleNamespace(returncode=1, stdout="", stderr="HTTP 404 Not Found")
            with patch.object(factory.subprocess, "run", side_effect=subprocess_stub):
                self.assertTrue(factory.scope2b_eligible(root, "a" * 40))
            self.assertEqual(len(calls), 2)
            self.assertEqual(factory.scope2b_branch("a"*40),
                             "bot/gaslux-scope2b-mint-pins-aaaaaaaaaaaa")

    def test_issue_spoof_drift_and_existing_branch_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture_repo(root)
            for bad in [
                issue_row(author="foreign-user"),
                issue_row(number=900),
                dict(issue_row(), state="closed"),
                dict(issue_row(), title="Mint icon design"),
            ]:
                with self.subTest(bad=bad):
                    fake = SimpleNamespace(returncode=0, stdout=json.dumps(bad), stderr="")
                    with patch.object(factory.subprocess, "run", return_value=fake):
                        with self.assertRaises(ValueError):
                            factory.scope2b_eligible(root, "a" * 40)
            (root / "release-config.json").write_text(json.dumps({
                "distributions": [{"id": "mint", "isoInstaller": "https://tampered.example"}]
            }))
            with self.assertRaises(ValueError):
                factory.scope2b_eligible(root, "a" * 40)
            fixture_repo(root)
            fake = SimpleNamespace(returncode=1, stdout="", stderr="403 Forbidden")
            with patch.object(factory.subprocess, "run", return_value=fake):
                with self.assertRaises(RuntimeError):
                    factory.scope2b_eligible(root, "a" * 40)
            fake_issue = SimpleNamespace(returncode=0, stdout=json.dumps(issue_row()), stderr="")
            with patch.object(factory.subprocess, "run",
                              side_effect=[fake_issue, SimpleNamespace(returncode=0, stdout="{}", stderr="")]):
                self.assertFalse(factory.scope2b_eligible(root, "a" * 40))

    def test_model_artifact_bound_to_scope_gate_and_source_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture_repo(root)
            evidence = root / "evidence"
            base = "b" * 40
            with patch.object(factory, "git", return_value=base), \
                 patch.object(factory, "call_model", return_value=accepted()) as model:
                factory.generate(root, evidence, "mint", base, scope=factory.SCOPE2B_ID)
                report = factory.verify(root, evidence, "mint", base,
                                        execute=True, scope=factory.SCOPE2B_ID)
                self.assertEqual(report["scope"], factory.SCOPE2B_ID)
                self.assertEqual(report["issue"], 404)
                self.assertIn("Mint 22.3", model.call_args.args[0])
                for key, bad in [
                    ("issue", 405), ("gate", "install"),
                    ("platform", "windows11-uefi-gpt"),
                    ("model_digest", "0" * 64),
                    ("source_sha256", "0" * 64),
                ]:
                    original = json.loads((evidence / "report.json").read_text())
                    original[key] = bad
                    (evidence / "report.json").write_text(json.dumps(original))
                    with self.subTest(key=key), self.assertRaises(ValueError):
                        factory.verify(root, evidence, "mint", base,
                                       execute=False, scope=factory.SCOPE2B_ID)
                    original[key] = report[key]
                    (evidence / "report.json").write_text(json.dumps(original))
                with self.assertRaises(ValueError):
                    factory.verify(root, evidence, "mint", "c" * 40,
                                   execute=False, scope=factory.SCOPE2B_ID)

    def test_existing_lifecycle_scope_stays_separate(self):
        with self.assertRaises(ValueError):
            factory.validate_addition("mint", accepted(), execute=True)
        self.assertEqual(factory.origin_branch("mint", "a"*40),
                         "bot/gaslux-feature-mint-aaaaaaaaaaaa")

    def test_workflow_reuses_separate_model_safety_publisher_gates(self):
        workflow = (SCRIPT.parents[2] /
                    ".github/workflows/gaslux-agent-feature-factory.yml").read_text()
        self.assertNotIn("pull_request_target:", workflow)
        self.assertEqual(workflow.count("SCOPE: ${{ needs.select.outputs.scope }}"), 3)
        self.assertIn("      scope: ${{ steps.plan.outputs.scope }}", workflow)
        self.assertIn("out.write('scope='", workflow)
        self.assertEqual(workflow.count('--scope "$SCOPE"'), 4)
        self.assertIn("    environment: gaslux-main-publisher", workflow)
        before, publisher = workflow.split("  publish_draft:\n", 1)
        self.assertNotIn("GASLUX_PUBLISH_APP_PRIVATE_KEY", before)
        self.assertIn("github.ref == 'refs/heads/main'", publisher)
        for path in [
            "auto_tests/tools/gaslux_agent_feature_factory.py",
            "auto_tests/tests/test_gaslux_agent_phase2b.py",
        ]:
            self.assertIn(path, workflow)


if __name__ == "__main__":
    unittest.main()
