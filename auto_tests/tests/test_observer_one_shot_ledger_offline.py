"""Adversarial offline one-shot state/transaction tests; never start a VM."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
FILE = ROOT / "auto_tests/tools/observer_one_shot_ledger_offline.py"
FIXTURE = ROOT / "auto_tests/fixtures/observer-one-shot/valid-grant.json"
SCHEMA = ROOT / "schemas/observer-one-shot-grant-v2.schema.json"
spec = importlib.util.spec_from_file_location("observer_one_shot_ledger_offline", FILE)
assert spec is not None and spec.loader is not None

model = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = model
spec.loader.exec_module(model)

NOW = "2026-11-21T13:00:00Z"


def grant_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def trusted_fixture(g: dict):
    return model.TrustedDecisionFixture(
        repository=g["repository"],
        experiment_id=g["experimentId"],
        preparation_sha=g["preparationSha"],
        authorization_sha=g["authorizationSha"],
        protected_controller_sha=g["protectedControllerSha"],
        audited_code_sha=g["auditedCodeSha"],
        requester_id=g["requesterId"],
        approver_id=g["externalApproverId"],
        human_review_id=g["humanReviewId"],
        external_decision_id=g["externalDecisionId"],
        review_verified=True,
        authority_available=True,
    )


def run_fixture(g: dict):
    return model.RunObservationFixture(
        repository=g["repository"],
        experiment_id=g["experimentId"],
        request_ref=g["requestRef"],
        preparation_sha=g["preparationSha"],
        authorization_sha=g["authorizationSha"],
        protected_controller_sha=g["protectedControllerSha"],
        audited_code_sha=g["auditedCodeSha"],
        run_id="run-fixture-1",
    )


def git(path: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()


class GrantSchemaTests(unittest.TestCase):
    def test_offline_schema_is_versioned_and_strict(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(grant_fixture())
        self.assertFalse(schema["additionalProperties"])

    def test_invalid_grants_fail_closed(self):
        for field, value in (
            ("scope", "INSTALL"),
            ("contractVersion", 3),
            ("preparationSha", "short"),
            ("externalApproverId", ""),
            ("repository", "other/repository"),
        ):
            with self.subTest(field=field):
                g = grant_fixture()
                g[field] = value
                with self.assertRaisesRegex(model.Refused, "GRANT_SCHEMA_INVALID"):
                    model._check_grant(g)
        g = grant_fixture()
        g["humanApproved"] = True
        with self.assertRaisesRegex(model.Refused, "GRANT_SCHEMA_INVALID"):
            model._check_grant(g)

    def test_self_approval_and_bad_window_refused(self):
        g = grant_fixture()
        g["externalApproverId"] = g["requesterId"].upper()
        with self.assertRaisesRegex(model.Refused, "SELF_APPROVAL"):
            model._check_grant(g)
        g = grant_fixture()
        g["expiresAt"] = g["issuedAt"]
        with self.assertRaisesRegex(model.Refused, "INVALID_GRANT_WINDOW"):
            model._check_grant(g)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gaslux-offline-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "ledger.sqlite3"
        self.ledger = model.OfflineLedger(self.path)
        self.g = grant_fixture()
        self.trusted = trusted_fixture(self.g)
        self.run = run_fixture(self.g)

    def ready(self):
        self.ledger.request(self.g, now=NOW)
        self.ledger.transition(self.g["grantId"], "REVIEW_PENDING", now=NOW)
        self.ledger.transition(self.g["grantId"], "APPROVED", now=NOW, trusted=self.trusted)

    def attempt(self, reason, *, trusted=None, run=None, now=NOW):
        with self.assertRaises(model.Refused) as error:
            self.ledger.transition(
                self.g["grantId"],
                "CONSUMED",
                now=now,
                trusted=self.trusted if trusted is None else trusted,
                run=self.run if run is None else run,
            )
        self.assertEqual(error.exception.reason, reason)

    def test_full_fsm_durable_one_shot_and_replay(self):
        self.ready()
        self.assertEqual(
            self.ledger.transition(
                self.g["grantId"], "CONSUMED", now=NOW, trusted=self.trusted, run=self.run
            ),
            "CONSUMED",
        )
        self.assertEqual(model.OfflineLedger(self.path).state(self.g["grantId"]), "CONSUMED")
        self.attempt("INVALID_STATE_TRANSITION")
        self.assertEqual(
            self.ledger.events(self.g["grantId"])[-1][2:4], ("DENIED", "INVALID_STATE_TRANSITION")
        )

    def test_duplicate_grant_refused_and_recorded(self):
        self.ledger.request(self.g, now=NOW)
        with self.assertRaisesRegex(model.Refused, "GRANT_ID_REUSED"):
            self.ledger.request(copy.deepcopy(self.g), now=NOW)
        self.assertEqual(self.ledger.events(self.g["grantId"])[-1][3], "GRANT_ID_REUSED")

    def test_p01_distinct_uuids_cannot_reserve_or_consume_same_authorization(self):
        """P-01: grantId is NOT the authorization identity; terminal reuse prohibited."""
        first = copy.deepcopy(self.g)
        second = copy.deepcopy(self.g)
        second["grantId"] = "8c123456-1bb1-4bab-9abc-111111111111"
        assert first["grantId"] != second["grantId"]
        self.ledger.request(first, now=NOW)
        self.ledger.transition(first["grantId"], "REVIEW_PENDING", now=NOW)
        self.ledger.transition(first["grantId"], "APPROVED", now=NOW, trusted=self.trusted)
        self.assertEqual(
            self.ledger.transition(
                first["grantId"], "CONSUMED", now=NOW, trusted=self.trusted, run=self.run
            ),
            "CONSUMED",
        )
        with self.assertRaisesRegex(model.Refused, "AUTHORIZATION_ALREADY_RESERVED"):
            self.ledger.request(second, now=NOW)
        self.assertEqual(self.ledger.state(first["grantId"]), "CONSUMED")
        with self.assertRaisesRegex(model.Refused, "UNKNOWN_GRANT"):
            self.ledger.state(second["grantId"])

    def test_second_uuid_same_external_decision_after_revocation_is_denied(self):
        self.ledger.request(self.g, now=NOW)
        self.ledger.transition(self.g["grantId"], "REVOKED", now=NOW)
        second = copy.deepcopy(self.g)
        second["grantId"] = str(uuid.uuid4())
        with self.assertRaisesRegex(model.Refused, "AUTHORIZATION_ALREADY_RESERVED"):
            self.ledger.request(second, now=NOW)
        self.assertEqual(self.ledger.state(self.g["grantId"]), "REVOKED")
        self.assertIn(
            ("DENIED", "AUTHORIZATION_ALREADY_RESERVED"),
            [event[2:4] for event in self.ledger.events(second["grantId"])],
        )

    def test_authorization_cannot_reuse_commit_with_different_review(self):
        self.ledger.request(self.g, now=NOW)
        second = copy.deepcopy(self.g)
        second["grantId"] = str(uuid.uuid4())
        second["externalDecisionId"] = str(uuid.uuid4())
        second["humanReviewId"] = "new-review-synthetic-20261121"
        with self.assertRaisesRegex(model.Refused, "AUTHORIZATION_ALREADY_RESERVED"):
            self.ledger.request(second, now=NOW)

    def test_experiment_commit_cannot_rotate_branch_name(self):
        self.ledger.request(self.g, now=NOW)
        second = copy.deepcopy(self.g)
        second["grantId"] = str(uuid.uuid4())
        second["requestRef"] = "refs/heads/qemu-approved/another-ref"
        second["externalDecisionId"] = str(uuid.uuid4())
        second["humanReviewId"] = "different-review-synthetic"
        with self.assertRaisesRegex(model.Refused, "EXPERIMENT_COMMIT_ALREADY_RESERVED"):
            self.ledger.request(second, now=NOW)

    def test_external_decision_cannot_reapprove_another_commit(self):
        self.ledger.request(self.g, now=NOW)
        second = copy.deepcopy(self.g)
        second["grantId"] = str(uuid.uuid4())
        second["authorizationSha"] = "e" * 40
        second["humanReviewId"] = "different-review-for-other-commit"
        with self.assertRaisesRegex(model.Refused, "EXTERNAL_DECISION_ALREADY_RESERVED"):
            self.ledger.request(second, now=NOW)

    def test_one_human_review_cannot_rotate_external_decision_id(self):
        self.ledger.request(self.g, now=NOW)
        second = copy.deepcopy(self.g)
        second["grantId"] = str(uuid.uuid4())
        second["authorizationSha"] = "e" * 40
        second["externalDecisionId"] = str(uuid.uuid4())
        with self.assertRaisesRegex(model.Refused, "HUMAN_REVIEW_ALREADY_RESERVED"):
            self.ledger.request(second, now=NOW)

    def test_two_genuinely_distinct_simulated_decisions_do_not_collide(self):
        self.ledger.request(self.g, now=NOW)
        second = copy.deepcopy(self.g)
        second["grantId"] = str(uuid.uuid4())
        second["authorizationSha"] = "e" * 40
        second["externalDecisionId"] = str(uuid.uuid4())
        second["humanReviewId"] = "separate-human-review"
        self.ledger.request(second, now=NOW)
        for grant in (self.g, second):
            self.ledger.transition(grant["grantId"], "REVIEW_PENDING", now=NOW)
            self.assertEqual(
                self.ledger.transition(
                    grant["grantId"],
                    "APPROVED",
                    now=NOW,
                    trusted=trusted_fixture(grant),
                ),
                "APPROVED",
            )
        self.assertEqual(self.ledger.state(second["grantId"]), "APPROVED")

    def test_eight_parallel_equivalent_reservations_only_one_wins(self):
        barrier = threading.Barrier(8)
        records = []
        for index in range(8):
            g = copy.deepcopy(self.g)
            g["grantId"] = str(uuid.uuid4())
            g["externalDecisionId"] = str(uuid.uuid4())
            g["humanReviewId"] = f"parallel-review-{index}"
            records.append(g)

        def reserve(grant):
            barrier.wait()
            try:
                self.ledger.request(grant, now=NOW)
                return "RESERVED"
            except model.Refused as exc:
                return exc.reason

        with ThreadPoolExecutor(max_workers=8) as pool:
            observed = list(pool.map(reserve, records))
        self.assertEqual(observed.count("RESERVED"), 1)
        self.assertEqual(observed.count("AUTHORIZATION_ALREADY_RESERVED"), 7)
        self.assertEqual(sum(len(self.ledger.events(g["grantId"])) for g in records), 8)
        self.assertEqual(
            sum(
                self.ledger.state(g["grantId"]) == "REQUESTED"
                for g, status in zip(records, observed, strict=True)
                if status == "RESERVED"
            ),
            1,
        )

    def test_direct_sql_insert_cannot_bypass_any_unique_reservation_key(self):
        self.ledger.request(self.g, now=NOW)
        columns = (
            "grant_id",
            "authorization_key",
            "execution_key",
            "commit_key",
            "external_decision_id",
            "review_key",
        )
        with sqlite3.connect(self.path) as con:
            existing = dict(
                zip(
                    columns,
                    con.execute(
                        "SELECT grant_id, authorization_key, execution_key, "
                        "commit_key, external_decision_id, review_key FROM grants"
                    ).fetchone(),
                    strict=True,
                )
            )
            for collided in columns:
                with self.subTest(index=collided):
                    other = {key: str(uuid.uuid4()) for key in columns}
                    other[collided] = existing[collided]
                    with self.assertRaises(sqlite3.IntegrityError):
                        con.execute(
                            "INSERT INTO grants (grant_id, authorization_key, "
                            "execution_key, commit_key, external_decision_id, review_key, "
                            "payload, digest, state, created_at) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                *(other[key] for key in columns),
                                "{}",
                                "0" * 64,
                                "REQUESTED",
                                NOW,
                            ),
                        )
            self.assertEqual(con.execute("SELECT COUNT(*) FROM grants").fetchone()[0], 1)

    def test_expiry_preserves_reservation_and_refusal_events(self):
        self.ledger.request(self.g, now=NOW)
        self.ledger.transition(self.g["grantId"], "REVIEW_PENDING", now=NOW)
        with self.assertRaisesRegex(model.Refused, "GRANT_EXPIRED"):
            self.ledger.transition(
                self.g["grantId"],
                "APPROVED",
                now="2026-11-22T12:00:00Z",
                trusted=self.trusted,
            )
        self.assertEqual(self.ledger.state(self.g["grantId"]), "EXPIRED")
        alt = copy.deepcopy(self.g)
        alt["grantId"] = str(uuid.uuid4())
        with self.assertRaisesRegex(model.Refused, "AUTHORIZATION_ALREADY_RESERVED"):
            self.ledger.request(alt, now=NOW)

    def test_interrupted_before_commit_does_not_reserve(self):
        g = self.g
        keys = model._identities(g)
        con = sqlite3.connect(self.path, isolation_level=None)
        try:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                "INSERT INTO grants (grant_id, authorization_key, execution_key, "
                "commit_key, external_decision_id, review_key, payload, digest, state, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    g["grantId"],
                    keys[0],
                    keys[1],
                    model._commit_key(g),
                    g["externalDecisionId"],
                    keys[2],
                    "{}",
                    "0" * 64,
                    "REQUESTED",
                    NOW,
                ),
            )
            con.execute("ROLLBACK")
        finally:
            con.close()
        self.ledger.request(g, now=NOW)
        self.assertEqual(self.ledger.state(g["grantId"]), "REQUESTED")

    def test_reopen_after_consumption_still_denies_alternate_uuid(self):
        self.ready()
        self.ledger.transition(
            self.g["grantId"],
            "CONSUMED",
            now=NOW,
            trusted=self.trusted,
            run=self.run,
        )
        reopened = model.OfflineLedger(self.path)
        second = copy.deepcopy(self.g)
        second["grantId"] = str(uuid.uuid4())
        with self.assertRaisesRegex(model.Refused, "AUTHORIZATION_ALREADY_RESERVED"):
            reopened.request(second, now=NOW)

    def test_legacy_v1_database_refused_without_migration(self):
        old_file = Path(self.temp.name) / "legacy-v1.sqlite3"
        con = sqlite3.connect(old_file)
        try:
            con.execute(
                "CREATE TABLE grants (grant_id TEXT PRIMARY KEY, payload TEXT NOT NULL, "
                "digest TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL)"
            )
            con.execute(
                "CREATE TABLE decisions (sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
                "grant_id TEXT NOT NULL, at TEXT NOT NULL, before_state TEXT, "
                "after_state TEXT, decision TEXT NOT NULL, reason TEXT NOT NULL, "
                "run_id TEXT)"
            )
            con.commit()
        finally:
            con.close()
        with self.assertRaisesRegex(model.Refused, "LEGACY_OR_AMBIGUOUS_LEDGER"):
            model.OfflineLedger(old_file)
        con = sqlite3.connect(old_file)
        try:
            self.assertEqual(len(con.execute("PRAGMA table_info(grants)").fetchall()), 5)
        finally:
            con.close()

    def test_external_database_tamper_is_not_prevented(self):
        self.ready()
        with sqlite3.connect(self.path) as con:
            con.execute(
                "UPDATE grants SET state = 'CONSUMED' WHERE grant_id = ?",
                (self.g["grantId"],),
            )
        self.assertEqual(self.ledger.state(self.g["grantId"]), "CONSUMED")
        # SQL constraints cannot prevent a privileged offline DB rewrite.
        with sqlite3.connect(self.path) as con:
            con.execute(
                "UPDATE grants SET state = 'APPROVED' WHERE grant_id = ?",
                (self.g["grantId"],),
            )
        self.assertEqual(
            self.ledger.transition(
                self.g["grantId"],
                "CONSUMED",
                now=NOW,
                trusted=self.trusted,
                run=self.run,
            ),
            "CONSUMED",
        )

    def test_restoring_old_db_snapshot_defeats_local_consumption(self):
        self.ready()
        snapshot = Path(self.temp.name) / "prior-snapshot.sqlite3"
        shutil.copy2(self.path, snapshot)
        self.ledger.transition(
            self.g["grantId"],
            "CONSUMED",
            now=NOW,
            trusted=self.trusted,
            run=self.run,
        )
        shutil.copy2(snapshot, self.path)
        reopened = model.OfflineLedger(self.path)
        self.assertEqual(reopened.state(self.g["grantId"]), "APPROVED")
        self.assertEqual(
            reopened.transition(
                self.g["grantId"],
                "CONSUMED",
                now=NOW,
                trusted=self.trusted,
                run=self.run,
            ),
            "CONSUMED",
        )

    def test_caller_controlled_clock_is_not_an_external_time_authority(self):
        # A backwards caller-supplied clock can still request a new grant.
        g = copy.deepcopy(self.g)
        g["issuedAt"] = "2026-01-01T00:00:00Z"
        g["expiresAt"] = "2026-01-02T00:00:00Z"
        self.ledger.request(g, now="2026-01-01T12:00:00Z")
        self.assertEqual(self.ledger.state(g["grantId"]), "REQUESTED")

    def test_forged_approval_or_mismatched_pins(self):
        self.ledger.request(self.g, now=NOW)
        self.ledger.transition(self.g["grantId"], "REVIEW_PENDING", now=NOW)
        for altered in (
            replace(self.trusted, review_verified=False),
            replace(self.trusted, authority_available=False),
            replace(self.trusted, approver_id="forged-reviewer"),
            replace(self.trusted, preparation_sha="f" * 40),
            replace(self.trusted, protected_controller_sha="e" * 40),
            replace(self.trusted, audited_code_sha="e" * 40),
        ):
            with self.subTest(altered=altered), self.assertRaises(model.Refused):
                self.ledger.transition(self.g["grantId"], "APPROVED", now=NOW, trusted=altered)
        self.assertEqual(self.ledger.state(self.g["grantId"]), "REVIEW_PENDING")

    def test_approval_refused_without_external_review_or_authority(self):
        self.ledger.request(self.g, now=NOW)
        self.ledger.transition(self.g["grantId"], "REVIEW_PENDING", now=NOW)
        with self.assertRaisesRegex(model.Refused, "EXTERNAL_AUTHORITY_UNAVAILABLE"):
            self.ledger.transition(self.g["grantId"], "APPROVED", now=NOW)
        with self.assertRaisesRegex(model.Refused, "HUMAN_REVIEW_NOT_VERIFIED"):
            self.ledger.transition(
                self.g["grantId"],
                "APPROVED",
                now=NOW,
                trusted=replace(self.trusted, review_verified=False),
            )

    def test_consume_requires_current_external_authority_and_review(self):
        self.ready()
        self.attempt(
            "EXTERNAL_AUTHORITY_UNAVAILABLE",
            trusted=replace(self.trusted, authority_available=False),
        )
        self.attempt(
            "HUMAN_REVIEW_NOT_VERIFIED", trusted=replace(self.trusted, review_verified=False)
        )
        self.assertEqual(self.ledger.state(self.g["grantId"]), "APPROVED")

    def test_run_refuses_creation_recreation_force_rerun_and_writes(self):
        self.ready()
        cases = (
            ("BRANCH_CREATION_OR_RECREATION_REFUSED", replace(self.run, branch_created=True)),
            ("BRANCH_CREATION_OR_RECREATION_REFUSED", replace(self.run, branch_recreated=True)),
            ("BRANCH_CREATION_OR_RECREATION_REFUSED", replace(self.run, forced_update=True)),
            ("WORKFLOW_RERUN_REFUSED", replace(self.run, run_attempt=2)),
            ("WORKFLOW_RERUN_REFUSED", replace(self.run, run_attempt=True)),
            ("WRITER_OR_INSTALLATION_REFUSED", replace(self.run, scope="INSTALL")),
            ("WRITER_OR_INSTALLATION_REFUSED", replace(self.run, scope="DISK_WRITE")),
            ("UNAPPROVED_EXACT_COMMIT_OR_CONTEXT", replace(self.run, preparation_sha="f" * 40)),
            ("UNAPPROVED_EXACT_COMMIT_OR_CONTEXT", replace(self.run, authorization_sha="f" * 40)),
            (
                "UNAPPROVED_EXACT_COMMIT_OR_CONTEXT",
                replace(self.run, protected_controller_sha="f" * 40),
            ),
            ("UNAPPROVED_EXACT_COMMIT_OR_CONTEXT", replace(self.run, audited_code_sha="f" * 40)),
        )
        for reason, run in cases:
            with self.subTest(reason=reason, run=run):
                self.attempt(reason, run=run)
        self.assertEqual(self.ledger.state(self.g["grantId"]), "APPROVED")

    def test_revoked_and_expired_grants_refused(self):
        self.ready()
        self.ledger.transition(self.g["grantId"], "REVOKED", now=NOW)
        self.attempt("INVALID_STATE_TRANSITION")
        self.assertEqual(self.ledger.state(self.g["grantId"]), "REVOKED")
        self.g["grantId"] = "8f34961d-dcfe-4f8c-9f8e-d13a6b1c1111"
        self.g["authorizationSha"] = "e" * 40
        self.g["externalDecisionId"] = str(uuid.uuid4())
        self.g["humanReviewId"] = "separate-review-for-expiry"
        self.trusted = trusted_fixture(self.g)
        self.run = run_fixture(self.g)
        self.ready()
        self.attempt("GRANT_EXPIRED", now="2026-11-22T12:00:00Z")
        self.assertEqual(self.ledger.state(self.g["grantId"]), "EXPIRED")

    def test_refused_is_terminal(self):
        self.ledger.request(self.g, now=NOW)
        self.ledger.transition(self.g["grantId"], "REFUSED", now=NOW)
        with self.assertRaisesRegex(model.Refused, "INVALID_STATE_TRANSITION"):
            self.ledger.transition(self.g["grantId"], "REVIEW_PENDING", now=NOW)

    def test_two_consumers_and_thread_race_exactly_one_success(self):
        self.ready()
        barrier = threading.Barrier(8)

        def worker(index):
            local = model.OfflineLedger(self.path)
            barrier.wait(timeout=10)
            try:
                local.transition(
                    self.g["grantId"],
                    "CONSUMED",
                    now=NOW,
                    trusted=self.trusted,
                    run=replace(self.run, run_id=f"concurrent-{index}"),
                )
                return "CONSUMED"
            except model.Refused as exc:
                return exc.reason

        with ThreadPoolExecutor(max_workers=8) as pool:
            out = list(pool.map(worker, range(8)))
        self.assertEqual(out.count("CONSUMED"), 1, out)
        self.assertEqual(out.count("INVALID_STATE_TRANSITION"), 7, out)
        self.assertEqual(self.ledger.state(self.g["grantId"]), "CONSUMED")
        self.assertEqual(
            sum(
                x[2] == "TRANSITION" and x[3] == "CONSUMED"
                for x in self.ledger.events(self.g["grantId"])
            ),
            1,
        )

    def test_abrupt_process_exit_after_commit_is_not_reusable(self):
        self.ready()
        command = """import json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[2])))
from observer_one_shot_ledger_offline import (
    OfflineLedger, TrustedDecisionFixture, RunObservationFixture
)
fixture = json.loads(Path(sys.argv[3]).read_text(encoding='utf-8'))
trusted = TrustedDecisionFixture(
    fixture['repository'], fixture['experimentId'], fixture['preparationSha'],
    fixture['authorizationSha'], fixture['protectedControllerSha'],
    fixture['auditedCodeSha'], fixture['requesterId'], fixture['externalApproverId'],
    fixture['humanReviewId'], fixture['externalDecisionId'], True, True)
run = RunObservationFixture(
    fixture['repository'], fixture['experimentId'], fixture['requestRef'],
    fixture['preparationSha'], fixture['authorizationSha'],
    fixture['protectedControllerSha'], fixture['auditedCodeSha'], 'killed-consumer')
OfflineLedger(Path(sys.argv[1])).transition(
    fixture['grantId'], 'CONSUMED', now='2026-11-21T13:00:00Z',
    trusted=trusted, run=run)
os._exit(23)
"""
        proc = subprocess.run(
            [sys.executable, "-c", command, str(self.path), str(FILE.parent), str(FIXTURE)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 23, proc.stderr)
        self.assertEqual(model.OfflineLedger(self.path).state(self.g["grantId"]), "CONSUMED")
        self.attempt("INVALID_STATE_TRANSITION")

    def test_hardlinked_ledger_refused(self):
        alias = Path(self.temp.name) / "hardlink.sqlite3"
        os.link(self.path, alias)
        with self.assertRaisesRegex(model.Refused, "LEDGER_ALIAS_REFUSED"):
            model.OfflineLedger(alias)

    def test_interruption_after_commit_never_reopens_grant(self):
        self.ready()
        self.ledger.transition(
            self.g["grantId"], "CONSUMED", now=NOW, trusted=self.trusted, run=self.run
        )
        # Synthetic powercut boundary: discard application instance immediately.
        # SQLite commit has returned; there is no external executor or real SIGKILL here.
        del self.ledger
        self.ledger = model.OfflineLedger(self.path)
        self.attempt("INVALID_STATE_TRANSITION")
        self.assertEqual(self.ledger.state(self.g["grantId"]), "CONSUMED")

    def test_fixture_never_sets_operational_authority(self):
        self.ready()
        self.ledger.transition(
            self.g["grantId"], "CONSUMED", now=NOW, trusted=self.trusted, run=self.run
        )
        self.assertTrue(all(value is False for value in model.CAPABILITIES.values()))
        self.assertEqual(
            set(model.CAPABILITIES),
            {
                "protectedControllerOperational",
                "externalLedgerOperational",
                "guestAttestationVerified",
                "qemuExecutionAuthorized",
                "guestCommandChannelAuthorized",
                "diskWritesAuthorized",
                "productionInstallationAuthorized",
            },
        )

    def test_symlink_file_refused(self):
        alias = Path(self.temp.name) / "alias.sqlite3"
        alias.symlink_to(self.path)
        with self.assertRaisesRegex(model.Refused, "LEDGER_SYMLINK_REFUSED"):
            model.OfflineLedger(alias)

    def test_real_git_intermediate_workflow_and_preflight_commits_refused(self):
        for target in (
            ".github/workflows/observer-gpt-qemu-one-shot.yml",
            "auto_tests/tools/observer_gpt_qemu_one_shot.py",
        ):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                subprocess.run(["git", "init", "-q", str(root)], check=True)
                git(root, "config", "user.name", "Fixture Only")
                git(root, "config", "user.email", "fixture@example.invalid")
                (root / "README.md").write_text("base\n", encoding="utf-8")
                git(root, "add", "README.md")
                git(root, "commit", "-qm", "audited preparation")
                original = git(root, "rev-parse", "HEAD")
                path = root / target
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("changed intermediate payload\n", encoding="utf-8")
                git(root, "add", target)
                git(root, "commit", "-qm", "unreviewed intermediate")
                intermediate = git(root, "rev-parse", "HEAD")
                assert original != intermediate
                approved = root / ".github/gpt-qemu-approvals/grant.json"
                approved.parent.mkdir(parents=True, exist_ok=True)
                approved.write_text("{}\n", encoding="utf-8")
                git(root, "add", ".github/gpt-qemu-approvals/grant.json")
                git(root, "commit", "-qm", "final approval-only commit")
                final = git(root, "rev-parse", "HEAD")
                self.assertEqual(git(root, "rev-parse", "HEAD^"), intermediate)
                self.assertEqual(
                    git(root, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"),
                    ".github/gpt-qemu-approvals/grant.json",
                )
                with tempfile.TemporaryDirectory() as ledger_dir:
                    ledger = model.OfflineLedger(Path(ledger_dir) / "db.sqlite3")
                    g = grant_fixture()
                    g["preparationSha"] = original
                    g["authorizationSha"] = "b" * 40
                    ledger.request(g, now=NOW)
                    ledger.transition(g["grantId"], "REVIEW_PENDING", now=NOW)
                    trusted = trusted_fixture(g)
                    ledger.transition(g["grantId"], "APPROVED", now=NOW, trusted=trusted)
                    run = replace(
                        run_fixture(g), preparation_sha=intermediate, authorization_sha=final
                    )
                    with self.assertRaisesRegex(
                        model.Refused, "UNAPPROVED_EXACT_COMMIT_OR_CONTEXT"
                    ):
                        ledger.transition(
                            g["grantId"], "CONSUMED", now=NOW, trusted=trusted, run=run
                        )
                    self.assertEqual(ledger.state(g["grantId"]), "APPROVED")


if __name__ == "__main__":
    unittest.main()
