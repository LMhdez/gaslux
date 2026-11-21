"""Adversarial synthetic TPM quote replay tests; no guest or swtpm launched."""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from datetime import timedelta

import pytest

from auto_tests.installer_observer.durable_quote_replay import DurableQuoteReplayGuard
from auto_tests.installer_observer.guest_attestation import (
    AttestationRefused,
    OfflineQuoteVerifier,
    make_challenge,
)
from auto_tests.tests.test_observer_guest_attestation import NOW, fixture, run, sign_quote


def ledger(tmp_path):
    tmp_path.chmod(0o700)
    return tmp_path / "tpm-replay.sqlite3"


def verify_with(guard, policy, evidence, *, context=None):
    return OfflineQuoteVerifier(policy, guard).verify(
        evidence, expected_context=context or evidence.context, now=NOW
    )


def code_of(fn):
    try:
        fn()
    except AttestationRefused as exc:
        return exc.code
    return "ACCEPT"


def subprocess_consume(path, evidence, *, request_id=None, nonce=None):
    """A new Python process reopens the same on-disk ledger without reset."""
    context = evidence.context
    code = """
import sys
from datetime import datetime, UTC, timedelta
from auto_tests.installer_observer.durable_quote_replay import DurableQuoteReplayGuard
from auto_tests.installer_observer.guest_attestation import AttestationRefused
try:
    DurableQuoteReplayGuard(sys.argv[1]).consume_challenge(
        bytes.fromhex(sys.argv[2]), nonce=bytes.fromhex(sys.argv[3]),
        request_id=sys.argv[4], transaction_id=sys.argv[5],
        session_id=sys.argv[6], now=datetime.fromisoformat(sys.argv[7]),
        valid_until=datetime.fromisoformat(sys.argv[8]),
    )
except AttestationRefused as exc:
    print(exc.code)
else:
    print("ACCEPT")
"""
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            code,
            str(path),
            make_challenge(context).hex(),
            (nonce or context.nonce).hex(),
            request_id or context.request_id,
            context.transaction_id,
            context.session_id,
            NOW.isoformat(),
            (NOW + timedelta(days=1)).isoformat(),
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    return proc.stdout.strip()


def test_provision_reopen_and_cross_process_replay(tmp_path):
    path = ledger(tmp_path)
    _, policy, evidence = fixture()
    assert code_of(lambda: DurableQuoteReplayGuard(path)) == "REPLAY_STORAGE_UNAVAILABLE"
    guard = DurableQuoteReplayGuard.provision(path)
    assert verify_with(guard, policy, evidence).quote_signature_valid
    assert path.stat().st_mode & 0o777 == 0o600
    assert code_of(lambda: DurableQuoteReplayGuard.provision(path)) == "REPLAY_STORAGE_UNAVAILABLE"
    assert subprocess_consume(path, evidence) == "CHALLENGE_REPLAY"
    assert code_of(lambda: verify_with(DurableQuoteReplayGuard(path), policy, evidence)) == (
        "CHALLENGE_REPLAY"
    )


def test_cross_process_atomic_single_winner(tmp_path):
    path = ledger(tmp_path)
    DurableQuoteReplayGuard.provision(path)
    _, _, evidence = fixture()
    context = evidence.context
    # Independent processes contend on BEGIN IMMEDIATE, not a threading.Lock.
    code = """
import sys
from datetime import datetime, timedelta
from auto_tests.installer_observer.durable_quote_replay import DurableQuoteReplayGuard
from auto_tests.installer_observer.guest_attestation import AttestationRefused
try:
    DurableQuoteReplayGuard(sys.argv[1]).consume_challenge(
        bytes.fromhex(sys.argv[2]), nonce=bytes.fromhex(sys.argv[3]),
        request_id=sys.argv[4], transaction_id=sys.argv[5],
        session_id=sys.argv[6], now=datetime.fromisoformat(sys.argv[7]),
        valid_until=datetime.fromisoformat(sys.argv[8]))
except AttestationRefused as exc:
    print(exc.code)
else:
    print("ACCEPT")
"""
    argv = [
        sys.executable,
        "-c",
        code,
        str(path),
        make_challenge(context).hex(),
        context.nonce.hex(),
        context.request_id,
        context.transaction_id,
        context.session_id,
        NOW.isoformat(),
        (NOW + timedelta(days=1)).isoformat(),
    ]
    processes = [subprocess.Popen(argv, stdout=subprocess.PIPE, text=True) for _ in range(4)]
    outcomes = []
    for proc in processes:
        stdout, _ = proc.communicate(timeout=20)
        assert proc.returncode == 0
        outcomes.append(stdout.strip())
    assert outcomes.count("ACCEPT") == 1
    assert outcomes.count("CHALLENGE_REPLAY") == 3


@pytest.mark.parametrize("variant", ("nonce", "request_id"))
def test_nonce_and_request_uniqueness_across_quote_contexts(tmp_path, variant):
    path = ledger(tmp_path)
    guard = DurableQuoteReplayGuard.provision(path)
    key, policy, evidence = fixture()
    run(policy, evidence, guard=guard)
    if variant == "nonce":
        changed = replace(evidence.context, request_id="new-request-id")
        expected = "NONCE_REPLAY"
    else:
        changed = replace(evidence.context, nonce=bytes([0xA5]) * 32)
        expected = "REQUEST_REPLAY"
    new_quote = sign_quote(
        key, evidence.ak_spki_der, changed, evidence.pcrs, policy.qualified_signer_hex
    )
    assert code_of(lambda: verify_with(DurableQuoteReplayGuard(path), policy, new_quote)) == (
        expected
    )


def test_corruption_and_deleted_ledger_are_fail_closed(tmp_path):
    path = ledger(tmp_path)
    DurableQuoteReplayGuard.provision(path)
    path.write_bytes(b"not a SQLite file")
    assert code_of(lambda: DurableQuoteReplayGuard(path)) == "REPLAY_STORAGE_UNAVAILABLE"
    path.unlink()
    assert code_of(lambda: DurableQuoteReplayGuard(path)) == "REPLAY_STORAGE_UNAVAILABLE"


def test_symlink_hardlink_and_writable_mode_refused(tmp_path):
    path = ledger(tmp_path)
    DurableQuoteReplayGuard.provision(path)
    alias = tmp_path / "alias.sqlite3"
    os.link(path, alias)
    assert code_of(lambda: DurableQuoteReplayGuard(path)) == "REPLAY_STORAGE_UNAVAILABLE"
    alias.unlink()
    path.chmod(0o644)
    assert code_of(lambda: DurableQuoteReplayGuard(path)) == "REPLAY_STORAGE_UNAVAILABLE"
    path.chmod(0o600)
    alias.symlink_to(path)
    assert code_of(lambda: DurableQuoteReplayGuard(alias)) == "REPLAY_STORAGE_UNAVAILABLE"


def test_post_open_path_substitution_revokes_guard(tmp_path):
    path = ledger(tmp_path)
    guard = DurableQuoteReplayGuard.provision(path)
    path.rename(tmp_path / "old.sqlite3")
    alias = tmp_path / "alias.sqlite3"
    alias.symlink_to(tmp_path / "old.sqlite3")
    alias.rename(path)
    _, _, evidence = fixture()
    assert (
        code_of(
            lambda: guard.consume_challenge(
                make_challenge(evidence.context),
                nonce=evidence.context.nonce,
                request_id=evidence.context.request_id,
                transaction_id=evidence.context.transaction_id,
                session_id=evidence.context.session_id,
                now=NOW,
                valid_until=NOW + timedelta(days=1),
            )
        )
        == "REPLAY_STORAGE_UNAVAILABLE"
    )


def test_expired_reference_policy_never_licenses_replay(tmp_path):
    path = ledger(tmp_path)
    guard = DurableQuoteReplayGuard.provision(path)
    _, policy, evidence = fixture()
    run(policy, evidence, guard=guard)
    assert (
        code_of(
            lambda: verify_with(
                DurableQuoteReplayGuard(path), replace(policy, valid_until=NOW), evidence
            )
        )
        == "POLICY_EXPIRED"
    )
    assert subprocess_consume(path, evidence) == "CHALLENGE_REPLAY"
