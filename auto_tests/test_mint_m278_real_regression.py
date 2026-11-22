"""M-278-01: real-module, fail-closed predecessor SHA-to-JSON regressions.

Tested on a synthetic private directory only; no guest, VM, disk or installer.
Expected on the vulnerable 7b8954a... head: three RED, two GREEN.

The hook wraps the *real* sha256_file() and mutates only AFTER its genuine
SHA-256 was calculated; authenticated_predecessor_status() is never mocked.
If the fixed code stops calling that legacy helper, the same tests also
require rejection of a forged predecessor prepared before the second attempt.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
import windows_mint_ab_forensic as forensic  # noqa: E402 — REAL imported module

TXID = "m278-real-safety-transaction"
OTHER_TXID = "m278-foreign-transaction"
RUN = "123456789"
COMMIT = "a" * 40
KEY = "checkpoint"
FILE = "mint-ab-checkpoint.json"


def encoded(doc: dict) -> bytes:
    return (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class MintM278RealModuleRegression(unittest.TestCase):
    """Five A–E cases; no production code, runner state or disks modified."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="gaslux-m278-red-")
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.checkpoint = self.dir / FILE
        self.a = encoded({"transactionId": TXID, "result": "PASS", "marker": "ORIGINAL"})
        self.b = encoded({"transactionId": TXID, "result": "PASS", "marker": "TAMPERED"})
        # Same byte length: also reproduces same-inode/same-size modification.
        self.assertEqual(len(self.a), len(self.b))
        self.checkpoint.write_bytes(self.a)
        early = encoded(
            {
                "schema": "gaslux-mint-ab-capacity-v1",
                "result": "PASS",
                "githubRunId": RUN,
                "sourceCommit": COMMIT,
            }
        )
        (self.dir / "mint-ab-capacity-early.json").write_bytes(early)
        self.supplied = {"checkpoint": digest(self.a), "earlyCapacity": digest(early)}
        env = patch.dict(os.environ, {"GITHUB_RUN_ID": RUN, "GITHUB_SHA": COMMIT})
        env.start()
        self.addCleanup(env.stop)

    def authenticate(self):
        return forensic.authenticated_predecessor_status(
            phase="before_windows_a",
            evidence=self.dir,
            transaction_id=TXID,
            supplied_sha256=self.supplied,
        )

    def _read_denied(self, result) -> bool:
        status, problems = result
        return bool(problems) or status[KEY]["sha256Matched"] is not True

    def _attack(self, operation) -> None:
        """Schedule attack after genuine digest A, before JSON parse B."""
        original_sha256_file = forensic.sha256_file
        fired = []
        parsed = []
        original_loads = forensic.json.loads

        def sha_then_mutate(path):
            result = original_sha256_file(path)  # genuine SHA on actual file A
            if Path(path).name == FILE and not fired:
                self.assertEqual(result, self.supplied[KEY])
                operation()
                fired.append(True)
            return result

        def observe_parsed(raw, *args, **kwargs):
            obj = original_loads(raw, *args, **kwargs)
            if isinstance(obj, dict) and obj.get("transactionId") == TXID:
                material = raw.encode() if isinstance(raw, str) else bytes(raw)
                parsed.append((digest(material), obj.get("marker")))
            return obj

        try:
            with (
                patch.object(forensic, "sha256_file", side_effect=sha_then_mutate),
                patch.object(forensic.json, "loads", side_effect=observe_parsed),
            ):
                result = self.authenticate()
        except (forensic.ForensicError, OSError, ValueError):
            return  # Correct fail-closed refusal is acceptable.

        if not fired:
            # Fixed implementations may have removed the insecure helper.
            # Then use the *same* attack payload as an already-swapped
            # predecessor with supplied SHA still pinned to original A.
            operation()
            try:
                result = self.authenticate()
            except (forensic.ForensicError, OSError, ValueError):
                return

        # Independent semantic oracle: if document B was parsed and accepted,
        # it was NOT the document whose SHA-256 was approved (A).
        if parsed and not self._read_denied(result):
            self.assertTrue(
                all(d == self.supplied[KEY] for d, _ in parsed),
                "M-278-01: semantically accepted JSON bytes do not match authenticated SHA",
            )
        self.assertTrue(
            self._read_denied(result),
            "M-278-01: a changed/symlink predecessor was accepted as authenticated",
        )

    def test_a_path_swap_after_hash_must_deny(self):
        replacement = self.dir / "replacement-private.json"
        replacement.write_bytes(self.b)

        def swap():
            os.replace(replacement, self.checkpoint)

        self._attack(swap)

    def test_b_same_inode_in_place_mutation_after_hash_must_deny(self):
        inode = self.checkpoint.stat().st_ino

        def mutate():
            with self.checkpoint.open("r+b") as output:
                output.write(self.b)
                output.flush()
                os.fsync(output.fileno())
            self.assertEqual(self.checkpoint.stat().st_ino, inode)
            self.assertEqual(self.checkpoint.stat().st_size, len(self.a))

        self._attack(mutate)

    def test_c_late_symlink_after_hash_must_deny(self):
        target = self.dir / "synthetic-foreign.json"
        target.write_bytes(self.b)
        saved = self.dir / "original-kept-open.json"

        def symlink_swap():
            os.replace(self.checkpoint, saved)
            self.checkpoint.symlink_to(target.name)

        self._attack(symlink_swap)

    def test_d_foreign_transaction_must_deny(self):
        foreign = encoded({"transactionId": OTHER_TXID, "result": "PASS", "marker": "ORIGINAL"})
        self.checkpoint.write_bytes(foreign)
        self.supplied[KEY] = digest(foreign)
        status, problems = self.authenticate()
        self.assertFalse(status[KEY]["sha256Matched"])
        self.assertIn("foreign_predecessor_transaction", {p["issue"] for p in problems})

    def test_e_correct_document_must_accept(self):
        status, problems = self.authenticate()
        self.assertEqual(problems, [])
        self.assertTrue(all(x["sha256Matched"] is True for x in status.values()))


if __name__ == "__main__":
    unittest.main()
