import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import safety_signer as s
import authority_contract as a
import authority_anchor as anchor
import test_authority_contract as fixtures

class SignerTests(unittest.TestCase):
    def setUp(self):
        # TEST KEY ONLY; /tmp ancestor check deliberately mocked in fixture.
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.fixture=fixtures.Tests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.e=self.fixture.e
        key=self.root/"signer.pem"
        subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(key)],check=True)
        key.chmod(0o600)
        self.pem=s.public_pem(key.read_bytes())
        self.fp=hashlib.sha256(self.pem).hexdigest()
        db=s.open_db(self.root,self.fp,init=True)
        genesis=anchor.digest_state("signer",db)
        db.close()
        self.witness=anchor.WitnessStore(self.root/"witness.sqlite","signer",genesis=genesis)
        self.addCleanup(self.witness.close)
        self.live=lambda root,e:None
    def policy(self,d,e=None):
        e=self.e if e is None else e
        p=self.root/"policy.json"
        p.write_text(json.dumps({"schema":"gaslux-independent-safety-policy-v1","decisions":[
             {"head":e["head"],"evidence_sha256":s.v.digest(e),"decision":d}]}))
        p.chmod(0o600)
    def issue(self,d,e=None):
        with patch.object(s,"private_dir"):
            return s.issue(self.root,{"evidence":self.e if e is None else e,"decision":d},self.live,witness=self.witness)
    def test_independent_policy_required(self):
        self.policy("withdraw")
        with self.assertRaisesRegex(ValueError,"not authorized"): self.issue("approve")
    def test_real_signature_and_terminal_history(self):
        self.policy("approve")
        r=self.issue("approve")
        self.assertEqual(self.issue("approve"),r)
        with patch.object(a,"SIGNER_PEM_SHA256",self.fp):
            self.assertEqual(a.verify(self.e,"approve",r["signature_b64"],self.pem),r["decision_sha256"])
        self.policy("withdraw")
        self.live=lambda *_:self.fail("Withdrawal must not require live eligibility")
        rev=self.issue("withdraw")
        self.assertEqual(self.issue("withdraw"),rev)
        with patch.object(a,"SIGNER_PEM_SHA256",self.fp):
            self.assertEqual(a.verify(self.e,"withdraw",rev["signature_b64"],self.pem),rev["decision_sha256"])
        self.policy("approve")
        with self.assertRaisesRegex(ValueError,"Terminal"): self.issue("approve")
    def test_stale_live_snapshot(self):
        self.policy("approve")
        def drift(*_): raise ValueError("Live evidence drift")
        self.live=drift
        with self.assertRaisesRegex(ValueError,"drift"): self.issue("approve")
        db=s.open_db(self.root,self.fp)
        try: self.assertEqual(db.execute("SELECT COUNT(*) FROM decisions").fetchone()[0],0)
        finally: db.close()
    def test_wrong_evidence_digest(self):
        self.policy("approve")
        e={**self.e,"draft":True}
        with self.assertRaisesRegex(ValueError,"not authorized"): self.issue("approve",e)
    def test_unknown_withdrawal(self):
        self.policy("withdraw")
        with self.assertRaisesRegex(ValueError,"No matching"): self.issue("withdraw")
    def test_unsafe_policy_and_duplicate_json(self):
        self.policy("approve")
        (self.root/"policy.json").chmod(0o644)
        with self.assertRaisesRegex(ValueError,"Unsafe custody file"): self.issue("approve")
        with self.assertRaisesRegex(ValueError,"Duplicate"): s.strict_json(b'{"decision":"approve","decision":"withdraw"}')
    def test_no_implicit_journal_recreation(self):
        self.policy("approve")
        (self.root/"decisions.sqlite").unlink()
        with self.assertRaises(FileNotFoundError): self.issue("approve")
    def test_key_pin_drift(self):
        self.policy("approve")
        key=self.root/"signer.pem"
        subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(key)],check=True)
        key.chmod(0o600)
        with self.assertRaisesRegex(ValueError,"key or journal drift"): self.issue("approve")

    def test_real_signed_withdrawal_delivered_before_old_approval(self):
        self.policy("approve")
        approval=self.issue("approve")
        self.policy("withdraw")
        denial=self.issue("withdraw")
        f=self.fixture.f
        j=self.fixture.j
        with patch.object(a,"SIGNER_PEM_SHA256",self.fp):
            self.assertEqual(a.process(f,j,self.e,"withdraw",denial["signature_b64"],self.pem)["state"],"failure")
            with self.assertRaisesRegex(ValueError,"Terminal"):
                a.process(f,j,self.e,"approve",approval["signature_b64"],self.pem)
        self.assertEqual([r["state"] for r in f.rows],["failure"])

    def test_signer_rollback_detected(self):
        import sqlite3
        self.policy("approve")
        self.issue("approve")
        old=self.root/"old.sqlite"
        db=s.open_db(self.root,self.fp)
        dst=sqlite3.connect(old)
        db.backup(dst)
        dst.close()
        db.close()
        self.policy("withdraw")
        self.issue("withdraw")
        old.chmod(0o600)
        # Simulate restore of logical database state, but not independent witness.
        db=s.open_db(self.root,self.fp)
        src=sqlite3.connect(old)
        src.backup(db)
        src.close()
        db.close()
        self.policy("approve")
        with self.assertRaisesRegex(ValueError,"checkpoint mismatch"): self.issue("approve")
    def test_fresh_signed_query_before_and_after_revocation(self):
        def query(n):
            with patch.object(s,"private_dir"):
                return s.query(self.root,{"evidence":self.e,"nonce":n},witness=self.witness)
        self.policy("approve")
        self.issue("approve")
        n="a"*64
        first=query(n)
        with patch.object(a,"SIGNER_PEM_SHA256",self.fp):
            self.assertTrue(a.verify_current(self.e,n,first,self.pem))
            self.policy("withdraw")
            self.issue("withdraw")
            second=query("b"*64)
            self.assertFalse(a.verify_current(self.e,"b"*64,second,self.pem))
            with self.assertRaisesRegex(ValueError,"binding mismatch"):
                a.verify_current(self.e,"b"*64,first,self.pem)
