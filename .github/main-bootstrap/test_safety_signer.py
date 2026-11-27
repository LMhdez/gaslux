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
        s.open_db(self.root,self.fp,init=True).close()
        self.live=lambda root,e:None
    def policy(self,d,e=None):
        e=self.e if e is None else e
        p=self.root/"policy.json"
        p.write_text(json.dumps({"schema":"gaslux-independent-safety-policy-v1","decisions":[
             {"head":e["head"],"evidence_sha256":s.v.digest(e),"decision":d}]}))
        p.chmod(0o600)
    def issue(self,d,e=None):
        with patch.object(s,"private_dir"):
            return s.issue(self.root,{"evidence":self.e if e is None else e,"decision":d},self.live)
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
