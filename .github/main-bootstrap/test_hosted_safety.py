import hashlib
import unittest
from unittest.mock import patch
import hosted_safety as h
import hosted_evaluator as ev
import authority_contract as a
import safety_signer as signer
import test_authority_contract as fixtures

class HostedTests(unittest.TestCase):
    def setUp(self):
        self.fx=fixtures.Tests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.e=self.fx.e
        self.key=self.fx.f.key
        self.pem=self.fx.f.pem
        self.cfg=patch.multiple(h,CONTROL_REPO="example/safety-control",CONTROL_ID=123,
                                LEDGER_RULE=77,LEDGER_GENESIS="a"*40)
        self.cfg.start()
        self.addCleanup(self.cfg.stop)
    def envelope(self,n,parent,last,entry):
        p=h.event(n,parent,last,entry)
        return {"payload":p,"signature_b64":signer.sign_bytes(self.key,a.v.canonical(p))}
    def entry(self,d):
        return {"evidence":self.e,"decision":d,
                "signature_b64":signer.sign_bytes(self.key,a.v.canonical(a.v.decision_payload(self.e,d)))}
    def records(self,*decisions):
        out=[]
        last=None
        for i,d in enumerate((None,)+decisions):
            parent=str(i)*40
            envelope=self.envelope(i,parent,last,None if d is None else self.entry(d))
            out.append((parent,envelope))
            last=a.v.digest(envelope["payload"])
        return out
    def test_signed_terminal_history(self):
        states,last=h.replay(self.records("approve","withdraw"),self.pem)
        self.assertEqual(states[self.e["head"]]["decision"],"withdraw")
        with self.assertRaisesRegex(ValueError,"terminal approval"):
            h.replay(self.records("approve","withdraw","approve"),self.pem)
    def test_unknown_withdrawal_denied(self):
        with self.assertRaisesRegex(ValueError,"Unknown"):
            h.replay(self.records("withdraw"),self.pem)
    def test_tamper_and_parent_binding(self):
        records=self.records("approve")
        records[1]=("f"*40,records[1][1])
        with self.assertRaisesRegex(ValueError,"sequence mismatch"):
            h.replay(records,self.pem)
        records=self.records("approve")
        records[1][1]["signature_b64"]="A"*88
        with self.assertRaises(ValueError):
            h.replay(records,self.pem)
    def test_current_and_retained_are_live_read_only(self):
        ledger=h.Ledger("test",self.pem)
        with patch.object(ledger,"snapshot",return_value=("b"*40,2,{self.e["head"]:self.entry("withdraw")},"c"*64)):
            self.assertEqual(ledger.current(self.e),("b"*40,"withdrawn"))
            self.assertEqual(ledger.retained()[1][0]["decision"],"withdraw")
    def test_frozen_evidence_missing_blocks(self):
        with self.assertRaisesRegex(ValueError,"No independently reviewed"):
            ev.exact_evidence(436)
    def test_hosted_boundary_denies_unprovisioned_release(self):
        with self.assertRaisesRegex(ValueError,"Untrusted hosted evaluator"):
            ev.boundary()
    def test_ruleset_no_bypass_required(self):
        rule={"id":77,"source":"example/safety-control","source_type":"Repository",
              "target":"branch","enforcement":"active","bypass_actors":[],
              "conditions":{"ref_name":{"include":["refs/heads/ledger/safety"],"exclude":[]}},
              "rules":[{"type":"deletion"},{"type":"non_fast_forward"}]}
        h.rule_check(rule)
        rule["bypass_actors"]=[{"actor_id":1}]
        with self.assertRaisesRegex(ValueError,"protection drift"): h.rule_check(rule)
