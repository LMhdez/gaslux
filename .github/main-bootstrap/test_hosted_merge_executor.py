import unittest
from unittest.mock import patch
import authority_contract as a
import hosted_merge_executor as x
import github_main_merge as gm
import hosted_safety as h
import test_authority_contract as fixtures
import safety_signer as signer

class Writer:
    def __init__(self,fx):
        self.fx=fx
        self.e=fx.e
        self.pem=fx.f.pem
        self.entry={"evidence":self.e,"decision":"approve","signature_b64":
                    signer.sign_bytes(fx.f.key,a.v.canonical(a.v.decision_payload(self.e,"approve")))}
        self.active=None
        self.consumed=set()
        self.incidents=[]
        self.tip="0"*40
        self.ops=[]
        self.withdraw_at=None
    def snapshot_full(self):
        return self.tip,1,{self.e["head"]:self.entry},"1"*64,self.active,self.consumed,self.incidents
    def append_operation(self,e,op,rid,receipt=None):
        self.ops.append(op)
        self.tip=f"{len(self.ops):040x}"
        if op=="reserve_merge": self.active={"evidence":e,"reservation":rid,"phase":"reserved"}
        if op=="merge_posting": self.active["phase"]="posting"
        if op=="merge_aborted": self.active=None
        if op=="merge_confirmed": self.active=None; self.consumed.add(e["head"])
        if self.withdraw_at==op:
            self.entry={"evidence":e,"decision":"withdraw","signature_b64":
                        signer.sign_bytes(self.fx.f.key,a.v.canonical(a.v.decision_payload(e,"withdraw")))}
            if op=="reserve_merge": self.active=None
            self.tip="f"*40
        return self.tip,{}

class Merger:
    def __init__(self):
        self.calls=0
        self.result=None
        self.lost=False
    def proof(self): return {}
    def dispatch_once(self,e):
        self.calls+=1
        self.result={"pr":e["pr"],"head":e["head"],"base":e["base"],"tree":e["tree"],"merge":"e"*40}
        if self.lost: raise OSError("lost response")
        return self.result["merge"]
    def receipt(self,e,reader): return self.result

class MergeTests(unittest.TestCase):
    def setUp(self):
        self.fx=fixtures.Tests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.e=self.fx.e
        self.j=self.fx.j
        self.f=self.fx.f
        self.f.merged_receipt=lambda e:None
        self.w=Writer(self.fx)
        self.m=Merger()
        self.fx.call("approve")
        for target,name,val in [(x,"boundary",None),(x.evaluator,"exact_evidence",self.e)]:
            p=patch.object(target,name,return_value=val);p.start();self.addCleanup(p.stop)
    def run_merge(self): return x.execute(self.w,self.f,self.m,self.j,self.e)
    def test_exact_merge_once(self):
        self.assertEqual(self.run_merge()["state"],"merged")
        self.assertEqual(self.m.calls,1)
        self.assertEqual(self.w.ops,["reserve_merge","merge_posting","merge_confirmed"])
        with self.assertRaises(ValueError): self.run_merge()
        self.assertEqual(self.m.calls,1)
    def test_revocation_after_reservation_prevents_put(self):
        self.w.withdraw_at="reserve_merge"
        with self.assertRaisesRegex(ValueError,"Reservation revoked"): self.run_merge()
        self.assertEqual(self.m.calls,0)
    def test_revocation_after_posting_before_put(self):
        self.w.withdraw_at="merge_posting"
        with self.assertRaisesRegex(ValueError,"Reservation revoked"): self.run_merge()
        self.assertEqual(self.m.calls,0)
        self.assertEqual(self.run_merge()["state"],"merge_unresolved")
        self.assertEqual(self.m.calls,0)
    def test_response_lost_recovered_without_second_put(self):
        self.m.lost=True
        with self.assertRaises(OSError): self.run_merge()
        self.assertEqual(self.w.active["phase"],"posting")
        self.assertEqual(self.run_merge()["state"],"merged_recovered")
        self.assertEqual(self.m.calls,1)
    def test_pre_dispatch_crash_leaves_posting_and_no_retry(self):
        self.w.append_operation(self.e,"reserve_merge","f"*64)
        self.w.append_operation(self.e,"merge_posting","f"*64)
        self.assertEqual(self.run_merge()["state"],"merge_unresolved")
        self.assertEqual(self.m.calls,0)
    def test_restart_aborts_never_posted_reservation(self):
        self.w.append_operation(self.e,"reserve_merge","f"*64)
        self.assertEqual(self.run_merge()["state"],"reserved_aborted")
        self.assertEqual(self.m.calls,0)
    def test_stale_evidence_never_sends(self):
        self.f.e={**self.e,"draft":True}
        with self.assertRaisesRegex(ValueError,"Candidate/base/CI drift"): self.run_merge()
        self.assertEqual(self.m.calls,0)
    def test_missing_merge_identity_pins(self):
        with self.assertRaisesRegex(ValueError,"not provisioned"): gm.MainMerge()
    def test_merge_put_restricted(self):
        with self.assertRaises(ValueError): gm.put_once(1,self.e["head"],"test")
        with self.assertRaises(ValueError): gm.put_once(436,"f"*40,"test")
    def test_concurrent_journal_writer_blocks(self):
        other=a.Journal(self.fx.path,witness=self.fx.witness)
        try:
            with self.j.exclusive():
                with self.assertRaisesRegex(ValueError,"Writer already active"):
                    x.execute(self.w,self.f,self.m,other,self.e)
            self.assertEqual(self.m.calls,0)
        finally: other.close()
