import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import authority_contract as a

class Fake:
    def __init__(self,e):
        self.e=e
        self.rows=[]
        self.writes=0
        self.uncertain=False
    def policy_proof(self):
        return {"repository_id":a.v.RID,"app":a.APP,"actor":a.ACTOR,
                "installation":a.INSTALLATION,"native_review_retained":True,
                "source_pinned_gate":True,"complete_actor_inventory":True,
                "exclusive_writer":True,"paused":True}
    def combined(self,h):
        return {"sha":h,"repository":{"id":a.v.RID},"total_count":int(bool(self.rows)),
                "statuses":copy.deepcopy(self.rows[:1])}
    def history(self,h):
        return copy.deepcopy(self.rows)
    def snapshot(self,n):
        return copy.deepcopy(self.e)
    def publish(self,h,p):
        self.writes+=1
        row={**p,"id":100+self.writes,"creator":{"id":a.ACTOR,"login":a.SLUG+"[bot]","type":"Bot"},
             "created_at":str(self.writes),"updated_at":str(self.writes)}
        self.rows.insert(0,row)
        if self.uncertain:
            raise OSError("lost response after server write")
        return copy.deepcopy(row)

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/"journal.sqlite"
        self.j=a.Journal(self.path)
        self.addCleanup(self.j.close)
        h,t,b,pid=a.v.ALLOW[436]
        self.e={"schema":"gaslux-main-bootstrap-v1","repository":a.v.REPO,
                "repository_id":a.v.RID,"target":"main","pr":436,"pr_id":pid,
                "head":h,"tree":t,"base":a.v.BASE,"composition":"a"*40,
                "predecessors":[],"verifier":a.EVIDENCE_ENGINE,"draft":False,
                "ci":{"workflow":a.v.WORKFLOW,"run":1,"attempt":1,"job":2,"suite":3,
                      "base":a.v.BASE,"head":h,"tested_composition":"a"*40,
                      "job_log_sha256":"b"*64}}
        self.f=Fake(self.e)
    def call(self,decision,e=None):
        e=self.e if e is None else e
        with patch.object(a,"verify",side_effect=lambda e,d,s,p:a.v.digest(a.v.decision_payload(e,d))):
            return a.process(self.f,self.j,e,decision,"",b"")
    def test_evidence_binding(self):
        a.evidence_shape(self.e)
        for k,x in (("target","dev"),("head","c"*40),("tree","c"*40),("pr",437),
                    ("base","c"*40),("verifier","c"*40)):
            with self.assertRaises(ValueError):
                a.evidence_shape({**self.e,k:x})
    def test_signer_unprovisioned(self):
        with self.assertRaisesRegex(ValueError,"trust root"):
            a.verify(self.e,"approve","",b"")
    def test_approve_then_terminal_withdrawal(self):
        self.assertEqual(self.call("approve")["state"],"success")
        self.f.e={**self.e,"base":"c"*40}
        self.assertEqual(self.call("withdraw")["state"],"failure")
        self.assertEqual(self.j.row(self.e["head"])[3],"withdrawn")
        with self.assertRaises(ValueError): self.call("approve")
        self.assertEqual(self.f.writes,2)
    def test_approval_stale(self):
        self.f.e={**self.e,"base":"c"*40}
        with self.assertRaisesRegex(ValueError,"Stale"):
            self.call("approve")
        self.assertEqual(self.f.writes,0)
    def test_replay(self):
        self.call("approve")
        with self.assertRaises(ValueError): self.call("approve")
        self.assertEqual(self.f.writes,1)
    def test_unknown_withdraw(self):
        with self.assertRaises(ValueError): self.call("withdraw")
        self.assertEqual(self.f.writes,0)
    def test_uncertain_write_fails_closed(self):
        self.f.uncertain=True
        with self.assertRaises(OSError): self.call("approve")
        self.assertEqual(self.j.row(self.e["head"])[3],"approval_pending")
        self.f.uncertain=False
        for d in ("approve","withdraw"):
            with self.assertRaises(ValueError): self.call(d)
        self.assertEqual(self.f.writes,1)
    def test_durable_reservation_excludes_second_writer(self):
        self.j.reserve_approval(self.e,"a"*64)
        other=a.Journal(self.path)
        try:
            with self.assertRaises(ValueError): other.reserve_approval(self.e,"a"*64)
            self.assertEqual(other.row(self.e["head"])[3],"approval_pending")
        finally: other.close()
    def test_wrong_issuer(self):
        self.call("approve")
        self.f.rows[0]["creator"]["id"]=42
        with self.assertRaisesRegex(ValueError,"issuer"): self.call("withdraw")
    def test_incomplete_history(self):
        self.call("approve")
        row=self.f.rows[0]
        self.f.rows=[{**row,"id":i} for i in range(100)]
        with self.assertRaisesRegex(ValueError,"Incomplete"): self.call("withdraw")
    def test_missing_policy(self):
        self.f.policy_proof=lambda:{"repository_id":a.v.RID,"app":a.APP,"actor":a.ACTOR,
            "installation":a.INSTALLATION,"native_review_retained":True,
            "source_pinned_gate":False,"complete_actor_inventory":True,
            "exclusive_writer":True,"paused":True}
        with self.assertRaisesRegex(ValueError,"Unproven"): self.call("approve")
        self.assertEqual(self.f.writes,0)
