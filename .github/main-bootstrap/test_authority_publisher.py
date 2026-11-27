import copy
import unittest
from unittest.mock import patch
import authority_contract as a
import authority_publisher as publisher
import safety_signer as signer
import test_authority_contract as fixtures

class Multi:
    def __init__(self,fixture,evidence):
        self.fakes={}
        self.evidence={e["pr"]:e for e in evidence}
        self.key=fixture.f.key
        self.pem=fixture.f.pem
        self.merges={}
        self.attempts=[]
        self.before_publish=lambda *_:None
        for e in evidence:
            f=fixtures.Fake(e)
            f.key=self.key
            f.pem=self.pem
            self.fakes[e["head"]]=f
    def identity_proof(self):
        return next(iter(self.fakes.values())).identity_proof()
    def policy_proof(self):
        return next(iter(self.fakes.values())).policy_proof()
    def current_decision(self,e,nonce):
        return self.fakes[e["head"]].current_decision(e,nonce)
    def snapshot(self,n):
        return self.fakes[self.evidence[n]["head"]].snapshot(n)
    def merged_receipt(self,e):
        x=self.merges.get(e["pr"])
        if isinstance(x,Exception):
            raise x
        return x
    def combined(self,h):
        return self.fakes[h].combined(h)
    def history(self,h):
        return self.fakes[h].history(h)
    def outbound_settled(self,h,state):
        return self.fakes[h].outbound_settled(h,state)
    def publish(self,h,p):
        self.attempts.append((h,p["state"]))
        self.before_publish(h,p)
        return self.fakes[h].publish(h,p)

class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.fx=fixtures.Tests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.j=self.fx.j
        self.e1=self.fx.e
        self.e2=self.follow(self.e1,437,"d"*40,"e"*40)
        self.e3=self.follow(self.e2,438,"f"*40,"1"*40)
        self.t=Multi(self.fx,[self.e1,self.e2,self.e3])
    def follow(self,prior,n,merge,composition):
        h,tree,branch,pid=a.v.ALLOW[n]
        e=copy.deepcopy(prior)
        e.update(pr=n,pr_id=pid,head=h,tree=tree,base=merge,composition=composition)
        e["predecessors"].append({"pr":prior["pr"],"head":prior["head"],"tree":prior["tree"],"merge":merge})
        e["ci"].update(base=merge,head=h,tested_composition=composition)
        a.evidence_shape(e)
        return e
    def entry(self,e,d):
        msg=a.v.canonical(a.v.decision_payload(e,d))
        return {"evidence":e,"decision":d,"signature_b64":signer.sign_bytes(self.t.key,msg)}
    def cycle(self,*entries,journal=None):
        return publisher.cycle(self.t,self.j if journal is None else journal,list(entries),self.t.pem)
    def mark_merge(self):
        self.t.merges[436]={"pr":436,"head":self.e1["head"],"tree":self.e1["tree"],
                            "base":self.e1["base"],"merge":self.e2["base"]}
        # The old open-PR snapshot is no longer available.
        self.t.fakes[self.e1["head"]].e={**self.e1,"draft":True}
    def test_consumed_436_allows_437_and_never_reposts(self):
        one=self.entry(self.e1,"approve")
        two=self.entry(self.e2,"approve")
        self.cycle(one)
        self.mark_merge()
        result=self.cycle(one,two)
        self.assertEqual([x["state"] for x in result],["consumed","success"])
        self.assertEqual(self.j.row(self.e1["head"])[3],"consumed")
        self.assertEqual([x["state"] for x in self.cycle(one,two)],["consumed","already_approved"])
        self.assertEqual(self.t.attempts,[(self.e1["head"],"success"),(self.e2["head"],"success")])
    def test_invalid_or_missing_consumed_receipt_blocks_next(self):
        one=self.entry(self.e1,"approve")
        two=self.entry(self.e2,"approve")
        self.cycle(one)
        self.t.merges[436]=ValueError("wrong merge tree")
        with self.assertRaises(publisher.CycleBlocked):
            self.cycle(one,two)
        self.assertIsNone(self.j.row(self.e2["head"]))
        self.mark_merge()
        self.cycle(one)
        self.t.merges.clear()
        with self.assertRaises(publisher.CycleBlocked):
            self.cycle(one,two)
        self.assertEqual(len(self.t.attempts),1)
    def test_all_denials_reserved_and_independent_withdrawals(self):
        w1=self.entry(self.e1,"withdraw")
        w2=self.entry(self.e2,"withdraw")
        a3=self.entry(self.e3,"approve")
        f1=self.t.fakes[self.e1["head"]]
        f1.before_write=True
        f1.fenced["failure"]=False
        def before(h,p):
            self.assertIsNotNone(self.j.row(self.e1["head"])[2])
            self.assertIsNotNone(self.j.row(self.e2["head"])[2])
        self.t.before_publish=before
        with self.assertRaises(publisher.CycleBlocked) as ex:
            self.cycle(w1,w2,a3)
        self.assertEqual(ex.exception.results[0]["pr"],437)
        self.assertEqual(self.j.row(self.e2["head"])[3],"withdrawn")
        self.assertIsNone(self.j.row(self.e3["head"]))
        self.assertEqual(self.t.attempts,[(self.e1["head"],"failure"),(self.e2["head"],"failure")])
        # Restart keeps both denial intents. No blind retry of the first.
        other=a.Journal(self.fx.path,witness=self.fx.witness)
        try:
            f1.before_write=False
            with self.assertRaises(publisher.CycleBlocked):
                self.cycle(w1,w2,a3,journal=other)
            self.assertEqual(len(self.t.attempts),2)
            # A fake transport's real fence proof is provided only for testing.
            f1.fenced["failure"]=True
            result=self.cycle(w1,w2,a3,journal=other)
            self.assertEqual([x["state"] for x in result],["failure","failure","success"])
        finally: other.close()
    def test_lost_approval_response_reconciles_without_replay(self):
        one=self.entry(self.e1,"approve")
        f1=self.t.fakes[self.e1["head"]]
        f1.uncertain=True
        with self.assertRaises(publisher.CycleBlocked): self.cycle(one)
        self.assertEqual(self.j.row(self.e1["head"])[3],"approval_posting")
        f1.uncertain=False
        self.assertEqual(self.cycle(one)[0]["state"],"already_approved")
        self.assertEqual(self.j.row(self.e1["head"])[3],"approved")
        self.assertEqual(len(self.t.attempts),1)
    def test_pending_approval_with_no_receipt_is_not_reposted(self):
        one=self.entry(self.e1,"approve")
        two=self.entry(self.e2,"approve")
        f1=self.t.fakes[self.e1["head"]]
        f1.before_write=True
        with self.assertRaises(publisher.CycleBlocked): self.cycle(one)
        f1.before_write=False
        with self.assertRaises(publisher.CycleBlocked): self.cycle(one,two)
        self.assertEqual(len(self.t.attempts),1)
        self.assertIsNone(self.j.row(self.e2["head"]))
    def test_unresolved_other_head_denies_integration_and_new_approval(self):
        one=self.entry(self.e1,"approve")
        self.cycle(one)
        f2=self.t.fakes[self.e2["head"]]
        f2.before_write=True
        with self.assertRaises(publisher.CycleBlocked):
            self.cycle(one,self.entry(self.e2,"withdraw"))
        self.assertFalse(a.integration_permitted(self.t,self.j,self.e1))
        third=self.entry(self.e3,"approve")
        with self.assertRaisesRegex(ValueError,"Unresolved authority intents"):
            a.process(self.t,self.j,self.e3,"approve",third["signature_b64"],self.t.pem)
    def test_omitted_retained_intent_blocks_new_success(self):
        self.cycle(self.entry(self.e1,"withdraw"))
        with self.assertRaises(publisher.CycleBlocked):
            self.cycle(self.entry(self.e2,"approve"))
        self.assertIsNone(self.j.row(self.e2["head"]))
    def test_withdraw_consumed_approval_still_revokes(self):
        one=self.entry(self.e1,"approve")
        self.cycle(one)
        self.mark_merge()
        self.cycle(one)
        self.assertEqual(self.cycle(self.entry(self.e1,"withdraw"))[0]["state"],"failure")
        self.assertEqual(self.j.row(self.e1["head"])[3],"withdrawn")
