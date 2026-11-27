import copy
import unittest
from unittest.mock import patch
import authority_contract as a
import hosted_publisher_state as p
import authority_publisher as publisher
import safety_signer as signer
import test_authority_contract as fixtures

class Store:
    def __init__(self):
        self.state=[]
        self.history=[[]]
        self.lost=False
    def load(self): return copy.deepcopy(self.state)
    def assert_state(self,digest):
        a.v.need(p.state_digest(self.state)==digest,"External checkpoint mismatch")
    def advance_rows(self,before,rows):
        self.assert_state(before)
        if self.state==rows: return
        p.transition(self.state,rows)
        self.state=copy.deepcopy(rows)
        self.history.append(self.load())
        if self.lost: raise OSError("lost CAS response")

class HostedStateTests(unittest.TestCase):
    def setUp(self):
        self.fx=fixtures.Tests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.e=self.fx.e
        self.store=Store()
        self.j=p.HostedJournal(self.store)
        self.addCleanup(self.j.close)
    def call(self,j,d):
        sig=signer.sign_bytes(self.fx.f.key,a.v.canonical(a.v.decision_payload(self.e,d)))
        return a.process(self.fx.f,j,self.e,d,sig,self.fx.f.pem)
    def test_reconstruct_after_withdrawal_and_reject_old_view(self):
        old=p.HostedJournal(self.store)
        self.addCleanup(old.close)
        self.call(self.j,"withdraw")
        with self.assertRaisesRegex(ValueError,"checkpoint mismatch"): self.call(old,"approve")
        new=p.HostedJournal(self.store)
        self.addCleanup(new.close)
        self.assertEqual(new.row(self.e["head"])[3],"withdrawn")
        with self.assertRaisesRegex(ValueError,"Terminal"): self.call(new,"approve")
    def test_ambiguous_cas_reload_durable_intent_no_success(self):
        self.store.lost=True
        with self.assertRaises(OSError): self.call(self.j,"withdraw")
        self.assertEqual(self.fx.f.writes,0)
        with self.assertRaisesRegex(ValueError,"Poisoned"): self.call(self.j,"approve")
        self.store.lost=False
        new=p.HostedJournal(self.store)
        self.addCleanup(new.close)
        self.assertEqual(new.row(self.e["head"])[3],"withdrawal_reserved")
        self.assertEqual(self.call(new,"withdraw")["state"],"failure")
        self.assertEqual(self.fx.f.writes,1)
    def test_remote_posting_intent_survives_lost_status_response(self):
        self.fx.f.uncertain=True
        with self.assertRaises(OSError): self.call(self.j,"approve")
        new=p.HostedJournal(self.store)
        self.addCleanup(new.close)
        self.assertEqual(new.row(self.e["head"])[3],"approval_posting")
        self.fx.f.uncertain=False
        self.call(new,"withdraw")
        self.assertEqual(new.row(self.e["head"])[3],"withdrawn")
        self.assertEqual(self.fx.f.writes,2)
    def test_history_removal_and_denial_reset_rejected(self):
        self.call(self.j,"withdraw")
        rows=self.store.load()
        with self.assertRaisesRegex(ValueError,"history removed"): p.transition(rows,[])
        altered=copy.deepcopy(rows)
        altered[0][3]=None
        altered[0][4]="approval_reserved"
        with self.assertRaises(ValueError): p.transition(rows,altered)
    def test_digest_compatible_with_existing_journal(self):
        self.call(self.j,"approve")
        self.assertEqual(p.state_digest(self.j.rows()),a.anchor.digest_state("publisher",self.j.db))
    def test_snapshot_transition_validates_exact_evidence(self):
        self.call(self.j,"approve")
        rows=self.store.load()
        changed=copy.deepcopy(rows)
        changed[0][2]="0"*64
        with self.assertRaisesRegex(ValueError,"binding"): p.state_digest(changed)
