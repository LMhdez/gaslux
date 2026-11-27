import base64
import hashlib
import unittest
from unittest.mock import patch
import github_witness as g

class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.cfg=patch.multiple(g,REPOSITORY="example/gaslux-witness",REPOSITORY_ID=999,
                                RULE_ID=88,GENESIS={"signer":"a"*40,"publisher":"b"*40})
        self.cfg.start()
        self.addCleanup(self.cfg.stop)
        self.w=g.GitWitness("publisher")
        self.head="b"*40
        self.next=0
        self.calls=[]
        self.data={}
        self.old="1"*64
        self.new="2"*64
        self.events={self.head:("0"*40,g.event("publisher",0,None,self.old))}
        self.rule={"id":88,"source":"example/gaslux-witness","source_type":"Repository",
                   "target":"branch","enforcement":"active","bypass_actors":[],
                   "conditions":{"ref_name":{"include":["refs/heads/ledger/publisher",
                                                        "refs/heads/ledger/signer"],"exclude":[]}},
                   "rules":[{"type":"deletion"},{"type":"non_fast_forward"}]}
        self.w.api=self.api
        self.w.read_commit=lambda sha:self.events[sha]
    def api(self,method,path,payload=None):
        self.calls.append((method,path,payload))
        if path=="": return {"id":999,"full_name":g.REPOSITORY,"private":True,"fork":False}
        if path=="/rulesets/88": return self.rule
        if path.startswith("/rules/branches/"):
            return [{"type":x,"ruleset_id":88,"ruleset_source":g.REPOSITORY,
                     "ruleset_source_type":"Repository"} for x in ("deletion","non_fast_forward")]
        if method=="GET" and path.startswith("/git/ref/"):
            return {"ref":"refs/heads/ledger/publisher","object":{"type":"commit","sha":self.head}}
        if path=="/git/blobs":
            self.value=g.json.loads(base64.b64decode(payload["content"]))
            return {"sha":"c"*40}
        if path=="/git/trees": return {"sha":"d"*40}
        if path=="/git/commits":
            self.next+=1
            sha=f"{self.next+10:040x}"
            self.events[sha]=(payload["parents"][0],self.value)
            return {"sha":sha}
        if method=="PATCH":
            self.assertIs(payload["force"],False)
            self.assertEqual(self.events[payload["sha"]][0],self.head)
            self.head=payload["sha"]
            return {"ref":"refs/heads/ledger/publisher","object":{"type":"commit","sha":self.head,"url":"x"}}
        raise AssertionError((method,path))
    def test_append_only_checkpoint_and_restore_rejected(self):
        self.w.assert_state(self.old)
        self.w.advance(self.old,self.new)
        self.w.assert_state(self.new)
        with self.assertRaisesRegex(ValueError,"checkpoint mismatch"): self.w.assert_state(self.old)
        with self.assertRaisesRegex(ValueError,"rollback/reuse"): self.w.advance(self.new,self.old)
        self.assertEqual(len([x for x in self.calls if x[0]=="PATCH"]),1)
    def test_no_bypass_inventory_fails_closed(self):
        del self.rule["bypass_actors"]
        with self.assertRaisesRegex(ValueError,"weakened"): self.w.assert_state(self.old)
        self.assertFalse(any(x[0]=="PATCH" for x in self.calls))
    def test_noncanonical_ancestry_denied(self):
        self.head="e"*40
        self.events[self.head]=("b"*40,g.event("publisher",1,self.new,"3"*64))
        with self.assertRaisesRegex(ValueError,"sequence drift"): self.w.assert_state("3"*64)
    def test_missing_genesis_denied(self):
        self.head="e"*40
        self.events[self.head]=("e"*40,g.event("publisher",1,self.old,self.new))
        with self.assertRaisesRegex(ValueError,"ancestry cycle"): self.w.assert_state(self.new)
    def test_concurrent_ref_change_no_patch(self):
        original=self.w.head
        reads=0
        def changed():
            nonlocal reads
            reads+=1
            return "f"*40 if reads>=3 else original()
        self.w.head=changed
        with self.assertRaisesRegex(ValueError,"CAS conflict"): self.w.advance(self.old,self.new)
        self.assertFalse(any(x[0]=="PATCH" for x in self.calls))
    def test_missing_deployment_pins_denied(self):
        with patch.object(g,"REPOSITORY",None):
            with self.assertRaisesRegex(ValueError,"not provisioned"): g.GitWitness("publisher")
