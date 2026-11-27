import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import gaslux_authority_v3 as V

class AuthorityV3Tests(unittest.TestCase):
    def bound(self,kind="safety",n=42,base="b"*40,evidence=None):
        return V.binding(kind,n,"dev","a"*40,base,"mint",V.g.factory.SUPERVISED_TEST_SCOPE,
                         evidence or {"ci":[123]})
    def row(self,b,state,i=1):
        k=b["authority"]
        return {"id":i,"context":V.CONTEXTS[k],"state":state,"description":V.description(b,state),
                "creator":{"id":V.ACTORS[k],"type":"Bot","login":"gaslux-independent-"+k+"[bot]"}}
    def test_terminal_both_roles(self):
        for k in V.ROLES:
            b=self.bound(k)
            yes,no=self.row(b,"success"),self.row(b,"failure",2)
            for rows in ([yes,no],[no,yes]):
                with self.assertRaisesRegex(ValueError,"terminal"):
                    V.transition(b,"success",rows,V.CONTEXTS)
                V.terminal(b,rows,V.CONTEXTS)
    def test_replay(self):
        for b in (self.bound(n=43),self.bound(base="c"*40),self.bound(evidence={"ci":[456]})):
            with self.assertRaisesRegex(ValueError,"tuple"):
                V.transition(b,"success",[self.row(self.bound(),"success")],V.CONTEXTS)
    def test_wrong_issuer(self):
        b=self.bound()
        for row in ({**self.row(b,"success"),"creator":{"id":V.ACTORS["owner"]}},
                    {**self.row(b,"success"),"context":V.CONTEXTS["safety"].upper()}):
            with self.assertRaisesRegex(ValueError,"issuer"):
                V.transition(b,"success",[row],V.CONTEXTS)
    def test_incomplete_or_duplicate_history(self):
        b=self.bound()
        for rows in ([self.row(b,"success")]*100,[self.row(b,"success")]*2):
            with self.assertRaises(ValueError):
                V.transition(b,"success",rows,V.CONTEXTS)
    def test_role_specific_and_vm(self):
        row={"scope":V.g.factory.SUPERVISED_TEST_SCOPE,"technical_objection":False,
             "exact_scope_verified":True,"current_base_verified":True,
             "ci_workflow_provenance_verified":True,"ci_verified":True,
             "safety_review_verified":True,"backend_owner_verified":False}
        self.assertEqual(V.decision("safety",row,False),"success")
        self.assertEqual(V.decision("owner",row,False),"pending")
        row.update(scope=V.g.MULTIFILE_SCOPE,backend_owner_verified=True)
        for k in V.ROLES:
            self.assertEqual(V.decision(k,row,False),"pending")
            self.assertEqual(V.decision(k,{**row,"technical_objection":True},True),"failure")
    def test_bad_target(self):
        with self.assertRaises(ValueError):
            V.binding("safety",42,"main","a"*40,"b"*40,"mint",V.g.factory.SUPERVISED_TEST_SCOPE,{"ci":1})
    def test_history_drift(self):
        b=self.bound()
        with patch.object(V.a,"api",side_effect=[[self.row(b,"success")],[self.row(b,"failure",2)]]), patch.object(V.v1,"status_receipts",return_value={}):
            with self.assertRaisesRegex(ValueError,"Concurrent"):
                V.history(b["head"],V.CONTEXTS)
    def test_no_prior(self):
        with self.assertRaisesRegex(ValueError,"No prior"):
            V.transition(self.bound(),"failure",[],V.CONTEXTS)
    def test_pilot_isolated(self):
        self.assertFalse(set(V.PILOT.values()) & (set(V.CONTEXTS.values())|set(V.v1.CONTEXTS.values())))
        with patch.object(V,"pilot_context",side_effect=ValueError("paused only")),patch.object(V.a,"api") as api:
            with self.assertRaises(ValueError):
                V.pilot_write("safety","success")
            api.assert_not_called()
