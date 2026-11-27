import unittest
from unittest.mock import patch
import hosted_controller as c
import authority_contract as a
import test_authority_contract as fixtures

class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.fx=fixtures.Tests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.e=self.fx.e
        self.fact={"number":436,"id":self.e["pr_id"],"state":"open","merged":False,
                   "draft":False,"head":self.e["head"],"head_ref":a.v.ALLOW[436][2],
                   "head_repo":a.v.RID,"base_ref":"main","base_repo":a.v.RID,"main":self.e["base"]}
    def test_definite_adverse_facts(self):
        self.assertFalse(c.invalid_facts(self.e,self.fact))
        for key,value in (("head","f"*40),("base_ref","dev"),("draft",True),
                          ("main","f"*40),("state","closed")):
            self.assertTrue(c.invalid_facts(self.e,{**self.fact,key:value}))
    def test_controller_disabled(self):
        with self.assertRaisesRegex(ValueError,"not activated"):
            c.executor.controller_boundary(None)
    def test_revocation_fact_stability_and_no_fabrication(self):
        from unittest.mock import Mock
        w=Mock()
        entry={"evidence":self.e,"decision":"approve","signature_b64":"unused"}
        w.snapshot_full.return_value=("a"*40,1,{self.e["head"]:entry},"b"*64,None,set(),[])
        bad={**self.fact,"draft":True}
        with patch.object(c,"fact_view",side_effect=[self.fact,bad]):
            self.assertEqual(len(c.refresh_revocations(w,self.fx.f,None)),1)
            w.append.assert_not_called()
        with patch.object(c,"fact_view",return_value=bad):
            self.assertEqual(c.refresh_revocations(w,self.fx.f,None),[])
            w.append.assert_called_once_with(self.e,"withdraw")
    def test_unavailable_evidence_not_signed_as_withdrawal(self):
        from unittest.mock import Mock
        w=Mock()
        w.snapshot_full.return_value=("a"*40,1,{self.e["head"]:
            {"evidence":self.e,"decision":"approve","signature_b64":"unused"}},"b"*64,None,set(),[])
        with patch.object(c,"fact_view",side_effect=OSError("unavailable")):
            self.assertEqual(len(c.refresh_revocations(w,self.fx.f,None)),1)
            w.append.assert_not_called()

    def test_status_failure_does_not_starve_merge_readback(self):
        from unittest.mock import Mock
        w=Mock()
        active={"evidence":self.e,"reservation":"f"*64,"phase":"posting"}
        w.snapshot_full.return_value=("a"*40,1,{},"b"*64,active,set(),[])
        failure=c.publisher.CycleBlocked([], [{"stage":"withdraw"}])
        with patch.object(c.executor,"controller_boundary"),patch.object(c.executor,"boundary"), \
             patch.object(c,"feed_cycle",side_effect=failure), \
             patch.object(c,"refresh_revocations",return_value=[]), \
             patch.object(c.executor,"recover",return_value={"state":"merged_recovered"}) as recover:
            result=c.run(w,self.fx.f,Mock(),self.fx.j)
            self.assertEqual(result["result"]["state"],"merged_recovered")
            self.assertTrue(result["unresolved"])
            recover.assert_called_once()
