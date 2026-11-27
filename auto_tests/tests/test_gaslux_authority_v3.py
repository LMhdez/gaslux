import sys
import unittest
import json
import os
import re
import tempfile
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

    def test_marker_bounded_and_recoverable(self):
        b=self.bound(n=1000000)
        desc=V.description(b,"success")
        self.assertLessEqual(len(desc),140)
        self.assertEqual(V.MARKER.fullmatch(desc).groups(),("1000000","b"*40,V.digest(b),"success"))
    def test_prior_binding_retained_after_evidence_drift(self):
        b=self.bound()
        rows=[self.row(b,"success")]
        self.assertEqual(V.prior_marker(rows,"safety",42,"b"*40),V.digest(b))
        for n,base in ((43,"b"*40),(42,"c"*40)):
            with self.assertRaises(ValueError):
                V.prior_marker(rows,"safety",n,base)
    def test_wrong_app_history_refused(self):
        r=self.row(self.bound(),"success")
        r["creator"]["id"]=V.ACTORS["owner"]
        with self.assertRaisesRegex(ValueError,"issuer"):
            V.prior_marker([r],"safety",42,"b"*40)
    def test_explicit_withdrawal_request_authentication(self):
        event={"sender":{"id":V.ADMIN},"repository":{"id":V.a.REPOSITORY_ID},
               "inputs":{"v3_action":"withdraw","v3_pr":"42","v3_head":"a"*40,
                         "v3_base":"b"*40,"v3_role":"both"}}
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"event.json"
            path.write_text(json.dumps(event))
            env={"GITHUB_EVENT_NAME":"workflow_dispatch","GITHUB_ACTOR_ID":str(V.ADMIN),
                 "GITHUB_TRIGGERING_ACTOR":"LMhdez","GITHUB_RUN_ATTEMPT":"1","GITHUB_EVENT_PATH":str(path)}
            with patch.dict(os.environ,env,clear=True):
                self.assertEqual(V.authenticated_withdrawal_request(42,"a"*40,"b"*40),"both")
                with self.assertRaises(ValueError):
                    V.authenticated_withdrawal_request(42,"c"*40,"b"*40)
            for key,value in (("GITHUB_ACTOR_ID","123"),("GITHUB_RUN_ATTEMPT","2"),("GITHUB_EVENT_NAME","schedule")):
                with patch.dict(os.environ,{**env,key:value},clear=True):
                    with self.assertRaises(ValueError):
                        V.authenticated_withdrawal_request(42,"a"*40,"b"*40)
    def test_staged_publication_requires_pause_off_and_merge_off(self):
        env={"GASLUX_V3_AUTHORITY_ENABLED":"true","GASLUX_AUTONOMY_PAUSED":"false",
             "GASLUX_APP_STATUS_GATES_ENABLED":"false","GASLUX_PRODUCTION_MERGE_ENABLED":"false"}
        with patch.object(V,"role_context"),patch.object(V.g,"production_policy_observed",return_value=True),patch.object(V.g,"strict_ruleset_protected",return_value=True):
            with patch.dict(os.environ,env,clear=True):
                V.staged_publication_context("safety","b"*40)
            for key in env:
                with patch.dict(os.environ,{**env,key:"false" if env[key]=="true" else "true"},clear=True):
                    with self.assertRaises(ValueError):
                        V.staged_publication_context("safety","b"*40)
    def test_withdraw_old_binding_and_closed_pr(self):
        b=self.bound()
        obs=([self.row(b,"success")],{"safety":{"state":"success","description":V.description(b,"success")}})
        with patch.object(V,"role_context"),patch.object(V,"authenticated_withdrawal_request",return_value="safety"),patch.object(V,"candidate_identity_for_withdrawal",return_value={"number":42,"state":"closed"}),patch.object(V,"history",return_value=obs),patch.object(V,"write_production_status",return_value={"state":"failure"}) as write:
            result=V.withdraw("safety",42,"a"*40,"b"*40,explicit=True)
            self.assertEqual(result["state"],"failure")
            self.assertEqual(write.call_args.args[2]["description"],V.description(b,"failure"))
    def test_no_prior_automatic_withdrawal_refused(self):
        with patch.object(V,"role_context"),patch.object(V,"candidate_identity_for_withdrawal",return_value={"number":42}),patch.object(V,"history",return_value=([],{})),patch.object(V,"write_production_status") as write:
            with self.assertRaises(ValueError):
                V.withdraw("safety",42,"a"*40,"b"*40)
            write.assert_not_called()
    def test_explicit_wrong_role_refused(self):
        with patch.object(V,"role_context"),patch.object(V,"authenticated_withdrawal_request",return_value="owner"),patch.object(V,"history") as history:
            with self.assertRaises(ValueError):
                V.withdraw("safety",42,"a"*40,"b"*40,explicit=True)
            history.assert_not_called()
    def test_no_status_write_on_history_race(self):
        b=self.bound()
        p=V.transition(b,"success",[],V.CONTEXTS)
        with patch.object(V,"staged_publication_context"),patch.object(V,"history",return_value=([self.row(b,"failure")],{})),patch.object(V.a,"api") as api:
            with self.assertRaisesRegex(ValueError,"changed"):
                V.write_production_status("safety","a"*40,p,([],{}))
            api.assert_not_called()

    def test_workflow_serializes_and_separates_withdrawal_from_approval(self):
        w=(Path(__file__).resolve().parents[2]/".github/workflows/gaslux-agent-integrator.yml").read_text()
        safety=w.split("  v3_role_safety:",1)[1].split("  v3_role_owner:",1)[0]
        owner=w.split("  v3_role_owner:",1)[1].split("  v3_safety_approve:",1)[0]
        self.assertIn("needs: v3_role_safety",owner)
        for job in (safety,owner):
            self.assertIn("inputs.v3_action == 'withdraw'",job)
            self.assertIn("refs/heads/main",job)
            self.assertIn("permission-statuses: write",job)
            self.assertNotIn("permission-contents: write",job)
            self.assertNotIn("permission-pull-requests: write",job)
        # Other paused credential audits may independently require no V3 action.
        for name in ("v3_safety_approve","v3_owner_approve","v3_safety_revoke",
                     "v3_owner_revoke","v3_terminal_audit"):
            block=re.split(r"\n  [A-Za-z0-9_-]+:[ \t]*\n",
                           w.split("  "+name+":\n",1)[1],maxsplit=1)[0]
            self.assertEqual(block.count("inputs.v3_action == 'none' &&"),1,name)
            self.assertIn("inputs.paused_v3_probe == true &&",block)
            self.assertIn("GASLUX_AUTONOMY_PAUSED == 'true'",block)

    def test_workflow_job_uniqueness_and_dependencies(self):
        w=(Path(__file__).resolve().parents[2]/".github/workflows/gaslux-agent-integrator.yml").read_text()
        self.assertEqual(w.count("\njobs:\n"),1)
        body=w.split("\njobs:\n",1)[1]
        # Workflow uses block-style plain job keys at exactly two spaces.
        # Inspect every top-level entry, not a YAML loader that silently
        # overwrites duplicated mapping keys.
        matches=list(re.finditer(r"^  ([A-Za-z0-9_-]+):[ \t]*(?:#.*)?$",body,re.M))
        names=[m.group(1) for m in matches]
        self.assertTrue(names)
        self.assertEqual(len(names),len(set(names)),"Duplicate job keys")
        for line in body.splitlines():
            if line.startswith("  ") and not line.startswith("   ") and line.strip() and not line.lstrip().startswith("#"):
                self.assertRegex(line,r"^  [A-Za-z0-9_-]+:[ \t]*(?:#.*)?$")
        jobs={m.group(1):body[m.end():matches[i+1].start() if i+1<len(matches) else len(body)]
              for i,m in enumerate(matches)}
        expected={
            "v3_role_safety":None,
            "v3_role_owner":"v3_role_safety",
            "v3_safety_approve":"paused_status_pilot_audit",
            "v3_owner_approve":"v3_safety_approve",
            "v3_safety_revoke":"v3_owner_approve",
            "v3_owner_revoke":"v3_safety_revoke",
            "v3_terminal_audit":"v3_owner_revoke"}
        self.assertEqual({n for n in names if n.startswith("v3_")},set(expected))
        for job,dep in expected.items():
            actual=re.findall(r"^    needs: (.+)$",jobs[job],re.M)
            self.assertEqual(actual,[dep] if dep else [],job)
            if dep:
                self.assertIn(dep,jobs)
        self.assertIn("--pilot-approve safety",jobs["v3_safety_approve"])
        self.assertIn("--pilot-approve owner",jobs["v3_owner_approve"])
        self.assertIn("--pilot-revoke safety",jobs["v3_safety_revoke"])
        self.assertIn("--pilot-revoke owner",jobs["v3_owner_revoke"])
        self.assertIn("--pilot-audit",jobs["v3_terminal_audit"])
