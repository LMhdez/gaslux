import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import gaslux_integrator_v4 as V


class V4Tests(unittest.TestCase):
    def rule(self):
        return {"id":123,"name":V.MANDATORY,"source":V.a.REPO,"source_type":"Repository",
                "target":"branch","enforcement":"active","conditions":V.TARGET,
                "current_user_can_bypass":"never","bypass_actors":[],
                "rules":[{"type":"deletion"},{"type":"non_fast_forward"},
                         {"type":"pull_request","parameters":{
                            "required_approving_review_count":0,"dismiss_stale_reviews_on_push":True,
                            "require_last_push_approval":False,"required_review_thread_resolution":True,
                            "require_code_owner_review":False,"required_reviewers":[],
                            "allowed_merge_methods":["squash"]}},
                         {"type":"required_status_checks","parameters":{
                            "strict_required_status_checks_policy":True,"do_not_enforce_on_create":False,
                            "required_status_checks":[{"context":k,"integration_id":i}
                                for k,i in V.EXPECTED_CHECKS.items()]}}]}
    def test_mandatory_policy_contract(self):
        V.mandatory_contract(self.rule())
        for field,value in (("bypass_actors",[{"actor_id":42}]),("current_user_can_bypass","always")):
            r=self.rule()
            r[field]=value
            with self.assertRaises(ValueError):
                V.mandatory_contract(r)
    def test_wrong_source_and_missing_ci(self):
        for change in ("wrong","missing","duplicate","not_strict"):
            r=self.rule()
            p=r["rules"][-1]["parameters"]
            if change=="wrong":
                p["required_status_checks"][-1]["integration_id"]=15368
            elif change=="missing":
                p["required_status_checks"].pop()
            elif change=="duplicate":
                p["required_status_checks"].append(p["required_status_checks"][0])
            else:
                p["strict_required_status_checks_policy"]=False
            with self.assertRaises(ValueError):
                V.mandatory_contract(r)
    def test_exclusive_actor_never_accepts_extra_or_always(self):
        actor={"actor_id":42,"actor_type":"Integration","bypass_mode":"pull_request"}
        self.assertTrue(V.exclusive_actor({"bypass_actors":[actor]},42))
        self.assertFalse(V.exclusive_actor({"bypass_actors":[actor,actor]},42))
        self.assertFalse(V.exclusive_actor({"bypass_actors":[{**actor,"bypass_mode":"always"}]},42))
    def test_lab_or_role_app_never_accepted(self):
        for app in (5950119,5938492,5938509,15368,*V.v.APPS.values()):
            with patch.dict(os.environ,{"GASLUX_INTEGRATOR_APP_ID":str(app)},clear=True):
                with self.assertRaises(ValueError):
                    V.app_id()
    def test_paused_audit_never_enables_merge(self):
        env={"GITHUB_EVENT_NAME":"workflow_dispatch","GASLUX_V4_AUDIT":"true",
             "GASLUX_AUTONOMY_PAUSED":"true","GASLUX_PRODUCTION_MERGE_ENABLED":"false",
             "GASLUX_APP_STATUS_GATES_ENABLED":"false","GASLUX_V3_AUTHORITY_ENABLED":"false"}
        with patch.object(V,"trusted"),patch.object(V,"credential",return_value={"app_id":42}),patch.object(V.a,"api",return_value={"object":{"sha":"a"*40}}),patch.object(V.g,"production_policy_observed",return_value=True),patch.object(V.g,"strict_ruleset_protected",return_value=True):
            with patch.dict(os.environ,env,clear=True):
                self.assertFalse(V.paused_audit()["merge_authorized"])
            with patch.dict(os.environ,{**env,"GASLUX_V4_MERGE_ENABLED":"true"},clear=True):
                with self.assertRaises(ValueError):
                    V.paused_audit()
    def test_execution_blocked_by_default(self):
        with patch.object(V,"trusted"),patch.dict(os.environ,{},clear=True),patch.object(V.a,"api") as api:
            with self.assertRaises(ValueError):
                V.integrate_one(42,"mint","test","a"*40,"b"*40)
            api.assert_not_called()
    def test_final_drift_prevents_write(self):
        p={"draft":False,"mergeable_state":"clean"}
        with patch.object(V,"execution_context",return_value={}),patch.object(V,"exact_candidate",return_value=p),patch.object(V,"receipts",side_effect=[1,2]),patch.object(V.a,"api",return_value={"tree":{"sha":"c"*40}}) as api:
            with self.assertRaisesRegex(ValueError,"drift"):
                V.integrate_one(42,"mint","test","a"*40,"b"*40)
            self.assertTrue(all(c.args[0]=="GET" for c in api.call_args_list))
    def test_ready_state_does_not_change(self):
        with patch.object(V,"execution_context",return_value={}),patch.object(V,"exact_candidate",return_value={"draft":True}),patch.object(V,"receipts",return_value={}),patch.object(V.a,"api") as api:
            self.assertEqual(V.integrate_one(42,"mint","test","a"*40,"b"*40)["status"],"ready_transition_required")
            api.assert_not_called()
    def test_exact_merge_and_closure_receipt(self):
        head,base,tree,merged="a"*40,"b"*40,"c"*40,"d"*40
        p={"draft":False,"mergeable_state":"clean"}
        replies=[{"tree":{"sha":tree}},{"merged":True,"sha":merged},
                 {"parents":[{"sha":base}],"tree":{"sha":tree}},
                 {"state":"closed","merged":True,"merge_commit_sha":merged,"head":{"sha":head},"base":{"ref":"dev"}},
                 {"object":{"sha":merged}}]
        with patch.object(V,"execution_context",return_value={}),patch.object(V,"exact_candidate",return_value=p),patch.object(V,"receipts",return_value={}),patch.object(V.a,"api",side_effect=replies) as api:
            result=V.integrate_one(42,"mint","test",head,base)
            self.assertTrue(result["pr_closure_verified"])
            self.assertEqual([c.args for c in api.call_args_list if c.args[0]=="PUT"],
                             [("PUT","/pulls/42/merge",{"sha":head,"merge_method":"squash"})])
    def test_workflow_credential_only_paused_audit(self):
        w=(Path(__file__).resolve().parents[2]/".github/workflows/gaslux-agent-integrator.yml").read_text()
        self.assertEqual(w.count("  paused_v4_credential_audit:\n"),1)
        job=w.split("  paused_v4_credential_audit:\n",1)[1]
        self.assertIn("environment: gaslux-production-integrator",job)
        self.assertIn("refs/heads/main",job)
        self.assertIn("GASLUX_AUTONOMY_PAUSED == 'true'",job)
        self.assertIn("--paused-audit",job)
        self.assertNotIn("--execute",job)
        self.assertEqual(w.count("secrets.GASLUX_INTEGRATOR_APP_PRIVATE_KEY"),1)
