import unittest
from unittest.mock import patch
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gaslux_app_status_gate as L

class AppStatusGateTests(unittest.TestCase):
    head = "a"*40
    base = "b"*40
    def row(self, scope=None):
        return {"scope": scope or L.gate.factory.SUPERVISED_TEST_SCOPE,
                "head": self.head, "base": self.base, "technical_objection": False,
                "next_action": "TEST_ONLY_INTEGRATION_ELIGIBLE",
                **dict.fromkeys(("exact_scope_verified", "current_base_verified",
                     "ci_workflow_provenance_verified", "ci_verified",
                     "safety_review_verified", "backend_owner_verified"), True)}
    def test_test_only_approved(self):
        self.assertEqual(L.decision(self.row(), "safety"), "success")
    def test_missing_owner_pending(self):
        self.assertEqual(L.decision({**self.row(), "backend_owner_verified":False}, "safety"), "pending")
    def test_hold_failure(self):
        self.assertEqual(L.decision({**self.row(), "technical_objection":True}, "owner"), "failure")
    def test_unknown_hold_pending(self):
        self.assertEqual(L.decision({**self.row(), "technical_objection":None}, "owner"), "pending")
    def test_stale_base_pending(self):
        self.assertEqual(L.decision({**self.row(), "current_base_verified":False}, "owner"), "pending")
    def test_product_requires_vm(self):
        r = {**self.row(L.gate.DYNAMIC_SCOPE), "next_action":"PRODUCT_INTEGRATION_ELIGIBLE"}
        self.assertEqual(L.decision(r, "safety"), "pending")
        self.assertEqual(L.decision({**r, "full_vm_acceptance_verified":True}, "safety"), "success")
    def test_receipt_issuer_and_base(self):
        r = {"actor":L.ACTORS["safety"], "type":"Bot", "login":"gaslux-independent-safety[bot]",
             "state":"success", "description":L.marker(42,"mint",self.base)}
        self.assertTrue(L.receipt_ok(r,"safety",42,"mint",self.base))
        self.assertFalse(L.receipt_ok(r,"owner",42,"mint",self.base))
        self.assertFalse(L.receipt_ok(r,"safety",42,"mint","c"*40))
        self.assertFalse(L.receipt_ok(r,"safety",43,"mint",self.base))
    def status_data(self):
        s={"id":17,"context":L.CONTEXTS["safety"],"state":"pending","description":"pending",
           "created_at":"t","updated_at":"t"}
        detail={**s,"creator":{"id":L.ACTORS["safety"],"type":"Bot","login":"gaslux-independent-safety[bot]"}}
        aggregate={"sha":self.head,"repository":{"id":L.a.REPOSITORY_ID},"total_count":1,"statuses":[s]}
        return aggregate,detail
    def test_real_aggregate_without_creator(self):
        s,d=self.status_data()
        with patch.object(L.a,"api",side_effect=[s,[d],s]):
            self.assertEqual(L.status_receipts(self.head)["safety"]["actor"],L.ACTORS["safety"])
    def test_missing_creator_fails(self):
        s,d=self.status_data()
        d.pop("creator")
        with patch.object(L.a,"api",side_effect=[s,[d],s]), self.assertRaises(ValueError):
            L.status_receipts(self.head)
    def test_wrong_receipt_fails(self):
        s,d=self.status_data()
        d["id"]=19
        with patch.object(L.a,"api",side_effect=[s,[d],s]), self.assertRaises(ValueError):
            L.status_receipts(self.head)
    def test_concurrent_change_fails(self):
        s,d=self.status_data()
        again={**s,"statuses":[{**s["statuses"][0],"state":"success"}]}
        with patch.object(L.a,"api",side_effect=[s,[d],again]), self.assertRaises(ValueError):
            L.status_receipts(self.head)
    def test_paused_publication_fails_before_api(self):
        with patch.dict(L.os.environ, {"GITHUB_REPOSITORY":L.a.REPO,"GITHUB_REF":"refs/heads/main",
                 "GITHUB_EVENT_NAME":"push","GASLUX_APP_STATUS_GATES_ENABLED":"true",
                 "GASLUX_AUTONOMY_PAUSED":"true"}, clear=True), patch.object(L.a,"api") as api:
            with self.assertRaises(ValueError):
                L.publish("safety")
            api.assert_not_called()
    def test_missing_pause_flag_fails_before_api(self):
        with patch.dict(L.os.environ, {"GITHUB_REPOSITORY":L.a.REPO,"GITHUB_REF":"refs/heads/main",
                 "GITHUB_EVENT_NAME":"push","GASLUX_APP_STATUS_GATES_ENABLED":"true"}, clear=True), patch.object(L.a,"api") as api:
            with self.assertRaises(ValueError):
                L.publish("owner")
            api.assert_not_called()

    def test_pilot_requires_explicit_flag_and_production_disabled(self):
        for env in ({}, {"GASLUX_STATUS_PILOT_ENABLED":"true","GASLUX_APP_STATUS_GATES_ENABLED":"true"}):
            with patch.dict(L.os.environ, env, clear=True), patch.object(L.lab,"context"), patch.object(L.a,"api") as api:
                with self.assertRaises(ValueError):
                    L.pilot_publish("safety")
                api.assert_not_called()

    def test_pilot_refuses_wrong_app(self):
        with patch.object(L,"pilot_context"), patch.object(L.gate,"review_app_actor",return_value=L.ACTORS["owner"]), patch.object(L.a,"api") as api:
            with self.assertRaises(ValueError):
                L.pilot_publish("safety")
            api.assert_not_called()

    def test_pilot_exact_write_and_receipt(self):
        kind="safety"
        live={"actor":L.ACTORS[kind],"type":"Bot","login":"gaslux-independent-safety[bot]",
              "state":"success","description":L.PILOT_DESCRIPTION,"id":17}
        result={"creator":{"id":L.ACTORS[kind]},"context":L.PILOT_CONTEXTS[kind],
                "state":"success","description":L.PILOT_DESCRIPTION,"id":17}
        with patch.object(L,"pilot_context"), patch.object(L.gate,"review_app_actor",return_value={"actor": L.ACTORS[kind], "app_id": 7000001, "slug": "gaslux-independent-safety"}), patch.object(L,"status_receipts",side_effect=[{}, {kind:live}]), patch.object(L.a,"api",return_value=result) as api:
            report=L.pilot_publish(kind)
            api.assert_called_once_with("POST","/statuses/"+L.lab.HEAD,{"context":L.PILOT_CONTEXTS[kind],"state":"success","description":L.PILOT_DESCRIPTION})
            self.assertFalse(report["merge_authorized"])
            self.assertFalse(report["production_gate_verified"])
            self.assertEqual(report["app_registration_id"], 7000001)
            self.assertNotIn(L.PILOT_CONTEXTS[kind],L.CONTEXTS.values())

    def test_pilot_audit_requires_both_real_issuers(self):
        with patch.object(L,"pilot_context"), patch.object(L,"status_receipts",return_value={"safety":{}}):
            with self.assertRaises(ValueError):
                L.pilot_audit()

    def test_pilot_retarget_or_closed_refused_before_write(self):
        with patch.dict(L.os.environ,{"GASLUX_STATUS_PILOT_ENABLED":"true"},clear=True), patch.object(L.lab,"context"), patch.object(L.lab,"actors",return_value=L.ACTORS), patch.object(L.lab,"candidate",return_value={"state":"closed"}), patch.object(L.a,"api") as api:
            with self.assertRaises(ValueError):
                L.pilot_publish("owner")
            api.assert_not_called()

    def test_activation_audit_is_not_merge_authority(self):
        with patch.object(L, "context"), patch.object(L.a, "api", return_value={"object": {"sha": self.base}}) as api, \
             patch.object(L.gate, "production_policy_observed", return_value=True), \
             patch.object(L.gate, "strict_ruleset_protected", return_value=True):
            report = L.activation_audit()
            self.assertTrue(report["main_and_target_policy_observed"])
            self.assertTrue(report["source_pinned_dev_policy_observed"])
            self.assertFalse(report["production_merge_authorized"])
            self.assertTrue(all(c.args[0] == "GET" for c in api.call_args_list))

    def test_exact_production_receipts_required_twice(self):
        valid = {kind: {"actor": L.ACTORS[kind], "type": "Bot",
                        "login": "gaslux-independent-" + kind + "[bot]", "state": "success",
                        "description": L.marker(42, "mint", self.base), "id": idx}
                 for idx, kind in enumerate(L.ROLES, 1)}
        for first, second, accepted in (
            (valid, valid, True),
            ({"safety": valid["safety"]}, valid, False),
            ({**valid, "owner": {**valid["owner"], "actor": L.ACTORS["safety"]}}, valid, False),
            ({**valid, "safety": {**valid["safety"], "description": L.PILOT_DESCRIPTION}}, valid, False),
            (valid, {**valid, "safety": {**valid["safety"], "state": "failure"}}, False),
            (valid, {**valid, "owner": {**valid["owner"], "id": 99}}, False),
        ):
            with patch.object(L, "frozen"), patch.object(L, "status_receipts", side_effect=[first, second]):
                self.assertEqual(L.gate.independent_status_receipts_verified(
                    42, "mint", self.head, self.base), accepted)

    def test_production_registration_not_lab_or_bot_id(self):
        for app_id in (5938492, 5938509, L.ACTORS["safety"], 15368, 0):
            with patch.object(L.gate, "review_app_actor", return_value={
                "actor": L.ACTORS["safety"], "slug": "gaslux-independent-safety", "app_id": app_id}):
                with self.assertRaises(ValueError):
                    L.app_registration("safety")
