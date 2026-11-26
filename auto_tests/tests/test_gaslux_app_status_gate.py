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
