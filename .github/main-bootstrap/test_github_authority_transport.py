import unittest
from unittest.mock import patch
import github_authority_transport as g

class TransportTests(unittest.TestCase):
    def test_unprovisioned_pins_deny_constructor(self):
        with self.assertRaisesRegex(ValueError,"deployment pins"): g.GitHubAuthority()
    def test_no_unsupported_head_or_payload(self):
        t=object.__new__(g.GitHubAuthority)
        with self.assertRaises(ValueError): t.publish("a"*40,{})
        h=g.v.ALLOW[436][0]
        with self.assertRaises(ValueError): t.publish(h,{"context":"wrong","state":"success","description":"x"})
    def test_no_inferred_settlement(self):
        t=object.__new__(g.GitHubAuthority)
        self.assertFalse(t.outbound_settled(g.v.ALLOW[436][0],"success"))
        self.assertFalse(t.outbound_settled(g.v.ALLOW[436][0],"failure"))
    def test_registration_and_scope(self):
        r={"id":g.a.APP,"slug":g.a.SLUG,"permissions":g.REGISTRATION}
        g.registration(r)
        with self.assertRaises(ValueError): g.registration({**r,"id":1})
        repo={"id":g.v.RID,"full_name":g.v.REPO}
        g.repository_scope({"total_count":1,"repositories":[repo]})
        with self.assertRaises(ValueError): g.repository_scope({"total_count":2,"repositories":[repo,repo]})
    def test_status_post_not_retried(self):
        t=object.__new__(g.GitHubAuthority)
        t.credential=lambda:"test-token"
        p={"context":g.v.CONTEXT,"state":"failure","description":"test"}
        h=g.v.ALLOW[436][0]
        with patch.object(g,"rest",side_effect=OSError("lost response")) as call:
            with self.assertRaises(OSError): t.publish(h,p)
            call.assert_called_once_with("POST",g.REPO_ROUTE+"/statuses/"+h,"test-token",p)
    def test_unknown_policy_denied(self):
        with self.assertRaisesRegex(ValueError,"policy changed"): g.validate_policy([],[])
    def test_redirect_denied(self):
        with self.assertRaisesRegex(ValueError,"redirect"): g.NoRedirect().redirect_request()
