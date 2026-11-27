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

    def test_exact_merged_chain_and_reject_wrong_tree(self):
        service=object.__new__(g.GitHubAuthority)
        service.credential=lambda:"test"
        h,tree,branch,pid=g.v.ALLOW[436]
        merged="d"*40
        repo={"id":g.v.RID}
        def fake(method,path,token):
            if path.endswith("/git/ref/heads/main"):
                return {"object":{"sha":merged,"type":"commit"}}
            if "/pulls/" in path:
                n=int(path.rsplit("/",1)[1])
                hh,tt,bb,ii=g.v.ALLOW[n]
                return {"number":n,"id":ii,"head":{"sha":hh,"ref":bb,"repo":repo},
                        "base":{"ref":"main","repo":repo},"state":"closed" if n==436 else "open",
                        "merged":n==436,"merge_commit_sha":merged if n==436 else None}
            return {"sha":merged,"parents":[{"sha":g.v.BASE},{"sha":h}],"tree":{"sha":tree}}
        with patch.object(g,"rest",side_effect=fake):
            self.assertEqual(service._merged_chain(),[{"pr":436,"head":h,"tree":tree,
                             "base":g.v.BASE,"merge":merged}])
        def wrong(method,path,token):
            row=fake(method,path,token)
            if "/git/commits/" in path: row["tree"]["sha"]="e"*40
            return row
        with patch.object(g,"rest",side_effect=wrong):
            with self.assertRaisesRegex(ValueError,"Wrong merged composition"): service._merged_chain()
