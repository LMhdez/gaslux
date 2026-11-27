import unittest
import credential_audit as a
class CredentialTests(unittest.TestCase):
    def test_registration(self):
        row={"id":a.APP,"slug":a.SLUG,"permissions":dict(a.EXPECTED)}
        a.registration(row)
        for p in ({"contents":"write"},{"pull_requests":"write"},{"statuses":"read"},{"administration":"write"}):
            with self.assertRaises(ValueError):
                a.registration({**row,"permissions":{**row["permissions"],**p}})
    def test_identity(self):
        with self.assertRaises(ValueError):
            a.registration({"id":1,"slug":a.SLUG,"permissions":a.EXPECTED})
    def test_scope(self):
        row={"id":a.v.RID,"full_name":a.v.REPO}
        a.installation({"total_count":1,"repositories":[row]})
        for rows in ([row,row],[{"id":1,"full_name":"other/repo"}],[]):
            with self.assertRaises(ValueError):
                a.installation({"total_count":len(rows),"repositories":rows})
