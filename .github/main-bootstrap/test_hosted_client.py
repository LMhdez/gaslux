import time
import unittest
from unittest.mock import patch
import authority_contract as a
import hosted_client as c
import hosted_safety as h
import safety_signer as signer
import test_authority_contract as fixtures

class HostedClientTests(unittest.TestCase):
    def setUp(self):
        self.fx=fixtures.Tests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.e=self.fx.e
        self.client=object.__new__(c.HostedClient)
        self.client.pem=self.fx.f.pem
        self.client.ledger=object.__new__(h.Ledger)
    def row(self,d):
        return {"evidence":self.e,"decision":d,"signature_b64":
                signer.sign_bytes(self.fx.f.key,a.v.canonical(a.v.decision_payload(self.e,d)))}
    def snap(self,d):
        return ("d"*40,2,{self.e["head"]:self.row(d)},"e"*64,None,set(),[])
    def test_live_state_rechecked_no_cached_approval(self):
        with patch.object(self.client.ledger,"snapshot_full",side_effect=[self.snap("approve"),self.snap("withdraw")]) as call:
            self.assertTrue(self.client.current(self.e))
            self.assertFalse(self.client.current(self.e))
            self.assertEqual(call.call_count,2)
    def test_ledger_error_and_timeout_fail_closed(self):
        with patch.object(self.client.ledger,"snapshot_full",side_effect=OSError("unavailable")):
            with self.assertRaises(OSError): self.client.current(self.e)
        with patch.object(self.client.ledger,"snapshot_full",return_value=self.snap("approve")), \
             patch.object(c.time,"monotonic",side_effect=[0,16]):
            with self.assertRaisesRegex(ValueError,"expired"): self.client.current(self.e)
    def test_invalid_signed_row_rejected(self):
        snap=self.snap("approve")
        snap[2][self.e["head"]]["signature_b64"]="A"*88
        with patch.object(self.client.ledger,"snapshot_full",return_value=snap):
            with self.assertRaises(ValueError): self.client.current(self.e)
    def test_retained_feed_validates_withdrawal(self):
        with patch.object(self.client.ledger,"snapshot_full",return_value=self.snap("withdraw")):
            entries,pem=self.client.poll()
            self.assertEqual(entries,[self.row("withdraw")])
            self.assertEqual(pem,self.client.pem)
    def test_backend_not_duck_typed(self):
        self.fx.f.hosted_safety=object()
        self.assertFalse(a.eligible(self.fx.f,self.e))

    def test_reservation_blocks_approval_but_retains_denial_feed(self):
        snap=self.snap("withdraw")
        active={"evidence":self.e,"reservation":"f"*64,"phase":"posting"}
        active_snapshot=(*snap[:4],active,set(),[])
        with patch.object(self.client.ledger,"snapshot_full",return_value=active_snapshot):
            self.assertFalse(self.client.current(self.e))
            self.assertEqual(self.client.poll()[0],[self.row("withdraw")])
        positive=self.snap("approve")
        with patch.object(self.client.ledger,"snapshot_full",return_value=(*positive[:4],active,set(),[])):
            self.assertFalse(self.client.current(self.e))
