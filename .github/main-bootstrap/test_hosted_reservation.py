import unittest
import hosted_safety as h
import authority_contract as a
import safety_signer as signer
import test_hosted_safety as fixtures

class ReservationTests(unittest.TestCase):
    def setUp(self):
        self.fx=fixtures.HostedTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.e=self.fx.e
        self.pem=self.fx.pem
        self.rid="f"*64
    def chain(self,*events):
        records=self.fx.records("approve")
        for value in events:
            i=len(records)
            parent=f"{i:040x}"
            last=a.v.digest(records[-1][1]["payload"])
            row=self.fx.entry(value) if value in ("approve","withdraw") else {
                "operation":value,"evidence":self.e,"reservation":self.rid,
                "receipt":({"pr":self.e["pr"],"head":self.e["head"],"base":self.e["base"],
                            "tree":self.e["tree"],"merge":"e"*40} if value=="merge_confirmed" else None)}
            records.append((parent,self.fx.envelope(i,parent,last,row)))
        return records
    def test_reservation_then_withdraw_cancels_before_post(self):
        records=self.chain("reserve_merge","withdraw")
        states,_,active,consumed,incidents=h.replay_full(records,self.pem)
        self.assertIsNone(active)
        self.assertEqual(states[self.e["head"]]["decision"],"withdraw")
        self.assertFalse(consumed)
        self.assertFalse(incidents)
        with self.assertRaisesRegex(ValueError,"Unknown merge reservation"):
            h.replay_full(self.chain("reserve_merge","withdraw","merge_posting"),self.pem)
    def test_withdraw_after_posting_retains_unresolved(self):
        states,_,active,_,_=h.replay_full(self.chain("reserve_merge","merge_posting","withdraw"),self.pem)
        self.assertEqual(active["phase"],"posting")
        self.assertEqual(states[self.e["head"]]["decision"],"withdraw")
        with self.assertRaisesRegex(ValueError,"Cannot abort"):
            h.replay_full(self.chain("reserve_merge","merge_posting","withdraw","merge_aborted"),self.pem)
    def test_late_merge_after_withdrawal_is_incident(self):
        _,_,active,consumed,incidents=h.replay_full(
            self.chain("reserve_merge","merge_posting","withdraw","merge_confirmed"),self.pem)
        self.assertIsNone(active)
        self.assertIn(self.e["head"],consumed)
        self.assertEqual(incidents[0]["head"],self.e["head"])
        with self.assertRaisesRegex(ValueError,"Reservation unavailable"):
            h.replay_full(self.chain("reserve_merge","merge_posting","withdraw","merge_confirmed","reserve_merge"),self.pem)
    def test_merge_consumed_and_no_second_reservation(self):
        _,_,active,consumed,incidents=h.replay_full(
            self.chain("reserve_merge","merge_posting","merge_confirmed"),self.pem)
        self.assertIsNone(active)
        self.assertIn(self.e["head"],consumed)
        self.assertFalse(incidents)
        with self.assertRaisesRegex(ValueError,"Reservation unavailable"):
            h.replay_full(self.chain("reserve_merge","merge_posting","merge_confirmed","reserve_merge"),self.pem)
    def test_duplicate_posting_and_reused_reservation_rejected(self):
        with self.assertRaisesRegex(ValueError,"not reserved"):
            h.replay_full(self.chain("reserve_merge","merge_posting","merge_posting"),self.pem)
        with self.assertRaisesRegex(ValueError,"Reservation unavailable"):
            h.replay_full(self.chain("reserve_merge","merge_aborted","reserve_merge"),self.pem)
    def test_wrong_merge_tree_rejected(self):
        row={"operation":"merge_confirmed","evidence":self.e,"reservation":self.rid,
             "receipt":{"pr":self.e["pr"],"head":self.e["head"],"base":self.e["base"],
                        "tree":"0"*40,"merge":"e"*40}}
        with self.assertRaisesRegex(ValueError,"Wrong merge receipt"): h.validate_operation(row)
