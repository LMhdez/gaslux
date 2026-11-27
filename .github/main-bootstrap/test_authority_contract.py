import copy
import base64
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import authority_contract as a

class Fake:
    def __init__(self,e):
        self.e=e
        self.rows=[]
        self.writes=0
        self.uncertain=False
        self.fenced={'success':False,'failure':True}
        self.before_write=False
        self.drift_after=False
        self.readback_failure=False
        self.current_state="approved"
    def current_decision(self,e):
        return {"state":self.current_state,"evidence_sha256":a.v.digest(e),
                "decision_sha256":a.v.digest(a.v.decision_payload(e,"approve"))}
    def identity_proof(self):
        return {'repository_id':a.v.RID,'app':a.APP,'actor':a.ACTOR,'installation':a.INSTALLATION,'exclusive_writer':True}
    def outbound_settled(self,h,state):
        return self.fenced[state]
    def policy_proof(self):
        return {"repository_id":a.v.RID,"app":a.APP,"actor":a.ACTOR,
                "installation":a.INSTALLATION,"native_review_retained":True,
                "source_pinned_gate":True,"complete_actor_inventory":True,
                "exclusive_writer":True,"paused":True}
    def combined(self,h):
        return {"sha":h,"repository":{"id":a.v.RID},"total_count":int(bool(self.rows)),
                "statuses":copy.deepcopy(self.rows[:1])}
    def history(self,h):
        if self.readback_failure and self.writes:
            raise OSError('readback unavailable')
        return copy.deepcopy(self.rows)
    def snapshot(self,n):
        return copy.deepcopy(self.e)
    def publish(self,h,p):
        self.writes+=1
        if self.before_write:
            raise OSError('request in flight')
        row={**p,"id":100+self.writes,"creator":{"id":a.ACTOR,"login":a.SLUG+"[bot]","type":"Bot"},
             "created_at":str(self.writes),"updated_at":str(self.writes)}
        self.rows.insert(0,row)
        if self.drift_after:
            self.e={**self.e,'base':'c'*40}
        if self.uncertain:
            raise OSError("lost response after server write")
        return copy.deepcopy(row)

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/"journal.sqlite"
        self.j=a.Journal(self.path,initialize=True)
        self.addCleanup(self.j.close)
        h,t,b,pid=a.v.ALLOW[436]
        self.e={"schema":"gaslux-main-bootstrap-v1","repository":a.v.REPO,
                "repository_id":a.v.RID,"target":"main","pr":436,"pr_id":pid,
                "head":h,"tree":t,"base":a.v.BASE,"composition":"a"*40,
                "predecessors":[],"verifier":a.EVIDENCE_ENGINE,"draft":False,
                "ci":{"workflow":a.v.WORKFLOW,"run":1,"attempt":1,"job":2,"suite":3,
                      "base":a.v.BASE,"head":h,"tested_composition":"a"*40,
                      "job_log_sha256":"b"*64}}
        self.f=Fake(self.e)
    def call(self,decision,e=None):
        e=self.e if e is None else e
        with patch.object(a,"verify",side_effect=lambda e,d,s,p:a.v.digest(a.v.decision_payload(e,d))):
            return a.process(self.f,self.j,e,decision,"",b"")
    def test_evidence_binding(self):
        a.evidence_shape(self.e)
        for k,x in (("target","dev"),("head","c"*40),("tree","c"*40),("pr",437),
                    ("base","c"*40),("verifier","c"*40)):
            with self.assertRaises(ValueError):
                a.evidence_shape({**self.e,k:x})
    def test_signer_unprovisioned(self):
        with self.assertRaisesRegex(ValueError,"trust root"):
            a.verify(self.e,"approve","",b"")
    def test_approve_then_terminal_withdrawal(self):
        self.assertEqual(self.call("approve")["state"],"success")
        self.f.e={**self.e,"base":"c"*40}
        self.assertEqual(self.call("withdraw")["state"],"failure")
        self.assertEqual(self.j.row(self.e["head"])[3],"withdrawn")
        with self.assertRaises(ValueError): self.call("approve")
        self.assertEqual(self.f.writes,2)
    def test_approval_stale(self):
        self.f.e={**self.e,"base":"c"*40}
        with self.assertRaisesRegex(ValueError,"Stale"):
            self.call("approve")
        self.assertEqual(self.f.writes,0)
    def test_replay(self):
        self.call("approve")
        with self.assertRaises(ValueError): self.call("approve")
        self.assertEqual(self.f.writes,1)
    def test_withdraw_before_approval_is_terminal(self):
        self.assertEqual(self.call("withdraw")["state"],"failure")
        self.assertEqual(self.j.row(self.e["head"])[3],"withdrawn")
        with self.assertRaisesRegex(ValueError,"Terminal signed withdrawal"): self.call("approve")
        self.assertEqual([x["state"] for x in self.f.rows],["failure"])
        self.assertFalse(a.integration_permitted(self.f,self.j,self.e))
    def test_uncertain_write_recovery_and_withdrawal(self):
        self.f.uncertain=True
        with self.assertRaises(OSError): self.call("approve")
        self.assertEqual(self.j.row(self.e["head"])[3],"approval_posting")
        self.assertFalse(a.integration_permitted(self.f,self.j,self.e))
        self.f.uncertain=False
        self.assertEqual(self.call("withdraw")["state"],"failure")
        self.assertEqual(self.j.row(self.e["head"])[3],"withdrawn")
        self.assertEqual(self.f.writes,2)
    def test_durable_reservation_excludes_second_writer(self):
        self.j.reserve_approval(self.e,"a"*64)
        other=a.Journal(self.path)
        try:
            with self.assertRaises(ValueError): other.reserve_approval(self.e,"a"*64)
            self.assertEqual(other.row(self.e["head"])[3],"approval_reserved")
        finally: other.close()
    def test_wrong_issuer(self):
        self.call("approve")
        self.f.rows[0]["creator"]["id"]=42
        with self.assertRaisesRegex(ValueError,"issuer"): self.call("withdraw")
    def test_incomplete_history(self):
        self.call("approve")
        row=self.f.rows[0]
        self.f.rows=[{**row,"id":i} for i in range(100)]
        with self.assertRaisesRegex(ValueError,"Incomplete"): self.call("withdraw")
    def test_missing_policy(self):
        self.f.policy_proof=lambda:{"repository_id":a.v.RID,"app":a.APP,"actor":a.ACTOR,
            "installation":a.INSTALLATION,"native_review_retained":True,
            "source_pinned_gate":False,"complete_actor_inventory":True,
            "exclusive_writer":True,"paused":True}
        with self.assertRaisesRegex(ValueError,"Unproven"): self.call("approve")
        self.assertEqual(self.f.writes,0)

    def test_crash_before_post(self):
        d=a.v.digest(a.v.decision_payload(self.e,"approve"))
        self.j.reserve_approval(self.e,d)
        self.assertFalse(a.integration_permitted(self.f,self.j,self.e))
        self.assertEqual(self.call("withdraw")["state"],"failure")
        self.assertEqual([r["state"] for r in self.f.rows],["failure"])
    def test_lost_failure_response(self):
        self.call("approve")
        self.f.uncertain=True
        with self.assertRaises(OSError): self.call("withdraw")
        self.assertFalse(a.integration_permitted(self.f,self.j,self.e))
        self.f.uncertain=False
        self.assertEqual(self.call("withdraw")["state"],"failure")
        self.assertEqual(self.f.writes,2)
    def test_readback_failure_then_restart(self):
        self.f.readback_failure=True
        with self.assertRaises(OSError): self.call("approve")
        self.f.readback_failure=False
        other=a.Journal(self.path)
        try:
            with patch.object(a,"verify",side_effect=lambda e,d,s,p:a.v.digest(a.v.decision_payload(e,d))):
                self.assertEqual(a.process(self.f,other,self.e,"withdraw","",b"")["state"],"failure")
        finally: other.close()
    def test_crash_before_db_completion(self):
        with patch.object(self.j,"change",wraps=self.j.change) as c:
            original=self.j.change.__wrapped__ if hasattr(self.j.change,"__wrapped__") else c._mock_wraps
            def fail(head,old,new,**kw):
                if new=="approved": raise OSError("crash after readback")
                return original(head,old,new,**kw)
            c.side_effect=fail
            with self.assertRaises(OSError): self.call("approve")
        self.assertEqual(self.call("withdraw")["state"],"failure")
    def test_policy_drift_does_not_prevent_denial(self):
        self.call("approve")
        self.f.policy_proof=lambda: {}
        self.assertEqual(self.call("withdraw")["state"],"failure")
    def test_postpublication_drift_quarantine(self):
        self.f.drift_after=True
        with self.assertRaisesRegex(ValueError,"Postpublication drift"): self.call("approve")
        self.assertEqual(self.j.row(self.e["head"])[3],"quarantined")
        self.assertFalse(a.integration_permitted(self.f,self.j,self.e))
        self.assertEqual(self.call("withdraw")["state"],"failure")
    def test_delayed_success_never_acknowledged_without_fence(self):
        self.f.before_write=True
        with self.assertRaises(OSError): self.call("approve")
        self.f.before_write=False
        with self.assertRaisesRegex(ValueError,"delayed success"): self.call("withdraw")
        self.assertEqual(self.f.rows[0]["state"],"failure")
        self.assertFalse(a.integration_permitted(self.f,self.j,self.e))
        self.f.fenced["success"]=True
        self.assertEqual(self.call("withdraw")["state"],"failure")
        self.assertEqual(self.f.writes,2)
    def test_late_success_repaired_before_acknowledgment(self):
        self.f.before_write=True
        with self.assertRaises(OSError): self.call("approve")
        self.f.before_write=False
        with self.assertRaises(ValueError): self.call("withdraw")
        d=a.v.digest(a.v.decision_payload(self.e,"approve"))
        self.f.publish(self.e["head"],{"context":a.v.CONTEXT,"state":"success",
                                      "description":a.v.status_marker(self.e,d,"success")})
        self.assertFalse(a.integration_permitted(self.f,self.j,self.e))
        self.assertEqual(self.call("withdraw")["state"],"failure")
        self.assertEqual([x["state"] for x in self.f.rows],["failure","success","failure"])
        self.assertEqual(self.j.row(self.e["head"])[3],"withdrawn")
        self.assertFalse(a.integration_permitted(self.f,self.j,self.e))
    def test_concurrent_revoke_approve_lock(self):
        other=a.Journal(self.path)
        try:
            with self.j.exclusive():
                with patch.object(a,"verify",return_value="a"*64):
                    for d in ("approve","withdraw"):
                        with self.assertRaisesRegex(ValueError,"Writer already active"):
                            a.process(self.f,other,self.e,d,"",b"")
        finally: other.close()
    def test_real_ed25519(self):
        root=Path(self.tmp.name)
        key=root/"private"
        subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(key)],check=True)
        pem=subprocess.check_output(["openssl","pkey","-in",str(key),"-pubout"])
        (root/"msg").write_bytes(a.v.canonical(a.v.decision_payload(self.e,"approve")))
        sig=subprocess.check_output(["openssl","pkeyutl","-sign","-inkey",str(key),"-rawin","-in",str(root/"msg")])
        b64=base64.b64encode(sig).decode()
        with patch.object(a,"SIGNER_PEM_SHA256",hashlib.sha256(pem).hexdigest()):
            self.assertEqual(a.verify(self.e,"approve",b64,pem),a.v.digest(a.v.decision_payload(self.e,"approve")))
            for d,s,p in (("withdraw",b64,pem),("approve",base64.b64encode(b"0"*64).decode(),pem),
                          ("approve",b64,pem+b" ")):
                with self.assertRaises(ValueError): a.verify(self.e,d,s,p)
        subprocess.run(["openssl","genpkey","-algorithm","X25519","-out",str(key)],check=True)
        wrong=subprocess.check_output(["openssl","pkey","-in",str(key),"-pubout"])
        with patch.object(a,"SIGNER_PEM_SHA256",hashlib.sha256(wrong).hexdigest()):
            with self.assertRaisesRegex(ValueError,"Not an Ed25519"): a.verify(self.e,"approve",b64,wrong)

    def test_lost_repair_response(self):
        self.f.before_write=True
        with self.assertRaises(OSError): self.call("approve")
        self.f.before_write=False
        with self.assertRaises(ValueError): self.call("withdraw")
        d=a.v.digest(a.v.decision_payload(self.e,"approve"))
        self.f.publish(self.e["head"],{"context":a.v.CONTEXT,"state":"success",
                                      "description":a.v.status_marker(self.e,d,"success")})
        self.f.uncertain=True
        with self.assertRaises(OSError): self.call("withdraw")
        self.f.uncertain=False
        self.assertEqual(self.call("withdraw")["state"],"failure")
        self.assertEqual([x["state"] for x in self.f.rows],["failure","success","failure"])
    def test_no_blind_failure_retry(self):
        self.call("approve")
        self.f.before_write=True
        self.f.fenced["failure"]=False
        with self.assertRaises(OSError): self.call("withdraw")
        self.f.before_write=False
        with self.assertRaisesRegex(ValueError,"POST unresolved"): self.call("withdraw")
        self.f.fenced["failure"]=True
        self.assertEqual(self.call("withdraw")["state"],"failure")

    def test_lock_ownership_through_predicate(self):
        self.call("approve")
        other=a.Journal(self.path)
        try:
            with self.j.exclusive() as lease:
                self.assertTrue(a.integration_permitted_locked(self.f,self.j,self.e,lease))
                with self.assertRaises(ValueError):
                    a.integration_permitted_locked(self.f,other,self.e,lease)
                with self.assertRaises(ValueError):
                    with other.exclusive(): pass
            with self.assertRaisesRegex(ValueError,"Active writer lease"):
                a.integration_permitted_locked(self.f,self.j,self.e,lease)
        finally: other.close()

    def test_w_before_a_lost_response_restart(self):
        self.f.uncertain=True
        with self.assertRaises(OSError): self.call("withdraw")
        self.assertEqual(self.j.row(self.e["head"])[3],"withdrawal_posting")
        self.f.uncertain=False
        other=a.Journal(self.path)
        try:
            with patch.object(a,"verify",side_effect=lambda e,d,s,p:a.v.digest(a.v.decision_payload(e,d))):
                with self.assertRaisesRegex(ValueError,"Terminal"):
                    a.process(self.f,other,self.e,"approve","",b"")
                self.assertEqual(a.process(self.f,other,self.e,"withdraw","",b"")["state"],"failure")
        finally: other.close()
        self.assertEqual(self.f.writes,1)
    def test_denial_persisted_before_identity_failure(self):
        original=self.f.identity_proof
        self.f.identity_proof=lambda: {}
        with self.assertRaisesRegex(ValueError,"Unproven writer"): self.call("withdraw")
        self.assertIsNotNone(self.j.row(self.e["head"])[2])
        self.f.identity_proof=original
        with self.assertRaisesRegex(ValueError,"Terminal"): self.call("approve")
        self.assertEqual(self.f.writes,0)
        self.assertEqual(self.call("withdraw")["state"],"failure")
    def test_denial_survives_history_unavailable_for_existing_success(self):
        self.call("approve")
        self.f.readback_failure=True
        with self.assertRaises(OSError): self.call("withdraw")
        self.assertIsNotNone(self.j.row(self.e["head"])[2])
        self.f.readback_failure=False
        self.assertFalse(a.integration_permitted(self.f,self.j,self.e))
        with self.assertRaisesRegex(ValueError,"Terminal"): self.call("approve")
        self.assertEqual(self.call("withdraw")["state"],"failure")
    def test_invalid_withdraw_signature_creates_no_tombstone(self):
        with patch.object(a,"verify",side_effect=ValueError("bad signature")):
            with self.assertRaisesRegex(ValueError,"bad signature"):
                a.process(self.f,self.j,self.e,"withdraw","",b"")
        self.assertIsNone(self.j.row(self.e["head"]))
        self.assertEqual(self.f.writes,0)
    def test_withdraw_wrong_evidence_rejected(self):
        self.call("approve")
        with self.assertRaisesRegex(ValueError,"Different historical"):
            self.call("withdraw",{**self.e,"draft":True})
        self.assertIsNone(self.j.row(self.e["head"])[2])
    def test_no_implicit_journal_recreation(self):
        missing=self.path.parent/"missing.sqlite"
        with self.assertRaises(FileNotFoundError): a.Journal(missing)
        self.assertFalse(missing.exists())
        with self.assertRaises(FileExistsError): a.Journal(self.path,initialize=True)
        missing.touch(mode=0o600)
        with self.assertRaisesRegex(ValueError,"Missing or incompatible"): a.Journal(missing)
    def test_current_signer_revocation_blocks_stale_approval(self):
        self.f.current_state="withdrawn"
        with self.assertRaisesRegex(ValueError,"Stale"): self.call("approve")
        self.assertEqual(self.f.writes,0)
    def test_current_signer_revocation_blocks_integration(self):
        self.call("approve")
        self.f.current_state="withdrawn"
        self.assertFalse(a.integration_permitted(self.f,self.j,self.e))
    def test_concurrent_delivery_respects_denial(self):
        other=a.Journal(self.path)
        try:
            with self.j.exclusive():
                d=a.v.digest(a.v.decision_payload(self.e,"withdraw"))
                self.j.reserve_denial(self.e,d)
                with patch.object(a,"verify",return_value=a.v.digest(a.v.decision_payload(self.e,"approve"))):
                    with self.assertRaisesRegex(ValueError,"Writer already active"):
                        a.process(self.f,other,self.e,"approve","",b"")
            with self.assertRaisesRegex(ValueError,"Terminal"): self.call("approve")
            self.assertEqual(self.call("withdraw")["state"],"failure")
        finally: other.close()
