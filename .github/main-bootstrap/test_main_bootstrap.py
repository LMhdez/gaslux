import base64
import copy
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import main_bootstrap as A

class Contracts(unittest.TestCase):
    def setUp(self):
        self.e = {"pr":436,"base":"a"*40,"head":"b"*40,"tree":"c"*40,"verifier":"d"*40}
        self.a = A.digest(A.decision_payload(self.e,"approve"))
        self.w = A.digest(A.decision_payload(self.e,"withdraw"))
    def test_bindings(self):
        for k in self.e:
            x = dict(self.e)
            x[k] = 437 if k=="pr" else "e"*40
            self.assertNotEqual(self.a,A.digest(A.decision_payload(x,"approve")))
        self.assertNotEqual(self.a,self.w)
    def test_marker_length(self):
        self.assertLessEqual(len(A.status_marker(self.e,self.a,"success")),140)
    def test_unconfigured_key_denied(self):
        with self.assertRaisesRegex(ValueError,"trust root"):
            A.verify_signed_decision(self.e,"approve","",b"fake")
    def test_real_signature(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(root/"key")],check=True)
            pem=subprocess.check_output(["openssl","pkey","-in",str(root/"key"),"-pubout"])
            (root/"msg").write_bytes(A.canonical(A.decision_payload(self.e,"approve")))
            sig=subprocess.check_output(["openssl","pkeyutl","-sign","-inkey",str(root/"key"),
                                        "-rawin","-in",str(root/"msg")])
            with patch.object(A,"SAFETY_KEY_SHA256",hashlib.sha256(pem).hexdigest()):
                b64=base64.b64encode(sig).decode()
                self.assertEqual(A.verify_signed_decision(self.e,"approve",b64,pem),self.a)
                with self.assertRaises(ValueError):
                    A.verify_signed_decision({**self.e,"pr":437},"approve",b64,pem)
                with self.assertRaises(ValueError):
                    A.verify_signed_decision(self.e,"withdraw",b64,pem)
                with self.assertRaises(ValueError):
                    A.verify_signed_decision(self.e,"approve",b64,pem+b" ")
    def row(self,state,actor=42,i=1):
        return {"id":i,"context":A.CONTEXT,"creator":{"id":actor,"type":"Bot"},"state":state,
                "description":A.status_marker(self.e,self.a if state=="success" else self.w,state)}
    def transition(self,rows,state):
        return A.validate_transition(rows,self.e,self.a,self.w,state,42)
    def test_replay(self):
        self.assertTrue(self.transition([],"success"))
        with self.assertRaises(ValueError): self.transition([self.row("success")],"success")
    def test_wrong_issuer(self):
        with self.assertRaises(ValueError): self.transition([self.row("success",43)],"failure")
    def test_terminal(self):
        rows=[self.row("failure",i=2),self.row("success")]
        for seq in (rows,rows[::-1]):
            with self.assertRaises(ValueError): self.transition(seq,"success")
        self.assertTrue(self.transition([self.row("success")],"failure"))
    def test_incomplete_history(self):
        with self.assertRaises(ValueError): self.transition([self.row("success")]*100,"failure")
