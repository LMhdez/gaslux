"""Reviewed hosted live-ref reader, separate from legacy SSH nonce transport.

The reader credential is read-only on the independently protected control
repository. No caller-provided snapshot or cached approval is trusted.
"""
import time
from pathlib import Path
import authority_anchor as anchor
import authority_contract as a
import hosted_safety as h
import main_bootstrap as v

ROOT=Path("/etc/gaslux-authority")
MAX_ELAPSED=15

class HostedClient:
    def __init__(self):
        key=ROOT/"safety-signing-public.pem"
        token=ROOT/"safety-control-read-token"
        anchor.checked_file(key)
        anchor.checked_file(token,True)
        self.pem=key.read_bytes()
        self.ledger=h.Ledger(token.read_text().strip(),self.pem)
    def read(self):
        start=time.monotonic()
        tip,count,states,last,active,consumed,incidents=self.ledger.snapshot_full()
        v.need(v.SHA.fullmatch(tip) and type(count) is int and 1<=count<=h.MAX_EVENTS
               and isinstance(last,str) and a.HEX64.fullmatch(last),"Invalid hosted ledger receipt")
        v.need(time.monotonic()-start<=MAX_ELAPSED,"Hosted ledger read expired")
        return tip,states,active,consumed,incidents
    def current(self,e):
        a.evidence_shape(e)
        _,states,active,consumed,incidents=self.read()
        if active is not None or incidents or e["head"] in consumed:
            return False
        row=states.get(e["head"])
        if row is None: return False
        v.need(row["evidence"]==e,"Hosted evidence mismatch")
        a.verify(e,row["decision"],row["signature_b64"],self.pem)
        return row["decision"]=="approve"
    def poll(self):
        _,states,_,_,_=self.read()
        entries=sorted(states.values(),key=lambda row:(row["decision"]!="withdraw",row["evidence"]["pr"]))
        for row in entries:
            a.verify(row["evidence"],row["decision"],row["signature_b64"],self.pem)
        return entries,self.pem
