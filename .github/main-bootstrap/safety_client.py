"""Concrete SSH client for fresh Safety queries. No endpoint provisioned."""
from pathlib import Path
import authority_anchor as anchor
import authority_contract as a
import main_bootstrap as v

SAFETY_HOST=None
SAFETY_USER=None
ROOT=Path("/etc/gaslux-authority")

class SafetyClient:
    def current_decision(self,e,nonce):
        a.evidence_shape(e)
        v.need(a.HEX64.fullmatch(nonce),"Invalid nonce")
        key=ROOT/"safety-signing-public.pem"
        anchor.checked_file(key)
        pem=key.read_bytes()
        ssh=anchor.SSH(SAFETY_HOST,SAFETY_USER,ROOT/"safety-query.key",
                       ROOT/"safety.known_hosts","gaslux-safety-query-v1")
        response=ssh.request({"evidence":e,"nonce":nonce})
        a.verify_current(e,nonce,response,pem)
        return response,pem
