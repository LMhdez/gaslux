"""Nonce-bound feed of retained signed decisions, bounded to bootstrap PRs.

Withdrawals are retained, not deleted after delivery. Polling restarts safely.
No private key or policy is accepted from a feed requester.
"""
import json
import authority_contract as a
import main_bootstrap as v

def payload(nonce,entries):
    v.need(isinstance(nonce,str) and a.HEX64.fullmatch(nonce),"Invalid feed nonce")
    v.need(type(entries) is list and len(entries)<=len(v.ALLOW),"Invalid feed size")
    heads=set()
    for row in entries:
        v.need(type(row) is dict and set(row)=={"evidence","decision","signature_b64"},"Invalid feed entry")
        e=row["evidence"]
        a.evidence_shape(e)
        v.need(e["head"] not in heads and row["decision"] in ("approve","withdraw")
               and isinstance(row["signature_b64"],str),"Invalid feed decision")
        heads.add(e["head"])
    return {"schema":"gaslux-safety-feed-v1","repository_id":v.RID,"nonce":nonce,"entries":entries}

def verify(nonce,response,pem):
    v.need(type(response) is dict and set(response)=={"payload","signature_b64"},
           "Invalid feed response")
    p=response["payload"]
    v.need(p==payload(nonce,p["entries"]),"Feed binding mismatch")
    a.verify_bytes(v.canonical(p),response["signature_b64"],pem)
    for row in p["entries"]:
        a.verify(row["evidence"],row["decision"],row["signature_b64"],pem)
    return sorted(p["entries"],key=lambda row:(row["decision"]!="withdraw",row["evidence"]["pr"]))
