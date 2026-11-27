"""Hosted Safety append-only signed ledger (bootstrap only, no deployed pins).

Only the isolated hosted signer may append. Pi has read-only control-repo
access. The GitHub admin is explicitly trusted. No async nonce emulation:
the reader validates signed history and current authenticated live ref.
Use as a merge authorization source only after independent review.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import time
import authority_contract as a
import authority_anchor as anchor
import github_witness as gw
import main_bootstrap as v
import safety_signer as signer

CONTROL_REPO=None
CONTROL_ID=None
LEDGER_RULE=None
LEDGER_GENESIS=None
BRANCH="ledger/safety"
MAX_EVENTS=128
ROOT=Path("/etc/gaslux-authority")
SCHEMA="gaslux-hosted-safety-v1"
ACTIONS_CONTROL_SHA=None

def pins():
    v.need(isinstance(CONTROL_REPO,str) and
           re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",CONTROL_REPO)
           and CONTROL_REPO.casefold()!=v.REPO.casefold()
           and type(CONTROL_ID) is int and CONTROL_ID>0 and CONTROL_ID!=v.RID
           and type(LEDGER_RULE) is int and LEDGER_RULE>0
           and isinstance(LEDGER_GENESIS,str) and v.SHA.fullmatch(LEDGER_GENESIS)
           and isinstance(a.SIGNER_PEM_SHA256,str) and a.HEX64.fullmatch(a.SIGNER_PEM_SHA256),
           "Hosted Safety deployment pins absent")

def rule_check(row):
    v.need(row["id"]==LEDGER_RULE and row["source"]==CONTROL_REPO
           and row["source_type"]=="Repository" and row["target"]=="branch"
           and row["enforcement"]=="active" and row.get("bypass_actors")==[]
           and row["conditions"]=={"ref_name":{"include":["refs/heads/"+BRANCH],"exclude":[]}}
           and len(row["rules"])==2 and {x["type"] for x in row["rules"]}==
               {"deletion","non_fast_forward"} and all(not x.get("parameters") for x in row["rules"]),
           "Hosted ledger protection drift")

def event(seq,parent,previous,entry):
    v.need(type(seq) is int and 0<=seq<MAX_EVENTS and isinstance(parent,str) and v.SHA.fullmatch(parent)
           and ((seq==0 and previous is None and entry is None) or
                (seq>0 and isinstance(previous,str) and a.HEX64.fullmatch(previous)
                 and type(entry) is dict)),"Invalid hosted ledger event")
    if entry is not None:
        v.need(set(entry)=={"evidence","decision","signature_b64"} and
               entry["decision"] in ("approve","withdraw"),"Invalid hosted decision")
        a.evidence_shape(entry["evidence"])
    return {"schema":SCHEMA,"repository_id":v.RID,"control_repository_id":CONTROL_ID,
            "sequence":seq,"parent":parent,"previous":previous,"entry":entry}

def replay(records,pem):
    """Validate transitions, including permanent terminal withdrawal."""
    states={}
    previous=None
    for i,(parent,envelope) in enumerate(records):
        v.need(type(envelope) is dict and set(envelope)=={"payload","signature_b64"},"Invalid ledger envelope")
        p=envelope["payload"]
        v.need(p==event(i,parent,previous,p["entry"]),"Hosted ledger sequence mismatch")
        a.verify_bytes(v.canonical(p),envelope["signature_b64"],pem)
        row=p["entry"]
        if row:
            e,d,sig=row["evidence"],row["decision"],row["signature_b64"]
            a.verify(e,d,sig,pem)
            h=e["head"]
            prior=states.get(h)
            if d=="approve":
                v.need(prior is None,"Duplicate or terminal approval")
            else:
                v.need(prior is not None and prior["decision"]=="approve" and
                       prior["evidence"]==e,"Unknown or duplicate withdrawal")
            states[h]=row
        previous=v.digest(p)
    return states,previous

class Ledger:
    def __init__(self,token,pem):
        pins()
        v.need(isinstance(token,str) and token and isinstance(pem,bytes) and
               hashlib.sha256(pem).hexdigest()==a.SIGNER_PEM_SHA256,"Wrong ledger credential/key")
        self.token=token
        self.pem=pem
        self.cache={}
    def api(self,method,path,payload=None):
        return gw.request(method,"/repos/"+CONTROL_REPO+path,self.token,payload)
    def policy(self):
        repo=self.api("GET","")
        v.need(repo["id"]==CONTROL_ID and repo["full_name"]==CONTROL_REPO and
               repo["private"] is True and repo["fork"] is False,"Wrong control repository")
        rule_check(self.api("GET","/rulesets/"+str(LEDGER_RULE)))
        effective=self.api("GET","/rules/branches/ledger%2Fsafety?per_page=100")
        hits=[x for x in effective if x["ruleset_id"]==LEDGER_RULE]
        v.need(type(effective) is list and len(effective)<100 and len(hits)==2 and
               {x["type"] for x in hits}=={"deletion","non_fast_forward"} and
               all(x["ruleset_source"]==CONTROL_REPO and x["ruleset_source_type"]=="Repository" for x in hits),
               "Hosted ledger protection not effective")
    def head(self):
        ref=self.api("GET","/git/ref/heads/"+BRANCH)
        v.need(ref["ref"]=="refs/heads/"+BRANCH and ref["object"]["type"]=="commit"
               and v.SHA.fullmatch(ref["object"]["sha"]),"Invalid hosted ledger ref")
        return ref["object"]["sha"]
    def read(self,sha):
        if sha in self.cache: return self.cache[sha]
        c=self.api("GET","/git/commits/"+sha)
        v.need(c["sha"]==sha and len(c["parents"])==1 and
               v.SHA.fullmatch(c["parents"][0]["sha"]) and v.SHA.fullmatch(c["tree"]["sha"]),
               "Invalid hosted ledger commit")
        tree=self.api("GET","/git/trees/"+c["tree"]["sha"])
        v.need(tree["sha"]==c["tree"]["sha"] and tree["truncated"] is False and
               len(tree["tree"])==1,"Invalid hosted ledger tree")
        f=tree["tree"][0]
        v.need(f["path"]=="decision.json" and f["mode"]=="100644" and f["type"]=="blob"
               and v.SHA.fullmatch(f["sha"]),"Wrong hosted decision file")
        b=self.api("GET","/git/blobs/"+f["sha"])
        v.need(b["sha"]==f["sha"] and b["encoding"]=="base64","Wrong decision blob")
        raw=base64.b64decode("".join(b["content"].split()),validate=True)
        v.need(0<len(raw)<=65536 and b["size"]==len(raw) and
               hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==f["sha"],
               "Decision blob digest mismatch")
        envelope=signer.strict_json(raw)
        v.need(v.canonical(envelope)==raw,"Noncanonical signed ledger event")
        result=(c["parents"][0]["sha"],envelope)
        self.cache[sha]=result
        return result
    def snapshot(self):
        self.policy()
        head=self.head()
        sha=head
        records=[]
        seen=set()
        for _ in range(MAX_EVENTS):
            v.need(sha not in seen,"Hosted ledger cycle")
            seen.add(sha)
            parent,envelope=self.read(sha)
            records.append((parent,envelope))
            if sha==LEDGER_GENESIS: break
            sha=parent
        v.need(sha==LEDGER_GENESIS,"Missing pinned hosted genesis")
        records.reverse()
        states,last=replay(records,self.pem)
        self.policy()
        v.need(self.head()==head,"Hosted ledger changed during read")
        return head,len(records),states,last
    def current(self,e):
        a.evidence_shape(e)
        head,_,states,_=self.snapshot()
        row=states.get(e["head"])
        if row is None: return head,"unknown"
        v.need(row["evidence"]==e,"Hosted ledger evidence drift")
        return head,"approved" if row["decision"]=="approve" else "withdrawn"
    def retained(self):
        head,_,states,_=self.snapshot()
        return head,sorted(states.values(),key=lambda r:(r["decision"]!="withdraw",r["evidence"]["pr"]))

class HostedWriter(Ledger):
    def __init__(self,token,key):
        super().__init__(token,signer.public_pem(key))
        self.key=key
    def append(self,e,decision):
        """Caller must be protected independent evaluator. No signing API."""
        a.evidence_shape(e)
        v.need(decision in ("approve","withdraw"),"Invalid decision")
        head,seq,states,last=self.snapshot()
        existing=states.get(e["head"])
        if existing is not None:
            v.need(existing["evidence"]==e,"Different historical evidence")
            if existing["decision"]==decision:
                return head,existing
            v.need(existing["decision"]=="approve" and decision=="withdraw","Terminal withdrawal")
        else:
            v.need(decision=="approve","No historical approval")
        entry={"evidence":e,"decision":decision,
               "signature_b64":signer.sign_bytes(self.key,v.canonical(v.decision_payload(e,decision)))}
        value=event(seq,head,last,entry)
        envelope={"payload":value,"signature_b64":signer.sign_bytes(self.key,v.canonical(value))}
        raw=v.canonical(envelope)
        blob=self.api("POST","/git/blobs",{"encoding":"base64","content":base64.b64encode(raw).decode()})
        v.need(v.SHA.fullmatch(blob["sha"]),"Wrong created blob")
        tree=self.api("POST","/git/trees",{"tree":[{"path":"decision.json","mode":"100644",
                                                    "type":"blob","sha":blob["sha"]}]})
        v.need(v.SHA.fullmatch(tree["sha"]),"Wrong created tree")
        commit=self.api("POST","/git/commits",{"message":"GASLUX Safety ledger "+str(seq),
                                             "tree":tree["sha"],"parents":[head]})
        new=commit["sha"]
        v.need(v.SHA.fullmatch(new) and self.read(new)==(head,envelope),"Created ledger mismatch")
        self.policy()
        v.need(self.head()==head,"Hosted ledger CAS conflict")
        receipt=self.api("PATCH","/git/refs/heads/"+BRANCH,{"sha":new,"force":False})
        v.need(receipt["ref"]=="refs/heads/"+BRANCH and receipt["object"]["sha"]==new
               and receipt["object"]["type"]=="commit","Ledger update receipt mismatch")
        tip,count,after,digest=self.snapshot()
        v.need(tip==new and count==seq+1 and digest==v.digest(value) and
               after=={**states,e["head"]:entry},"Hosted ledger write unconfirmed")
        return tip,entry
