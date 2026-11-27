"""Optional GitHub witness for Pi-only deployments; no live pins provisioned.

The GitHub repository must be private, separately governed, and fast-forward
only. The full protected history is the external checkpoint, not a mutable
file or an Actions artifact. This is NOT protection against a repository
administrator who can remove its rules. No production code selects it until
a reviewed deployment explicitly chooses this backend.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import urllib.request
import authority_anchor as anchor
import main_bootstrap as v

REPOSITORY=None
REPOSITORY_ID=None
RULE_ID=None
GENESIS={"signer":None,"publisher":None}
ROOT=Path("/etc/gaslux-authority")
BRANCH={"signer":"ledger/signer","publisher":"ledger/publisher"}
SCHEMA="gaslux-github-witness-v1"
MAX_EVENTS=256
MAX_BODY=262144

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise ValueError("Unexpected witness redirect")

def request(method,path,token,payload=None):
    v.need(method in ("GET","POST","PATCH") and path.startswith("/repos/")
           and "://" not in path and ".." not in path and not any(c.isspace() for c in path),
           "Invalid witness route")
    v.need(isinstance(token,str) and token and not any(c.isspace() for c in token),
           "Invalid witness credential")
    v.need((method=="GET" and payload is None) or
           (method!="GET" and type(payload) is dict),"Invalid witness request body")
    req=urllib.request.Request("https://api.github.com"+path,
        data=None if payload is None else v.canonical(payload),method=method,
        headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
                 "Content-Type":"application/json","X-GitHub-Api-Version":"2022-11-28"})
    # No redirect or retry, including ambiguous PATCH.
    with urllib.request.build_opener(NoRedirect()).open(req,timeout=20) as response:
        raw=response.read(MAX_BODY+1)
        v.need(len(raw)<=MAX_BODY and 'rel="next"' not in response.headers.get("Link",""),
               "Incomplete witness response")
        return json.loads(raw)

def event(role,sequence,previous,digest):
    v.need(role in BRANCH and type(sequence) is int and 0<=sequence<MAX_EVENTS
           and isinstance(digest,str) and anchor.HEX.fullmatch(digest)
           and ((sequence==0 and previous is None) or
                (sequence>0 and isinstance(previous,str) and anchor.HEX.fullmatch(previous))),
           "Invalid checkpoint event")
    return {"schema":SCHEMA,"production_repository_id":v.RID,"witness_repository_id":REPOSITORY_ID,
            "role":role,"sequence":sequence,"previous":previous,"digest":digest}

def validate_rule(rule,repo):
    v.need(rule["id"]==RULE_ID and rule["source"]==repo and rule["source_type"]=="Repository"
           and rule["target"]=="branch" and rule["enforcement"]=="active"
           and rule["conditions"]=={"ref_name":{"include":sorted("refs/heads/"+x for x in BRANCH.values()),
                                               "exclude":[]}}
           and rule.get("bypass_actors")==[]
           and len(rule["rules"])==2 and {x["type"] for x in rule["rules"]}==
               {"deletion","non_fast_forward"} and all(not x.get("parameters") for x in rule["rules"]),
           "Incomplete or weakened witness ruleset")

class GitWitness:
    def __init__(self,role):
        v.need(role in BRANCH and isinstance(REPOSITORY,str) and
               re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",REPOSITORY)
               and REPOSITORY.casefold()!=v.REPO.casefold() and
               type(REPOSITORY_ID) is int and REPOSITORY_ID>0 and REPOSITORY_ID!=v.RID
               and type(RULE_ID) is int and RULE_ID>0
               and all(isinstance(GENESIS.get(k),str) and v.SHA.fullmatch(GENESIS[k])
                       for k in BRANCH),"GitHub witness deployment pins not provisioned")
        self.role=role
        self.repo="/repos/"+REPOSITORY
        self.branch=BRANCH[role]
        self.genesis=GENESIS[role]
        self.cache={}
    def token(self):
        # Fine-grained Contents write + Administration read, not admin-write,
        # scoped only to witness repository, role token separate from other roles.
        path=ROOT/(self.role+"-github-witness-token")
        anchor.checked_file(path,True)
        return path.read_text().strip()
    def api(self,method,path,payload=None):
        return request(method,self.repo+path,self.token(),payload)
    def policy(self):
        repo=self.api("GET","")
        v.need(repo["id"]==REPOSITORY_ID and repo["full_name"]==REPOSITORY and
               repo["private"] is True and repo["fork"] is False,"Wrong witness repository")
        rule=self.api("GET","/rulesets/"+str(RULE_ID))
        # The API may hide bypass actors from underprivileged tokens; deny.
        # GitHub may return the branch order differently, normalize only order.
        rule=json.loads(json.dumps(rule))
        rule["conditions"]["ref_name"]["include"].sort()
        validate_rule(rule,REPOSITORY)
        effective=self.api("GET","/rules/branches/"+self.branch.replace("/","%2F")+"?per_page=100")
        hits=[x for x in effective if x["ruleset_id"]==RULE_ID]
        v.need(type(effective) is list and len(effective)<100 and len(hits)==2 and
               {x["type"] for x in hits}=={"deletion","non_fast_forward"} and
               all(x["ruleset_source"]==REPOSITORY and x["ruleset_source_type"]=="Repository" for x in hits),
               "Witness protection not effective")
    def head(self):
        row=self.api("GET","/git/ref/heads/"+self.branch)
        v.need(row["ref"]=="refs/heads/"+self.branch and row["object"]["type"]=="commit"
               and v.SHA.fullmatch(row["object"]["sha"]),"Wrong witness ref")
        return row["object"]["sha"]
    def read_commit(self,sha):
        if sha in self.cache: return self.cache[sha]
        row=self.api("GET","/git/commits/"+sha)
        v.need(row["sha"]==sha and v.SHA.fullmatch(row["tree"]["sha"]) and
               len(row["parents"])==1 and v.SHA.fullmatch(row["parents"][0]["sha"]),
               "Invalid witness commit")
        tree=self.api("GET","/git/trees/"+row["tree"]["sha"])
        v.need(tree["sha"]==row["tree"]["sha"] and tree["truncated"] is False and
               len(tree["tree"])==1,"Unexpected witness tree")
        f=tree["tree"][0]
        v.need(f["path"]=="checkpoint.json" and f["type"]=="blob" and f["mode"]=="100644"
               and v.SHA.fullmatch(f["sha"]),"Unexpected witness checkpoint")
        blob=self.api("GET","/git/blobs/"+f["sha"])
        v.need(blob["sha"]==f["sha"] and blob["encoding"]=="base64","Wrong witness blob")
        raw=base64.b64decode("".join(blob["content"].split()),validate=True)
        git_sha=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\x00"+raw).hexdigest()
        v.need(len(raw)<=4096 and blob["size"]==len(raw) and git_sha==f["sha"],
               "Witness blob mismatch")
        value=json.loads(raw)
        v.need(value==event(self.role,value["sequence"],value["previous"],value["digest"])
               and raw==v.canonical(value),"Witness event mismatch")
        result=(row["parents"][0]["sha"],value)
        self.cache[sha]=result
        return result
    def snapshot(self):
        self.policy()
        head=self.head()
        sha=head
        seen=set()
        digests=set()
        records=[]
        for _ in range(MAX_EVENTS):
            v.need(sha not in seen,"Witness ancestry cycle")
            seen.add(sha)
            parent,value=self.read_commit(sha)
            v.need(value["digest"] not in digests,"Checkpoint rollback/reuse")
            digests.add(value["digest"])
            records.append(value)
            if sha==self.genesis:
                break
            sha=parent
        v.need(sha==self.genesis,"Missing pinned witness genesis")
        ordered=list(reversed(records))
        v.need(all(row["sequence"]==i and row["previous"]==(None if i==0 else ordered[i-1]["digest"])
                   for i,row in enumerate(ordered)),"Witness sequence drift")
        self.policy()
        v.need(self.head()==head,"Witness changed during read")
        return head,ordered
    def assert_state(self,digest):
        _,rows=self.snapshot()
        v.need(rows[-1]["digest"]==digest,"External checkpoint mismatch")
    def advance(self,before,after):
        head,rows=self.snapshot()
        v.need(rows[-1]["digest"]==before,"External checkpoint mismatch")
        if before==after: return
        v.need(after not in {x["digest"] for x in rows},"Checkpoint rollback/reuse")
        value=event(self.role,len(rows),before,after)
        blob=self.api("POST","/git/blobs",{"content":base64.b64encode(v.canonical(value)).decode("ascii"),
                                           "encoding":"base64"})
        v.need(v.SHA.fullmatch(blob["sha"]),"Invalid created witness blob")
        tree=self.api("POST","/git/trees",{"tree":[{"path":"checkpoint.json","mode":"100644",
                                                    "type":"blob","sha":blob["sha"]}]})
        v.need(v.SHA.fullmatch(tree["sha"]),"Invalid created witness tree")
        commit=self.api("POST","/git/commits",{"message":"GASLUX checkpoint "+self.role+" "+str(len(rows)),
                                             "tree":tree["sha"],"parents":[head]})
        new=commit["sha"]
        v.need(v.SHA.fullmatch(new) and self.read_commit(new)==(head,value),"Created checkpoint mismatch")
        self.policy()
        v.need(self.head()==head,"Witness CAS conflict")
        # A sibling commit cannot fast-forward over a concurrent winner.
        result=self.api("PATCH","/git/refs/heads/"+self.branch,{"sha":new,"force":False})
        v.need(result["ref"]=="refs/heads/"+self.branch and result["object"]=={"type":"commit","sha":new,
               "url":result["object"]["url"]},"Witness update receipt mismatch")
        observed,history=self.snapshot()
        v.need(observed==new and history==rows+[value],"Witness advance unconfirmed")
