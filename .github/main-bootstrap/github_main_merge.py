"""Dedicated main-only GitHub merge transport; no live credential provisioned."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request
import authority_contract as a
import authority_anchor as anchor
import github_authority_transport as g
import main_bootstrap as v

MERGE_APP=None
MERGE_INSTALLATION=None
MERGE_ACTOR=None
MERGE_SLUG=None
MERGE_KEY_SHA256=None
EXCLUSIVE_MAIN_RULE=None
MERGE_CUSTODY_REVIEW=None
REGISTRATION={"metadata":"read","contents":"write","pull_requests":"read"}
ROOT=Path("/etc/gaslux-authority")

def pins():
    v.need(all(type(x) is int and x>0 for x in
               (MERGE_APP,MERGE_INSTALLATION,MERGE_ACTOR,EXCLUSIVE_MAIN_RULE))
           and MERGE_APP not in (a.APP,5950656) and MERGE_ACTOR!=a.ACTOR
           and isinstance(MERGE_SLUG,str) and a.re.fullmatch(r"[a-z0-9-]+",MERGE_SLUG)
           and all(isinstance(x,str) and a.HEX64.fullmatch(x) for x in
                   (MERGE_KEY_SHA256,MERGE_CUSTODY_REVIEW)),
           "Independent main merge identity not provisioned")

def jwt(key):
    pins()
    anchor.checked_file(key,True)
    pub=subprocess.check_output(["/usr/bin/openssl","pkey","-in",str(key),"-pubout","-outform","DER"],
                                timeout=10)
    v.need(hashlib.sha256(pub).hexdigest()==MERGE_KEY_SHA256,"Wrong main merge key")
    now=int(time.time())
    raw=(g.b64url(v.canonical({"alg":"RS256","typ":"JWT"}))+"."+
         g.b64url(v.canonical({"iat":now-30,"exp":now+300,"iss":str(MERGE_APP)}))).encode()
    sig=subprocess.run(["/usr/bin/openssl","dgst","-sha256","-sign",str(key)],
                       input=raw,timeout=10,check=True,capture_output=True).stdout
    return raw.decode()+"."+g.b64url(sig)

def registration(row):
    v.need(row["id"]==MERGE_APP and row["slug"]==MERGE_SLUG and row["permissions"]==REGISTRATION,
           "Main merge App registration drift")

def validate_exclusive_rule(details,effective):
    g.validate_policy(details,effective)
    rows=[x for x in details if x["id"]==EXCLUSIVE_MAIN_RULE]
    v.need(len(rows)==1,"Exclusive main update rule missing")
    row=rows[0]
    v.need(row["source"]==v.REPO and row["source_type"]=="Repository" and
           row["target"]=="branch" and row["enforcement"]=="active" and
           row["conditions"]=={"ref_name":{"include":["refs/heads/main"],"exclude":[]}} and
           row["rules"]==[{"type":"update"}] and
           row["bypass_actors"]==[{"actor_id":MERGE_APP,"actor_type":"Integration",
                                    "bypass_mode":"pull_request"}],
           "Main update rule not exclusive PR-only")
    v.need(any(x["ruleset_id"]==EXCLUSIVE_MAIN_RULE and x["type"]=="update"
               and x["ruleset_source"]==v.REPO and x["ruleset_source_type"]=="Repository"
               for x in effective),"Exclusive rule not effective")

def put_once(n,head,token):
    v.need(type(n) is int and n in v.ALLOW and head==v.ALLOW[n][0],"Outside merge allowlist")
    v.need(isinstance(token,str) and token and not any(c.isspace() for c in token),"Invalid merge credential")
    req=urllib.request.Request("https://api.github.com/repos/"+v.REPO+"/pulls/"+str(n)+"/merge",
        data=v.canonical({"sha":head,"merge_method":"merge"}),method="PUT",
        headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
                 "Content-Type":"application/json","X-GitHub-Api-Version":"2022-11-28"})
    with urllib.request.build_opener(g.NoRedirect()).open(req,timeout=25) as response:
        raw=response.read(65537)
        v.need(len(raw)<=65536 and response.status==200,"Unconfirmed merge response")
        return json.loads(raw)

class MainMerge:
    def __init__(self):
        pins()
        self.key=ROOT/"main-merge-app.pem"
        self.admin_path=ROOT/"admin-read-token"
        self.token=None
        self.expiry=0
    def credential(self):
        if self.token is not None and time.monotonic()<self.expiry:
            return self.token
        auth=jwt(self.key)
        registration(g.rest("GET","/app",auth))
        installs=g.rest("GET","/app/installations?per_page=100",auth)
        v.need(type(installs) is list and len(installs)==1,"Unexpected merge App installation")
        i=installs[0]
        v.need(i["id"]==MERGE_INSTALLATION and i["app_id"]==MERGE_APP and
               i["account"]["login"]=="LMhdez" and i["repository_selection"]=="selected" and
               i["suspended_at"] is None and i["permissions"]==REGISTRATION,
               "Merge installation drift")
        route="/app/installations/"+str(MERGE_INSTALLATION)+"/access_tokens"
        scope=g.rest("POST",route,auth,{"permissions":{"metadata":"read"}})
        g.repository_scope(g.rest("GET","/installation/repositories?per_page=100",scope["token"]))
        minted=g.rest("POST",route,auth,{"repository_ids":[v.RID],"permissions":REGISTRATION})
        v.need(minted["permissions"]==REGISTRATION and minted["repository_selection"]=="selected",
               "Merge token scope drift")
        g.repository_scope(g.rest("GET","/installation/repositories?per_page=100",minted["token"]))
        self.token=minted["token"]
        self.expiry=time.monotonic()+300
        return self.token
    def proof(self):
        pins()
        token=self.credential()
        registration(g.rest("GET","/apps/"+MERGE_SLUG,token))
        g.repository_scope(g.rest("GET","/installation/repositories?per_page=100",token))
        bot=g.rest("GET","/users/"+MERGE_SLUG+"%5Bbot%5D",token)
        v.need(bot["id"]==MERGE_ACTOR and bot["login"]==MERGE_SLUG+"[bot]" and bot["type"]=="Bot",
               "Wrong merge bot")
        anchor.checked_file(self.admin_path,True)
        admin=self.admin_path.read_text().strip()
        details,effective=g.rule_inventory(admin)
        validate_exclusive_rule(details,effective)
        for k,value in g.FLAGS.items():
            row=g.rest("GET",g.REPO_ROUTE+"/actions/variables/"+k,admin)
            v.need(row["name"]==k and row["value"]==value,"Production pause drift")
        return {"app":MERGE_APP,"actor":MERGE_ACTOR,"repository_id":v.RID,
                "exclusive_rule":EXCLUSIVE_MAIN_RULE,"policy":g.ADMIN_POLICY_SHA256}
    def receipt(self,e,reader):
        # Exact two-parent/tree/live ordered ancestry validation is shared
        # with the authenticated status reader; also require the merge bot.
        receipt=reader.merged_receipt(e)
        if receipt is None: return None
        p=g.rest("GET",g.REPO_ROUTE+"/pulls/"+str(e["pr"]),self.credential())
        u=p["merged_by"]
        v.need(p["state"]=="closed" and p["merged"] is True and p["merge_commit_sha"]==receipt["merge"]
               and u is not None and u["id"]==MERGE_ACTOR and u["login"]==MERGE_SLUG+"[bot]"
               and u["type"]=="Bot" and reader.merged_receipt(e)==receipt,
               "Merge receipt issuer or composition drift")
        return receipt
    def dispatch_once(self,e):
        a.evidence_shape(e)
        result=put_once(e["pr"],e["head"],self.credential())
        v.need(result["merged"] is True and v.SHA.fullmatch(result["sha"]),
               "Merge not confirmed; do not retry")
        return result["sha"]
