"""Real GitHub REST adapter for bounded production authority; disabled until reviewed deployment.

No merge endpoint. No candidate execution. No automatic retry or inferred HTTP
settlement. App registration, installation scope and status-only authority
are checked independently of the approval policy. The production App key
must be held by the exclusive publisher service, never a candidate runner.
"""
import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.request
import authority_anchor as anchor
import authority_contract as a
import main_bootstrap as v
import safety_client as safety

ROOT=Path("/etc/gaslux-authority")
# These pins must be set in a separately reviewed, frozen deployment release.
# No runtime variable or request may substitute for them.
APP_KEY_PUBLIC_SHA256=None
ADMIN_POLICY_SHA256=None
ADDITIVE_RULE_ID=None
EXCLUSIVE_CUSTODY_REVIEW=None
MAX=8000000
REPO_ROUTE="/repos/"+v.REPO
FLAGS={"GASLUX_AUTONOMY_PAUSED":"true","GASLUX_PRODUCTION_MERGE_ENABLED":"false",
       "GASLUX_APP_STATUS_GATES_ENABLED":"false","GASLUX_V3_AUTHORITY_ENABLED":"false",
       "GASLUX_V4_MERGE_ENABLED":"false"}
REGISTRATION={"metadata":"read","contents":"read","pull_requests":"read",
              "actions":"read","checks":"read","statuses":"write"}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise ValueError("Unexpected REST redirect")

def rest(method,path,token,payload=None):
    v.need(method in ("GET","POST") and path.startswith("/") and
           "://" not in path and ".." not in path and not any(c.isspace() for c in path),
           "Invalid REST route")
    v.need(isinstance(token,str) and token and not any(c.isspace() for c in token),"Invalid credential")
    v.need((method=="GET" and payload is None) or (method=="POST" and type(payload) is dict),
           "Invalid request body")
    raw=None if payload is None else v.canonical(payload)
    req=urllib.request.Request("https://api.github.com"+path,data=raw,method=method,
        headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
                 "X-GitHub-Api-Version":"2022-11-28","Content-Type":"application/json"})
    # urllib's opener has no POST retry policy; redirects are refused.
    with urllib.request.build_opener(NoRedirect()).open(req,timeout=25) as response:
        data=response.read(MAX+1)
        v.need(len(data)<=MAX and 'rel="next"' not in response.headers.get("Link",""),
               "Incomplete or oversized response")
        return json.loads(data)

def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

def app_jwt(key):
    anchor.checked_file(key,True)
    pub=subprocess.check_output(["/usr/bin/openssl","pkey","-in",str(key),"-pubout","-outform","DER"],
                                timeout=10)
    import hashlib
    v.need(isinstance(APP_KEY_PUBLIC_SHA256,str) and
           hashlib.sha256(pub).hexdigest()==APP_KEY_PUBLIC_SHA256,"App private key pin mismatch")
    now=int(time.time())
    message=(b64url(v.canonical({"alg":"RS256","typ":"JWT"}))+"."+
             b64url(v.canonical({"iat":now-30,"exp":now+300,"iss":str(a.APP)}))).encode("ascii")
    sig=subprocess.run(["/usr/bin/openssl","dgst","-sha256","-sign",str(key)],
                       input=message,capture_output=True,timeout=10,check=True).stdout
    return message.decode("ascii")+"."+b64url(sig)

def registration(row):
    v.need(row["id"]==a.APP and row["slug"]==a.SLUG and row["permissions"]==REGISTRATION,
           "App registration drift")

def installation(row):
    v.need(row["id"]==a.INSTALLATION and row["app_id"]==a.APP and
           row["account"]["login"]=="LMhdez" and row["repository_selection"]=="selected" and
           row["suspended_at"] is None and row["permissions"]==REGISTRATION,
           "Installation drift")

def repository_scope(row):
    v.need(row["total_count"]==1 and len(row["repositories"])==1 and
           row["repositories"][0]["id"]==v.RID and
           row["repositories"][0]["full_name"]==v.REPO,"Repository scope drift")

def deployment_ready():
    v.need(all(isinstance(x,str) and a.HEX64.fullmatch(x) for x in
               (APP_KEY_PUBLIC_SHA256,ADMIN_POLICY_SHA256,EXCLUSIVE_CUSTODY_REVIEW)) and
           type(ADDITIVE_RULE_ID) is int and ADDITIVE_RULE_ID>0 and
           isinstance(a.SIGNER_PEM_SHA256,str) and a.HEX64.fullmatch(a.SIGNER_PEM_SHA256),
           "Independent deployment pins not provisioned")

def rule_inventory(admin):
    rows=rest("GET",REPO_ROUTE+"/rulesets?includes_parents=true&per_page=100",admin)
    v.need(type(rows) is list and len(rows)<100 and len({x["id"] for x in rows})==len(rows),
           "Incomplete ruleset inventory")
    details=[]
    for row in sorted(rows,key=lambda x:x["id"]):
        detail=rest("GET",REPO_ROUTE+"/rulesets/"+str(row["id"]),admin)
        v.need(detail["id"]==row["id"] and "bypass_actors" in detail and
               detail["enforcement"] in ("active","disabled","evaluate"),"Incomplete actor inventory")
        details.append({k:detail[k] for k in
            ("id","name","source","source_type","target","enforcement","conditions","rules","bypass_actors")})
    effective=rest("GET",REPO_ROUTE+"/rules/branches/main?per_page=100",admin)
    v.need(type(effective) is list and len(effective)<100,"Incomplete effective rules")
    return details,sorted(effective,key=lambda x:(x["ruleset_id"],x["type"],v.digest(x)))

def validate_policy(details,effective):
    v.need(v.digest({"rulesets":details,"effective_main":effective})==ADMIN_POLICY_SHA256,
           "Independently pinned policy changed")
    native=[x for x in details if x["id"]==v.RULE]
    additive=[x for x in details if x["id"]==ADDITIVE_RULE_ID]
    for rows in (native,additive):
        v.need(len(rows)==1 and rows[0]["source"]==v.REPO and
               rows[0]["source_type"]=="Repository" and rows[0]["target"]=="branch" and
               rows[0]["enforcement"]=="active" and rows[0]["bypass_actors"]==[] and
               rows[0]["conditions"]=={"ref_name":{"include":["refs/heads/main"],"exclude":[]}},
               "Mandatory main ruleset missing or bypassable")
    n={x["type"]:x.get("parameters",{}) for x in native[0]["rules"]}
    pr=n["pull_request"]
    ci=n["required_status_checks"]
    v.need(pr["required_approving_review_count"]>=1 and pr["dismiss_stale_reviews_on_push"] is True and
           pr["require_last_push_approval"] is True and pr["required_review_thread_resolution"] is True and
           ci["strict_required_status_checks_policy"] is True and
           {"context":"adversarial_contracts","integration_id":15368} in ci["required_status_checks"],
           "Native protection weakened")
    ar=additive[0]["rules"]
    v.need(len(ar)==1 and ar[0]["type"]=="required_status_checks" and
           ar[0]["parameters"]=={"strict_required_status_checks_policy":True,
               "do_not_enforce_on_create":False,"required_status_checks":[
               {"context":v.CONTEXT,"integration_id":a.APP}]},"Wrong additive App source gate")
    for rid,kind in ((v.RULE,"pull_request"),(v.RULE,"required_status_checks"),
                     (ADDITIVE_RULE_ID,"required_status_checks")):
        v.need(any(x["ruleset_id"]==rid and x["type"]==kind for x in effective),
               "Gate not effective on main")

class GitHubAuthority:
    def __init__(self):
        deployment_ready()
        self.key=ROOT/"publisher-app.pem"
        self.admin_path=ROOT/"admin-read-token"
        self.safety=safety.SafetyClient()
        self.token=None
        self.expiry=0
        self.identity_proof()

    def mint(self):
        jwt=app_jwt(self.key)
        registration(rest("GET","/app",jwt))
        installations=rest("GET","/app/installations?per_page=100",jwt)
        v.need(type(installations) is list and len(installations)==1,"Unexpected App installations")
        installation(installations[0])
        # Check full installation scope with an un-narrowed token first.
        scope=rest("POST","/app/installations/"+str(a.INSTALLATION)+"/access_tokens",jwt,
                   {"permissions":{"metadata":"read"}})
        repository_scope(rest("GET","/installation/repositories?per_page=100",scope["token"]))
        result=rest("POST","/app/installations/"+str(a.INSTALLATION)+"/access_tokens",jwt,
                    {"repository_ids":[v.RID],"permissions":REGISTRATION})
        v.need(result["permissions"]==REGISTRATION and result["repository_selection"]=="selected",
               "Token permission/scope mismatch")
        repository_scope(rest("GET","/installation/repositories?per_page=100",result["token"]))
        self.token=result["token"]
        self.expiry=time.monotonic()+300

    def credential(self):
        if self.token is None or time.monotonic()>=self.expiry:
            self.mint()
        return self.token

    def identity_proof(self):
        token=self.credential()
        registration(rest("GET","/apps/"+a.SLUG,token))
        repository_scope(rest("GET","/installation/repositories?per_page=100",token))
        bot=rest("GET","/users/"+a.SLUG+"%5Bbot%5D",token)
        v.need(bot["id"]==a.ACTOR and bot["login"]==a.SLUG+"[bot]" and bot["type"]=="Bot",
               "Wrong status actor")
        # This pin represents a separately reviewed deployment custody audit;
        # the API cannot prove that no other host holds a copy of a private key.
        return {"repository_id":v.RID,"app":a.APP,"actor":a.ACTOR,
                "installation":a.INSTALLATION,"exclusive_writer":True}

    def policy_proof(self):
        proof=self.identity_proof()
        anchor.checked_file(self.admin_path,True)
        admin=self.admin_path.read_text().strip()
        details,effective=rule_inventory(admin)
        validate_policy(details,effective)
        for k,value in FLAGS.items():
            row=rest("GET",REPO_ROUTE+"/actions/variables/"+k,admin)
            v.need(row["name"]==k and row["value"]==value,"Production not explicitly paused")
        return {**proof,"native_review_retained":True,"source_pinned_gate":True,
                "complete_actor_inventory":True,"paused":True}

    @contextmanager
    def snapshot_token(self):
        old=os.environ.get("GH_TOKEN")
        os.environ["GH_TOKEN"]=self.credential()
        try: yield
        finally:
            if old is None: os.environ.pop("GH_TOKEN",None)
            else: os.environ["GH_TOKEN"]=old

    def snapshot(self,n):
        with self.snapshot_token():
            v.need(v.ref(v.REF)==a.EVIDENCE_ENGINE,"Evidence verifier drift")
            v.verifier_policy()
            return v.snapshot(n,a.EVIDENCE_ENGINE)

    def _merged_chain(self):
        token=self.credential()
        def get(path):
            return rest("GET",REPO_ROUTE+path,token)
        main=get("/git/ref/heads/main")["object"]
        v.need(main["type"]=="commit" and v.SHA.fullmatch(main["sha"]),"Invalid main ref")
        base=v.BASE
        receipts=[]
        open_seen=False
        for n,(head,tree,branch,pid) in v.ALLOW.items():
            pr=get("/pulls/"+str(n))
            v.need(pr["number"]==n and pr["id"]==pid and pr["head"]["sha"]==head
                   and pr["head"]["ref"]==branch and pr["head"]["repo"]["id"]==v.RID
                   and pr["base"]["ref"]=="main" and pr["base"]["repo"]["id"]==v.RID,
                   "Candidate identity/target drift")
            if pr["state"]=="open" and pr["merged"] is False:
                open_seen=True
                continue
            v.need(not open_seen and pr["state"]=="closed" and pr["merged"] is True
                   and v.SHA.fullmatch(pr["merge_commit_sha"]),"Noncanonical closure or merge sequence")
            commit=get("/git/commits/"+pr["merge_commit_sha"])
            v.need(commit["sha"]==pr["merge_commit_sha"] and
                   [x["sha"] for x in commit["parents"]]==[base,head]
                   and commit["tree"]["sha"]==tree,"Wrong merged composition")
            receipts.append({"pr":n,"head":head,"merge":commit["sha"],"tree":tree,"base":base})
            base=commit["sha"]
        v.need(main["sha"]==base and get("/git/ref/heads/main")["object"]==main,
               "Live main ancestry drift")
        return receipts

    def merged_receipt(self,e):
        a.evidence_shape(e)
        first=self._merged_chain()
        v.need(first==self._merged_chain(),"Merged chain drift")
        found=[x for x in first if x["pr"]==e["pr"]]
        if not found:
            return None
        receipt=found[0]
        predecessors=[{k:x[k] for k in ("pr","head","merge","tree")}
                      for x in first if x["pr"]<e["pr"]]
        v.need(receipt["base"]==e["base"] and receipt["head"]==e["head"] and
               receipt["tree"]==e["tree"] and predecessors==e["predecessors"],
               "Merged receipt not bound to approved evidence")
        return receipt

    def current_decision(self,e,nonce):
        return self.safety.current_decision(e,nonce)

    def combined(self,head):
        self.check_head(head)
        return rest("GET",REPO_ROUTE+"/commits/"+head+"/status?per_page=100",self.credential())

    def history(self,head):
        self.check_head(head)
        return rest("GET",REPO_ROUTE+"/commits/"+head+"/statuses?per_page=100",self.credential())

    @staticmethod
    def check_head(head):
        v.need(head in {x[0] for x in v.ALLOW.values()},"HEAD outside bootstrap allowlist")

    def publish(self,head,payload):
        self.check_head(head)
        v.need(set(payload)=={"context","state","description"} and
               payload["context"]==v.CONTEXT and payload["state"] in ("success","failure") and
               len(payload["description"])<=140,"Invalid status payload")
        # No retry: the journal reconciles exact observed receipts.
        return rest("POST",REPO_ROUTE+"/statuses/"+head,self.credential(),payload)

    def outbound_settled(self,head,state):
        self.check_head(head)
        # REST provides no documented request fence. Never claim settlement
        # from a timeout, token revocation, empty GET or elapsed time.
        return False
