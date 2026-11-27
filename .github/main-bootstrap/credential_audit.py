"""Read-only credential audit; no authorizations or merges."""
import json
import os
import re
import urllib.request
import main_bootstrap as v

REF = "infra/main-authority-credential-audit-v1"
RULE = "gaslux-main-authority-audit-immutable-v1"
SLUG = "gaslux-main-infrastructure-auth"
APP = 5952630
EXPECTED = {"metadata":"read","contents":"read","pull_requests":"read",
            "actions":"read","checks":"read","statuses":"write"}

def get(path):
    v.need(path.startswith("/") and "://" not in path and ".." not in path,"Bad route")
    req=urllib.request.Request("https://api.github.com"+path,headers={
        "Authorization":"Bearer "+os.environ["GH_TOKEN"],
        "Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    with urllib.request.urlopen(req,timeout=25) as r:
        raw=r.read(2000001)
        v.need(len(raw)<=2000000 and 'rel="next"' not in r.headers.get("Link",""),"Incomplete response")
        return json.loads(raw)

def registration(row):
    v.need(row["id"]==APP and row["slug"]==SLUG and row["permissions"]==EXPECTED,
           "Unexpected infrastructure App registration")

def installation(row):
    v.need(row["total_count"]==1 and len(row["repositories"])==1
           and row["repositories"][0]["id"]==v.RID
           and row["repositories"][0]["full_name"]==v.REPO,"Installation not repository-only")

def audit():
    v.need(os.environ.get("GITHUB_ACTIONS")=="true"
           and os.environ.get("GITHUB_REPOSITORY")==v.REPO
           and os.environ.get("GITHUB_REPOSITORY_ID")==str(v.RID)
           and os.environ.get("GITHUB_EVENT_NAME")=="workflow_dispatch"
           and os.environ.get("GITHUB_REF")=="refs/heads/"+REF
           and os.environ.get("MINTED_SLUG")==SLUG,"Unexpected audit boundary")
    v.need(os.environ.get("PAUSE")=="true" and all(os.environ.get(k)=="false"
           for k in ("PROD_MERGE","LEGACY","V3","V4")),"Pause flags not explicit")
    pin=os.environ["VERIFIER_PIN"]
    v.need(v.SHA.fullmatch(pin) and v.ref(REF)==os.environ.get("GITHUB_SHA")==pin,
           "Audit verifier pin mismatch")
    v.need(v.ref(v.REF)=="3459813c7a191fd81f10e1bbdcbee3d5a8758013","Original verifier drift")
    repo=v.api("")
    v.need(repo["id"]==v.RID and repo["full_name"]==v.REPO and not repo["fork"],"Wrong repository")
    native=v.native_policy()
    original=v.verifier_policy()
    rows=v.api("/rulesets?includes_parents=true&per_page=100")
    hits=[r for r in rows if r["name"]==RULE]
    v.need(len(rows)<100 and len(hits)==1,"Immutable audit rule missing")
    m=v.api("/rulesets/"+str(hits[0]["id"]))
    v.need(m["source"]==v.REPO and m["source_type"]=="Repository"
           and m["target"]=="branch" and m["enforcement"]=="active"
           and m["conditions"]=={"ref_name":{"include":["refs/heads/"+REF],"exclude":[]}}
           and m["current_user_can_bypass"]=="never"
           and len(m["rules"])==3 and {x["type"] for x in m["rules"]}==
               {"update","deletion","non_fast_forward"},"Audit rule drift")
    if "bypass_actors" in m:
        v.need(m["bypass_actors"]==[],"Audit bypass exists")
    effective=v.api("/rules/branches/infra%2Fmain-authority-credential-audit-v1?per_page=100")
    own=[x for x in effective if x["ruleset_id"]==m["id"]]
    v.need(len(own)==3 and {x["type"] for x in own}=={"update","deletion","non_fast_forward"},
           "Audit rules not effective")
    registration(get("/apps/"+SLUG))
    installation(get("/installation/repositories?per_page=100"))
    bot=get("/users/"+SLUG+"%5Bbot%5D")
    v.need(bot["login"]==SLUG+"[bot]" and bot["type"]=="Bot"
           and bot["id"]==int(os.environ["EXPECTED_ACTOR"]),"Unexpected bot identity")
    v.need(v.ref(REF)==pin and v.native_policy()==native and v.verifier_policy()==original,
           "Final policy/ref drift")
    print(json.dumps({"app":APP,"slug":SLUG,"actor":bot["id"],
          "installation":os.environ["INSTALLATION_ID"],"repository_id":v.RID,
          "registration_verified":True,"repository_scope_verified":True,
          "token_requested":"read-only","authorization_published":False,
          "merge_authorized":False,"signer_provisioned":False,
          "bypass_inventory_visible":"bypass_actors" in m},sort_keys=True))
if __name__=="__main__":
    audit()
