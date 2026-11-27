#!/usr/bin/env python3
"""Staged V3 exact decision protocol. Only inert fixture writes are enabled."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gaslux_app_status_gate as v1

g, a, lab = v1.gate, v1.a, v1.lab
ROLES = v1.ROLES
ACTORS = v1.ACTORS
APPS = {"safety": 5936904, "owner": 5936940}
CONTEXTS = {k: "gaslux-dev/" + k + "-v3" for k in ROLES}
PILOT = {k: "gaslux-inert-authority-v3/" + k for k in ROLES}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def binding(kind, number, target, head, base, role, scope, evidence):
    need(kind in ROLES and type(number) is int and 0 < number <= 1000000
         and a.valid_sha(head) and a.valid_sha(base) and isinstance(evidence, dict)
         and bool(evidence), "Invalid decision binding")
    need((target == "dev" and role in g.factory.TASKS
          and scope in (*g.factory.SUPERVISED_SCOPES, g.DYNAMIC_SCOPE, g.MULTIFILE_SCOPE))
         or (target == lab.BASE_REF and number == lab.NUMBER and head == lab.HEAD
             and base == lab.BASE and role == scope == "inert"), "Invalid target")
    return {"schema":"gaslux-authoritative-decision-v3","repository_id":a.REPOSITORY_ID,
            "target":target,"pr":number,"head":head,"base":base,"role":role,"scope":scope,
            "authority":kind,"app":APPS[kind],"actor":ACTORS[kind],"evidence_sha256":digest(evidence)}


def description(bound, state):
    need(state in ("success","failure"), "Invalid state")
    return "GASLUX-V3:" + digest(bound) + ":" + state


def own(row, kind, contexts):
    actor = row.get("creator") or {}
    return (row.get("context") == contexts[kind] and actor.get("id") == ACTORS[kind]
            and actor.get("type") == "Bot"
            and actor.get("login") == "gaslux-independent-" + kind + "[bot]")


def transition(bound, state, rows, contexts):
    kind = bound["authority"]
    need(state in ("success","failure") and kind in ROLES, "Invalid transition")
    rows = a.complete_page(rows)
    ids = [r.get("id") for r in rows]
    need(all(type(i) is int and i > 0 for i in ids) and len(set(ids)) == len(ids), "Invalid history")
    related = [r for r in rows if str(r.get("context","")).casefold() == contexts[kind].casefold()]
    need(all(own(r,kind,contexts) for r in related), "Wrong issuer")
    if state == "success":
        need(not any(r.get("state") in ("failure","error") for r in related), "Revoked HEAD is terminal")
    valid = {(s,description(bound,s)) for s in ("success","failure")}
    need(all((r.get("state"),r.get("description")) in valid for r in related), "Decision tuple/history mismatch")
    if state == "failure":
        need(any(r.get("state") == "success" for r in related), "No prior authorization")
    return {"context":contexts[kind],"state":state,"description":description(bound,state)}


def history(head, contexts):
    need(a.valid_sha(head),"Invalid HEAD")
    path = "/commits/" + head + "/statuses?per_page=100"
    before = a.complete_page(a.api("GET",path))
    effective = v1.status_receipts(head,contexts=contexts)
    need(a.complete_page(a.api("GET",path)) == before,"Concurrent history change")
    ids = [r.get("id") for r in before]
    need(all(type(i) is int and i > 0 for i in ids) and len(set(ids)) == len(ids),"Invalid history")
    for k,ctx in contexts.items():
        rows = [r for r in before if str(r.get("context","")).casefold() == ctx.casefold()]
        e = effective.get(k)
        if rows:
            need(e and e["id"] == rows[0]["id"] and e["state"] == rows[0]["state"]
                 and e["description"] == rows[0]["description"],"Effective decision mismatch")
        else:
            need(e is None,"Unknown effective decision")
    return before,effective


def decision(kind,row,vm):
    # Transitional: each role requires its own authenticated review evidence,
    # never the other role's approval. Full VM evidence remains mandatory.
    if row.get("technical_objection") is True:
        return "failure"
    if row.get("technical_objection") is not False or not all(row.get(k) is True for k in
        ("exact_scope_verified","current_base_verified","ci_workflow_provenance_verified","ci_verified")):
        return "pending"
    key = {"safety":"safety_review_verified","owner":"backend_owner_verified"}[kind]
    if row.get(key) is not True:
        return "pending"
    if row["scope"] in g.PRODUCT_SCOPES and vm is not True:
        return "pending"
    return "success" if row["scope"] in (*g.PRODUCT_SCOPES,g.factory.SUPERVISED_TEST_SCOPE) else "pending"


def snapshot(n,role,scope,head,base):
    safety,owners = v1.identities()
    p = v1.frozen(n,head,base)
    branch = p["head"]["ref"]
    candidates = a.complete_page(a.api("GET","/pulls?state=all&head="+
        quote(a.REPO.split("/")[0]+":"+branch,safe="")+"&per_page=100"))
    need(len(candidates)==1 and candidates[0]["number"]==n,"Reused candidate branch")
    opens = a.complete_page(a.api("GET","/pulls?state=open&per_page=100"))
    need([x["number"] for x in opens if x.get("head",{}).get("sha")==head]==[n],"Ambiguous HEAD")
    paths = {"reviews":f"/pulls/{n}/reviews?per_page=100",
             "comments":f"/issues/{n}/comments?per_page=100",
             "checks":f"/commits/{head}/check-runs?per_page=100",
             "runs":f"/actions/runs?head_sha={head}&event=pull_request&per_page=100"}
    data = {k:a.api("GET",path) for k,path in paths.items()}
    reviews = a.complete_page(data["reviews"])
    a.complete_page(data["comments"])
    for k,field in (("checks","check_runs"),("runs","workflow_runs")):
        need(data[k]["total_count"]==len(a.complete_page(data[k][field])),"Incomplete evidence")
    row = g.inspect(n,role,scope,head,safety,owners[role],allow_ready=True)
    need(row["base"]==base,"Stale base")
    vm = scope not in g.PRODUCT_SCOPES or g.vm_acceptance_verified(
        reviews,role,head,base,p["user"]["id"],safety,owners[role])
    need(v1.frozen(n,head,base)["head"]["ref"]==branch and
         data=={k:a.api("GET",path) for k,path in paths.items()},"Evidence drift")
    tree=a.api("GET",f"/git/commits/{head}")["tree"]["sha"]
    need(a.valid_sha(tree),"Invalid evidence tree")
    # Hash exact evidence objects; separate own-role and independent VM receipts.
    observer=os.getenv("GASLUX_VM_OBSERVER_ID","")
    result={}
    for k in ROLES:
        evidence={"tree":tree,"checks":data["checks"],"runs":data["runs"],
                  "own_reviews":[x for x in reviews if (x.get("user") or {}).get("id")==ACTORS[k]
                                 and x.get("state")!="COMMENTED"],
                  "vm_reviews":[x for x in reviews if str((x.get("user") or {}).get("id"))==observer],
                  "comments":data["comments"],"vm_verified":vm,"engine":os.getenv("GITHUB_SHA")}
        result[k]={"state":decision(k,row,vm),
                   "binding":binding(k,n,"dev",head,base,role,scope,evidence)}
    return result


def shadow():
    v1.context()
    base=a.api("GET","/git/ref/heads/dev")["object"]["sha"]
    need(a.valid_sha(base),"Invalid dev")
    out=[]
    for n,(role,scope,head) in sorted(g.discover().items()):
        try:
            first=snapshot(n,role,scope,head,base)
            need(first==snapshot(n,role,scope,head,base),"Decision drift")
            out.append({"pr":n,"head":head,"decisions":first})
        except (OSError,RuntimeError,ValueError,TypeError,KeyError,AttributeError):
            out.append({"pr":n,"head":head,"state":"blocked_unverified"})
    need(a.api("GET","/git/ref/heads/dev")["object"]["sha"]==base,"Base changed")
    return {"schema":"gaslux-v3-shadow","base":base,"candidates":out,
            "read_only":True,"merge_authorized":False}


def pilot_context():
    lab.context()
    need(os.getenv("GITHUB_EVENT_NAME")=="workflow_dispatch"
         and os.getenv("GASLUX_V3_PILOT")=="true"
         and os.getenv("GASLUX_STATUS_PILOT_ENABLED")=="true"
         and os.getenv("GASLUX_APP_STATUS_GATES_ENABLED")=="false"
         and os.getenv("GASLUX_PRODUCTION_MERGE_ENABLED")=="false","Explicit paused pilot only")
    repo=a.api("GET","")
    need(repo["id"]==a.REPOSITORY_ID and repo["full_name"]==a.REPO and repo["fork"] is False
         and lab.candidate()["state"]=="open" and lab.actors()==ACTORS,"Wrong fixture")
    return {k:binding(k,lab.NUMBER,lab.BASE_REF,lab.HEAD,lab.BASE,"inert","inert",
                      {"tree":lab.TREE,"blob":lab.BLOB,"file":lab.FILE,"purpose":"inert only",
                       "engine":os.getenv("GITHUB_SHA")}) for k in ROLES}


def pilot_write(kind,state):
    bounds=pilot_context()
    need(v1.app_registration(kind)["app_id"]==APPS[kind],"Wrong App")
    bound=bounds[kind]
    before,effective=history(lab.HEAD,PILOT)
    payload=transition(bound,state,before,PILOT)
    need(pilot_context()==bounds and history(lab.HEAD,PILOT)==(before,effective),"Decision drift")
    result=a.api("POST","/statuses/"+lab.HEAD,payload)
    need(own(result,kind,PILOT) and all(result.get(k)==v for k,v in payload.items()),"Wrong receipt")
    after,live=history(lab.HEAD,PILOT)
    need(live.get(kind,{}).get("id")==result["id"] and pilot_context()==bounds,"Receipt drift")
    if state=="failure":
        terminal(bound,after,PILOT)
    return {"state":state,"kind":kind,"status_id":result["id"],"merge_authorized":False}


def terminal(bound,rows,contexts):
    try:
        transition(bound,"success",rows,contexts)
    except ValueError as exc:
        need(str(exc)=="Revoked HEAD is terminal","Wrong refusal")
    else:
        raise ValueError("Terminal revocation not enforced")


def pilot_audit():
    bounds=pilot_context()
    rows,live=history(lab.HEAD,PILOT)
    for k in ROLES:
        payload=transition(bounds[k],"failure",rows,PILOT)
        need(live.get(k,{}).get("state")=="failure" and live[k]["actor"]==ACTORS[k]
             and live[k]["description"]==payload["description"],"Revocation not effective")
        terminal(bounds[k],rows,PILOT)
    need(pilot_context()==bounds and history(lab.HEAD,PILOT)==(rows,live),"Audit drift")
    return {"schema":"gaslux-v3-inert-terminal-audit","head":lab.HEAD,"receipts":live,
            "both_roles_terminal":True,"merge_authorized":False}


if __name__=="__main__":
    p=argparse.ArgumentParser()
    modes=p.add_mutually_exclusive_group(required=True)
    modes.add_argument("--shadow",action="store_true")
    modes.add_argument("--pilot-approve",choices=ROLES)
    modes.add_argument("--pilot-revoke",choices=ROLES)
    modes.add_argument("--pilot-audit",action="store_true")
    args=p.parse_args()
    if args.shadow:
        out=shadow()
    elif args.pilot_approve:
        out=pilot_write(args.pilot_approve,"success")
    elif args.pilot_revoke:
        out=pilot_write(args.pilot_revoke,"failure")
    else:
        out=pilot_audit()
    print(json.dumps(out,sort_keys=True))
