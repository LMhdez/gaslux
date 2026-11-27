#!/usr/bin/env python3
"""Staged V3 decisions, explicit withdrawal, and fail-closed preactivation writers."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
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
    return f"GASLUX-V3:{bound['pr']}:{bound['base']}:{digest(bound)}:{state}"


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

 
# New contexts are intentionally NOT required by today's dev ruleset.
# Publication is staged only, behind explicit configuration. The production
# merge adapter is not present and must not be enabled by this flag.
MARKER = re.compile(r"GASLUX-V3:([1-9][0-9]{0,6}):([0-9a-f]{40}):([0-9a-f]{64}):(success|failure)")
ADMIN = 156089838


def role_context(kind):
    need(kind in ROLES,"Unknown authority")
    v1.context()
    repo = a.api("GET","")
    need(repo["id"] == a.REPOSITORY_ID and repo["full_name"] == a.REPO
         and repo["fork"] is False and repo["default_branch"] == "main","Wrong repository")
    need(os.getenv("GASLUX_AUTONOMY_PAUSED") in ("true","false"),"Explicit pause required")
    need(v1.app_registration(kind)["app_id"] == APPS[kind],"Wrong authority credential")


def staged_publication_context(kind, base):
    role_context(kind)
    need(os.getenv("GASLUX_V3_AUTHORITY_ENABLED") == "true"
         and os.getenv("GASLUX_AUTONOMY_PAUSED") == "false"
         and os.getenv("GASLUX_APP_STATUS_GATES_ENABLED") == "false"
         and os.getenv("GASLUX_PRODUCTION_MERGE_ENABLED") == "false",
         "Explicit separate preactivation stage required")
    need(g.production_policy_observed(base)
         and g.strict_ruleset_protected(base,require_app_statuses=True),
         "Existing native and source-pinned rules must remain enforced")


def authenticated_withdrawal_request(number,head,base):
    # This is a denial-only administrative emergency path. It grants no role
    # approval; each App signs its own failure with its existing isolated key.
    need(os.getenv("GITHUB_EVENT_NAME") == "workflow_dispatch"
         and os.getenv("GITHUB_ACTOR_ID") == str(ADMIN)
         and os.getenv("GITHUB_TRIGGERING_ACTOR") == "LMhdez"
         and os.getenv("GITHUB_RUN_ATTEMPT") == "1","Untrusted withdrawal requester")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    inputs = event.get("inputs") or {}
    need((event.get("sender") or {}).get("id") == ADMIN
         and (event.get("repository") or {}).get("id") == a.REPOSITORY_ID
         and inputs.get("v3_action") == "withdraw"
         and inputs.get("v3_pr") == str(number)
         and inputs.get("v3_head") == head and inputs.get("v3_base") == base,
         "Withdrawal inputs or requester changed")
    return inputs.get("v3_role")


def prior_marker(rows,kind,number,base):
    # Preserve the *original* binding digest even when current evidence is
    # no longer available. Never require stale CI/VM evidence to deny.
    related = [r for r in rows if str(r.get("context","")).casefold()==CONTEXTS[kind].casefold()]
    need(all(own(r,kind,CONTEXTS) for r in related),"Wrong issuer in authority history")
    matches=[]
    for r in related:
        m=MARKER.fullmatch(r.get("description") or "")
        need(m and int(m[1])==number and m[2]==base and m[4]==r.get("state"),
             "Withdrawal tuple mismatch")
        matches.append(m[3])
    need(len(set(matches)) <= 1,"Conflicting historical bindings")
    return matches[0] if matches else None


def candidate_identity_for_withdrawal(number,head,base):
    need(type(number) is int and 0 < number <= 1000000
         and a.valid_sha(head) and a.valid_sha(base) and head != lab.HEAD,
         "Invalid withdrawal tuple")
    p=a.api("GET",f"/pulls/{number}")
    need(p["number"]==number and a.publisher_ok(p.get("user") or {})
         and p["base"]["repo"]["id"]==p["head"]["repo"]["id"]==a.REPOSITORY_ID,
         "Withdrawal must target a known same-repo publisher PR")
    return p


def write_production_status(kind,head,payload,observed):
    # Callers have verified the tuple, role and evidence. This helper has no
    # generic API write route or ability to mutate reviews, refs or PRs.
    need(a.valid_sha(head) and head!=lab.HEAD
         and payload.get("context")==CONTEXTS[kind]
         and payload.get("state") in ("success","failure")
         and (m:=MARKER.fullmatch(payload.get("description") or ""))
         and m[4]==payload["state"],"Invalid production status write")
    if payload["state"]=="success":
        staged_publication_context(kind,m[2])
    else:
        role_context(kind)
    need(history(head,CONTEXTS)==observed,"Decision changed before publication")
    r=a.api("POST","/statuses/"+head,payload)
    need(own(r,kind,CONTEXTS) and all(r.get(k)==v for k,v in payload.items()),"Unauthenticated receipt")
    rows,live=history(head,CONTEXTS)
    need(live.get(kind,{}).get("id")==r["id"]
         and live[kind]["actor"]==ACTORS[kind] and live[kind]["state"]==payload["state"]
         and live[kind]["description"]==payload["description"],"Status not effective")
    if payload["state"]=="failure":
        need(any(own(x,kind,CONTEXTS) and x["state"]=="failure" and x["id"]==r["id"] for x in rows),
             "Withdrawal absent from history")
    return {"kind":kind,"state":payload["state"],"head":head,"status_id":r["id"],
            "merge_authorized":False}


def withdraw(kind,number,head,base,*,explicit=False):
    role_context(kind)
    if explicit:
        selected=authenticated_withdrawal_request(number,head,base)
        need(selected in (kind,"both"),"Wrong withdrawal role")
    p=candidate_identity_for_withdrawal(number,head,base)
    observed=history(head,CONTEXTS)
    previous=prior_marker(observed[0],kind,number,base)
    if previous is None:
        # A preemptive denial is terminal too, but only for the current exact
        # publisher tuple and an authenticated explicit request. An automated
        # scan must never poison an unrelated SHA without a prior decision.
        need(explicit and p["state"]=="open" and p["base"]["ref"]=="dev"
             and p["head"]["sha"]==head and p["base"]["sha"]==base
             and a.api("GET","/git/ref/heads/dev")["object"]["sha"]==base,
             "No prior authority or current exact candidate")
        need(g.discover().get(number,(None,None,None))[2]==head,"Unknown candidate")
        previous=digest({"schema":"gaslux-v3-preemptive-withdrawal","repository_id":a.REPOSITORY_ID,
                         "pr":number,"base":base,"head":head,"authority":kind,
                         "actor":ACTORS[kind],"target":"dev"})
    payload={"context":CONTEXTS[kind],"state":"failure",
             "description":f"GASLUX-V3:{number}:{base}:{previous}:failure"}
    old=observed[1].get(kind)
    if old and old["state"]=="failure" and old["description"]==payload["description"]:
        return {"kind":kind,"state":"failure","head":head,"status_id":old["id"],
                "merge_authorized":False,"already_withdrawn":True}
    # Reconfirm identity and history; even a closed/retargeted PR can have
    # its old authenticated authorization withdrawn. No review or ref write.
    need(candidate_identity_for_withdrawal(number,head,base)["number"]==number,
         "Withdrawal identity drift")
    return write_production_status(kind,head,payload,observed)


def publish_candidate(kind,number,role,scope,head,base):
    staged_publication_context(kind,base)
    first=snapshot(number,role,scope,head,base)
    observed=history(head,CONTEXTS)
    bound=first[kind]["binding"]
    if first[kind]["state"]!="success":
        return {"kind":kind,"state":"blocked","head":head,"merge_authorized":False}
    payload=transition(bound,"success",observed[0],CONTEXTS)
    need(snapshot(number,role,scope,head,base)==first,"Evidence changed before decision")
    staged_publication_context(kind,base)
    old=observed[1].get(kind)
    if old and old["state"]=="success" and old["description"]==payload["description"]:
        need(history(head,CONTEXTS)==observed,"Receipt drift")
        return {"kind":kind,"state":"success","head":head,"status_id":old["id"],
                "merge_authorized":False}
    result=write_production_status(kind,head,payload,observed)
    try:
        stable=snapshot(number,role,scope,head,base)==first
    except (OSError,RuntimeError,ValueError,TypeError,KeyError,AttributeError):
        stable=False
    if not stable:
        withdraw(kind,number,head,base)
        raise ValueError("Published decision drifted and was withdrawn")
    return result


def reconcile_role(kind):
    """Revoke before granting anything; staged-only automatic publisher.

    The inventory covers all open publisher PRs, including retargeted ones.
    Historical changed/closed heads require explicit withdrawal; do not
    present this sweep as atomic external review/comment revocation.
    """
    role_context(kind)
    base=a.api("GET","/git/ref/heads/dev")["object"]["sha"]
    need(a.valid_sha(base),"Invalid dev")
    open_prs=a.complete_page(a.api("GET","/pulls?state=open&per_page=100"))
    candidates=g.discover()
    enabled=(os.getenv("GASLUX_V3_AUTHORITY_ENABLED")=="true"
             and os.getenv("GASLUX_AUTONOMY_PAUSED")=="false"
             and os.getenv("GASLUX_APP_STATUS_GATES_ENABLED")=="false"
             and os.getenv("GASLUX_PRODUCTION_MERGE_ENABLED")=="false")
    results=[]
    for p in open_prs:
        if not a.publisher_ok(p.get("user") or {}) or any(
            (p.get(k,{}).get("repo") or {}).get("id")!=a.REPOSITORY_ID for k in ("head","base")):
            continue
        n,head=p["number"],p["head"]["sha"]
        rows,live=history(head,CONTEXTS)
        current=live.get(kind)
        if current is None or current["state"]!="success":
            continue
        m=MARKER.fullmatch(current["description"] or "")
        need(m and int(m[1])==n and current["actor"]==ACTORS[kind],"Ambiguous current authorization")
        issued_base=m[2]
        keep=False
        item=candidates.get(n)
        if enabled and item and item[2]==head and issued_base==base:
            try:
                staged_publication_context(kind,base)
                new=snapshot(n,item[0],item[1],head,base)[kind]
                keep=(new["state"]=="success" and
                      transition(new["binding"],"success",rows,CONTEXTS)["description"]==current["description"])
            except (OSError,RuntimeError,ValueError,TypeError,KeyError,AttributeError):
                keep=False
        if not keep:
            results.append(withdraw(kind,n,head,issued_base))
    if enabled:
        staged_publication_context(kind,base)
        for n,(role,scope,head) in sorted(candidates.items()):
            rows,live=history(head,CONTEXTS)
            if any(own(r,kind,CONTEXTS) and r["state"]=="failure" for r in rows):
                continue
            results.append(publish_candidate(kind,n,role,scope,head,base))
    need(a.api("GET","/git/ref/heads/dev")["object"]["sha"]==base,"Dev advanced during reconciliation")
    return {"schema":"gaslux-v3-role-reconciliation","kind":kind,"results":results,
            "production_merge_authorized":False}


if __name__=="__main__":
    p=argparse.ArgumentParser()
    modes=p.add_mutually_exclusive_group(required=True)
    modes.add_argument("--shadow",action="store_true")
    modes.add_argument("--pilot-approve",choices=ROLES)
    modes.add_argument("--pilot-revoke",choices=ROLES)
    modes.add_argument("--pilot-audit",action="store_true")
    modes.add_argument("--reconcile-role",choices=ROLES)
    modes.add_argument("--withdraw",choices=ROLES)
    p.add_argument("--pr",type=int)
    p.add_argument("--head")
    p.add_argument("--base")
    args=p.parse_args()
    if args.shadow:
        out=shadow()
    elif args.pilot_approve:
        out=pilot_write(args.pilot_approve,"success")
    elif args.pilot_revoke:
        out=pilot_write(args.pilot_revoke,"failure")
    elif args.reconcile_role:
        out=reconcile_role(args.reconcile_role)
    elif args.withdraw:
        out=withdraw(args.withdraw,args.pr,args.head,args.base,explicit=True)
    else:
        out=pilot_audit()
    print(json.dumps(out,sort_keys=True))
