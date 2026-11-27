#!/usr/bin/env python3
"""Dedicated V4 Integrator: read-only paused audit and gated exact merge.

No ruleset mutations, candidate execution, status writes or native-gate bypass.
The production execution entry point remains unwired until operational acceptance.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))
import gaslux_authority_v3 as v

a,g = v.a,v.g
SLUG = "gaslux-production-integrator"
PERMISSIONS = {"metadata":"read","contents":"write","pull_requests":"write",
               "actions":"read","checks":"read","statuses":"read","issues":"read"}
MANDATORY = "gaslux-dev-authority-v4"
EXCLUSIVE = "gaslux-dev-exclusive-integrator-v4"
TARGET = {"ref_name":{"include":["refs/heads/dev"],"exclude":[]}}
EXPECTED_CHECKS = {"evidence-python":15368,"evidence-powershell":15368,
                   "Windows recovery evidence rules (fixtures only)":15368,
                   **{v.CONTEXTS[k]:v.APPS[k] for k in v.ROLES}}
need = v.need


def app_id():
    raw=os.getenv("GASLUX_INTEGRATOR_APP_ID","")
    need(re.fullmatch(r"[1-9][0-9]{0,15}",raw),"Dedicated App ID required")
    value=int(raw)
    need(value not in (15368,5950119,5938492,5938509,*v.APPS.values(),*v.ACTORS.values()),
         "Lab or role identity forbidden")
    return value


def trusted():
    v.v1.context()
    repo=a.api("GET","")
    need(os.getenv("GITHUB_REPOSITORY_ID")==str(a.REPOSITORY_ID)
         and repo["id"]==a.REPOSITORY_ID and repo["full_name"]==a.REPO
         and repo["fork"] is False and repo["default_branch"]=="main",
         "Wrong production repository")


def credential():
    trusted()
    client=os.getenv("GASLUX_INTEGRATOR_APP_CLIENT_ID","")
    others=[os.getenv("GASLUX_"+k+"_APP_CLIENT_ID","") for k in ("SAFETY","OWNER","PUBLISH")]
    need(all(re.fullmatch(r"[A-Za-z0-9_.-]{8,128}",c) for c in [client,*others])
         and len(set([client,*others]))==4 and client!="Iv23liqNc2z4NWCoBHP0",
         "Distinct production credentials required")
    need(os.getenv("GASLUX_MINTED_APP_SLUG")==SLUG and
         re.fullmatch(r"[1-9][0-9]{0,18}",os.getenv("GASLUX_MINTED_INSTALLATION_ID","")),
         "Wrong token mint identity")
    app=g.readonly_gh_json("apps/"+SLUG)
    need(app["id"]==app_id() and app["slug"]==SLUG and app["client_id"]==client
         and app["permissions"]==PERMISSIONS,"Wrong App registration or permissions")
    repos=g.readonly_gh_json("installation/repositories?per_page=100")
    need(repos["total_count"]==1 and len(repos["repositories"])==1
         and repos["repositories"][0]["id"]==a.REPOSITORY_ID
         and repos["repositories"][0]["full_name"]==a.REPO,"Token not production-repo-only")
    bot=g.readonly_gh_json("users/"+SLUG+"%5Bbot%5D")
    need(bot["type"]=="Bot" and bot["login"]==SLUG+"[bot]" and type(bot["id"]) is int
         and bot["id"]>0 and bot["id"] not in (*v.ACTORS.values(),*a.BOTS.values()),
         "Wrong independent bot")
    return {"app_id":app["id"],"actor":bot["id"],"slug":SLUG}


ACTORS_QUERY = """
query($id:ID!) {
  node(id:$id) {
    __typename
    ... on RepositoryRuleset {
      id databaseId enforcement
      source { ... on Repository { nameWithOwner } }
      bypassActors(first:100) {
        totalCount pageInfo { hasNextPage hasPreviousPage }
        nodes {
          bypassMode
          actor { __typename ... on App { databaseId slug } }
        }
      }
    }
  }
}
"""


def exclusive_actor(rule,app):
    expected=[{"actor_id":app,"actor_type":"Integration","bypass_mode":"pull_request"}]
    if "bypass_actors" in rule:
        return rule["bypass_actors"]==expected
    rid,node=rule["id"],rule["node_id"]
    need(type(rid) is int and rid>0 and re.fullmatch(r"[A-Za-z0-9_+/=-]{1,180}",node),
         "Malformed ruleset node")
    raw=subprocess.run(["gh","api","graphql","-f","query="+ACTORS_QUERY,"-f","id="+node],
                       check=True,timeout=30,capture_output=True).stdout
    need(len(raw)<65536,"Oversized actor inventory")
    data=json.loads(raw)
    need(not data.get("errors"),"Actor inventory unavailable")
    n=data["data"]["node"]
    c=n["bypassActors"]
    return (n["__typename"]=="RepositoryRuleset" and n["id"]==node
            and n["databaseId"]==rid and n["enforcement"]=="ACTIVE"
            and n["source"]["nameWithOwner"]==a.REPO and c["totalCount"]==1
            and c["pageInfo"]=={"hasNextPage":False,"hasPreviousPage":False}
            and c["nodes"]==[{"bypassMode":"PULL_REQUEST","actor":{
                "__typename":"App","databaseId":app,"slug":SLUG}}]
            and a.api("GET",f"/rulesets/{rid}?includes_parents=false")==rule)


def rule_map(rule):
    rows=a.complete_page(rule["rules"])
    by={x["type"]:x.get("parameters",{}) for x in rows}
    need(len(by)==len(rows),"Duplicate rule type")
    return by


def exact_dev_rule(rule,name):
    need(rule["name"]==name and rule["source"]==a.REPO
         and rule["source_type"]=="Repository" and rule["target"]=="branch"
         and rule["enforcement"]=="active" and rule["conditions"]==TARGET,
         "Wrong exact dev policy")


def mandatory_contract(rule):
    exact_dev_rule(rule,MANDATORY)
    by=rule_map(rule)
    need(set(by)=={"deletion","non_fast_forward","pull_request","required_status_checks"}
         and by["deletion"]==by["non_fast_forward"]=={},
         "Mandatory rules altered")
    p=by["pull_request"]
    # Proposed replacement only: native review count migration is NOT applied
    # or authorized by this code. Both role-specific semantic reviews are
    # still checked independently at the application layer.
    need(type(p["required_approving_review_count"]) is int
         and p["required_approving_review_count"]==0
         and p["dismiss_stale_reviews_on_push"] is True
         and p["require_last_push_approval"] is False
         and p["required_review_thread_resolution"] is True
         and p["require_code_owner_review"] is False
         and p.get("required_reviewers")==[]
         and p["allowed_merge_methods"]==["squash"],
         "Unexpected PR policy")
    checks=by["required_status_checks"]
    rows=checks["required_status_checks"]
    need(checks["strict_required_status_checks_policy"] is True
         and checks["do_not_enforce_on_create"] is False
         and len(rows)==len(EXPECTED_CHECKS)
         and {x["context"]:x["integration_id"] for x in rows}==EXPECTED_CHECKS,
         "CI or role source pins differ")
    need(rule.get("current_user_can_bypass")=="never"
         and g.ruleset_bypass_evidence(rule) in ("rest_empty","graphql_empty"),
         "Mandatory gate bypass unverified")
    return by


def policy(base,*,integrator):
    trusted()
    need(g.production_policy_observed(base),"Trusted main or non-dev confinement missing")
    inventory=a.complete_page(a.api("GET","/rulesets?includes_parents=false&per_page=100"))
    need(len(inventory)<=16 and len({x["id"] for x in inventory})==len(inventory),
         "Unbounded ruleset inventory")
    selected={}
    for name in (MANDATORY,EXCLUSIVE):
        ids=[x["id"] for x in inventory if x["name"]==name]
        need(len(ids)==1 and type(ids[0]) is int and ids[0]>0,"Missing unique "+name)
        row=a.api("GET",f"/rulesets/{ids[0]}?includes_parents=false")
        need(row["id"]==ids[0],"Ruleset ID drift")
        exact_dev_rule(row,name)
        selected[name]=row
    main,exclusive=selected[MANDATORY],selected[EXCLUSIVE]
    mandatory=mandatory_contract(main)
    extra=rule_map(exclusive)
    need(extra in ({"update":{}},{"update":{"update_allows_fetch_and_merge":False}}),
         "Exclusive exception must be update-only")
    need(exclusive.get("current_user_can_bypass")==("pull_requests_only" if integrator else "never")
         and exclusive_actor(exclusive,app_id()),"Complete exclusive actor inventory required")
    effective=a.complete_page(a.api("GET","/rules/branches/dev?per_page=100"))
    expected={(main["id"],k):p for k,p in mandatory.items()}
    expected.update({(exclusive["id"],k):p for k,p in extra.items()})
    need(len(effective)==len(expected)
         and all(x.get("ruleset_source")==a.REPO and x.get("ruleset_source_type")=="Repository" for x in effective)
         and {(x["ruleset_id"],x["type"]):x.get("parameters",{}) for x in effective}==expected,
         "Effective policy differs")
    need(all(a.api("GET",f"/rulesets/{r['id']}?includes_parents=false")==r for r in selected.values())
         and a.api("GET","/git/ref/heads/dev")["object"]["sha"]==base,
         "Policy or base drift")
    return {"mandatory_id":main["id"],"exclusive_id":exclusive["id"],"base":base,
            "app_id":app_id(),"mandatory_no_bypass":True,"actor_inventory_verified":True}


def paused_audit():
    trusted()
    need(os.getenv("GITHUB_EVENT_NAME")=="workflow_dispatch"
         and os.getenv("GASLUX_V4_AUDIT")=="true"
         and os.getenv("GASLUX_AUTONOMY_PAUSED")=="true"
         and all(os.getenv(x)=="false" for x in ("GASLUX_PRODUCTION_MERGE_ENABLED",
                    "GASLUX_APP_STATUS_GATES_ENABLED","GASLUX_V3_AUTHORITY_ENABLED"))
         and os.getenv("GASLUX_V4_MERGE_ENABLED")!="true",
         "Explicit paused audit only")
    identity=credential()
    base=a.api("GET","/git/ref/heads/dev")["object"]["sha"]
    need(a.valid_sha(base) and g.production_policy_observed(base)
         and g.strict_ruleset_protected(base,require_app_statuses=True),
         "Existing protection unverified")
    return {"schema":"gaslux-v4-paused-credential-audit","identity":identity,"base":base,
            "current_protections_verified":True,"read_only":True,
            "exclusive_production_policy_verified":False,"merge_authorized":False}


def receipts(number,role,scope,head,base):
    snap=v.snapshot(number,role,scope,head,base)
    rows,live=v.history(head,v.CONTEXTS)
    need(set(live)==set(v.ROLES),"Both independent statuses required")
    for k in v.ROLES:
        item=snap[k]
        need(item["state"]=="success","Independent evaluation not eligible")
        payload=v.transition(item["binding"],"success",rows,v.CONTEXTS)
        row=live[k]
        need(row["actor"]==v.ACTORS[k] and row["login"]=="gaslux-independent-"+k+"[bot]"
             and row["type"]=="Bot" and row["state"]=="success"
             and row["description"]==payload["description"],"Stale/wrong/withdrawn decision")
    need(v.snapshot(number,role,scope,head,base)==snap
         and v.history(head,v.CONTEXTS)==(rows,live),"Decision drift")
    return snap,rows,live


def exact_candidate(number,role,scope,head,base):
    p=v.v1.frozen(number,head,base)
    need(a.single_parent(head)==base and g.discover().get(number)==(role,scope,head),
         "Candidate identity/parent not exact")
    # A same-SHA alias outside the unique candidate association is rejected.
    need(a.api("GET","/git/ref/heads/"+p["head"]["ref"])["object"]["sha"]==head,
         "Candidate ref drift")
    safety,owners=v.v1.identities()
    row=g.inspect(number,role,scope,head,safety,owners[role],allow_ready=True)
    need((g.eligible_product(row) if scope in g.PRODUCT_SCOPES else g.eligible_test(row))
         and row["base"]==base,"CI, scope, reviews or VM acceptance absent")
    return p


def execution_context(base):
    trusted()
    need(os.getenv("GASLUX_AUTONOMY_PAUSED")=="false"
         and os.getenv("GASLUX_V3_AUTHORITY_ENABLED")=="true"
         and os.getenv("GASLUX_V4_MERGE_ENABLED")=="true"
         and os.getenv("GASLUX_PRODUCTION_MERGE_ENABLED")=="false"
         and os.getenv("GASLUX_APP_STATUS_GATES_ENABLED")=="false"
         and os.getenv("GASLUX_V4_OPERATIONAL_APPROVAL_SHA")==os.getenv("GITHUB_SHA"),
         "No approved V4 activation; legacy merge routes must stay disabled")
    credential()
    return policy(base,integrator=True)


def integrate_one(number,role,scope,head,base):
    # Future adapter, intentionally no workflow/CLI execute route in this PR.
    rules=execution_context(base)
    p=exact_candidate(number,role,scope,head,base)
    proof=receipts(number,role,scope,head,base)
    if p.get("draft") is True:
        # Do not change ready state here: it may trigger CI/evidence changes.
        return {"status":"ready_transition_required","pr":number,"merge_authorized":False}
    need(p.get("draft") is False and p.get("mergeable_state")=="clean","GitHub not ready")
    tree=a.api("GET",f"/git/commits/{head}")["tree"]["sha"]
    need(a.valid_sha(tree),"Invalid tree")
    need(execution_context(base)==rules and exact_candidate(number,role,scope,head,base)==p
         and receipts(number,role,scope,head,base)==proof,"Final authorization drift")
    result=a.api("PUT",f"/pulls/{number}/merge",{"sha":head,"merge_method":"squash"})
    merged=result.get("sha")
    need(result.get("merged") is True and a.valid_sha(merged),"Merge not confirmed; do not retry")
    c=a.api("GET",f"/git/commits/{merged}")
    closed=a.api("GET",f"/pulls/{number}")
    need([x["sha"] for x in c["parents"]]==[base] and c["tree"]["sha"]==tree
         and closed["merged"] is True and closed["state"]=="closed"
         and closed["merge_commit_sha"]==merged and closed["head"]["sha"]==head
         and closed["base"]["ref"]=="dev"
         and a.api("GET","/git/ref/heads/dev")["object"]["sha"]==merged,
         "Post-merge receipt mismatch; stop and investigate")
    return {"status":"merged","pr":number,"head":head,"base":base,"merge_sha":merged,
            "pr_closure_verified":True,"reviewed_tree_verified":True,"release_eligible":False}


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--paused-audit",action="store_true",required=True)
    p.parse_args()
    print(json.dumps(paused_audit(),sort_keys=True))
