#!/usr/bin/env python3
"""Bounded production main bootstrap: read-only evidence audit, no candidate execution."""
import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import urllib.request
import urllib.parse

REPO = "LMhdez/gaslux"
RID = 1460159259
REF = "infra/main-bootstrap-verifier-v1"
BASE = "84cb41e1b005280450a3828a8162380a4764b416"
WORKFLOW = 427077540
RULE = 28152434
CONTEXT = "gaslux-main/infrastructure-v1"
ALLOW = {
    436: ("bdd4f6b5876fa1a38f15be2bae4e301a8dea0cbb", "21c2ce2bc343cfd6b1c37f9c2eeddabde18d1272", "fix/production-activation-live-confinement", 5518779705),
    437: ("9cf6995114748766553b2f406ab691dfac8a3f22", "729cc4d899909781c820863d71dc938ac821b106", "feat/authority-v3-paused-migration", 5523976062),
    438: ("bef33b7ebf9e4aedd7de5f2043b266a39070e681", "e80a871e70417655fb9dc7e602ec47f3c3d61360", "feat/dedicated-integrator-v4", 5524860202),
}
# No independent Safety signing key or production infrastructure App provisioned.
# Deliberately fail closed until a separately reviewed immutable trust root exists.
SAFETY_KEY_SHA256 = None
INFRA_APP_ID = None
INFRA_ACTOR_ID = None
SHA = re.compile(r"[0-9a-f]{40}")

def need(condition, msg):
    if not condition:
        raise ValueError(msg)

def canonical(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def digest(x):
    return hashlib.sha256(canonical(x)).hexdigest()

def api(path, *, paged=False):
    need(path == "" or path.startswith("/"), "Bad API route")
    need("://" not in path and ".." not in path, "Bad API route")
    req = urllib.request.Request("https://api.github.com/repos/" + REPO + path, headers={
        "Authorization": "Bearer " + os.environ["GH_TOKEN"],
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(req, timeout=25) as response:
        raw = response.read(8000001)
        need(len(raw) <= 8000000, "Oversize API response")
        next_page = bool(re.search(r'rel="next"', response.headers.get("Link", "")))
        row = json.loads(raw)
        if paged:
            return row, next_page
        need(not next_page, "Incomplete API page")
        return row

def ref(branch):
    obj = api("/git/ref/heads/" + branch)["object"]
    need(obj["type"] == "commit" and SHA.fullmatch(obj["sha"]), "Invalid ref")
    return obj["sha"]

def commit(sha):
    need(SHA.fullmatch(sha), "Invalid commit")
    row = api("/git/commits/" + sha)
    need(row["sha"] == sha and SHA.fullmatch(row["tree"]["sha"]), "Commit mismatch")
    return row

def boundary():
    need(os.environ.get("GITHUB_ACTIONS") == "true"
         and os.environ.get("GITHUB_REPOSITORY") == REPO
         and os.environ.get("GITHUB_REPOSITORY_ID") == str(RID)
         and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
         and os.environ.get("GITHUB_REF") == "refs/heads/" + REF, "Wrong execution boundary")
    verifier = ref(REF)
    need(os.environ.get("GITHUB_SHA") == verifier == os.environ.get("VERIFIER_PIN")
         and SHA.fullmatch(verifier), "Verifier ref/pin drift")
    need(os.environ.get("PAUSE") == "true" and all(os.environ.get(k) == "false" for k in
         ("PROD_MERGE", "LEGACY", "V3", "V4")), "Pause flags not explicit")
    repo = api("")
    need(repo["id"] == RID and repo["full_name"] == REPO and not repo["fork"], "Wrong repository")
    return verifier

def native_policy():
    m = api("/rulesets/" + str(RULE))
    need(m["id"] == RULE and m["name"] == "gaslux-main-protection"
         and m["source"] == REPO and m["source_type"] == "Repository"
         and m["target"] == "branch" and m["enforcement"] == "active"
         and m["conditions"] == {"ref_name":{"include":["refs/heads/main"],"exclude":[]}},
         "Native main rule changed")
    # GitHub can omit bypass inventory for read-only tokens. Never claim
    # complete actor proof in that case. The audit may report unknown.
    need(m.get("current_user_can_bypass") == "never", "Audit actor can bypass native rule")
    if "bypass_actors" in m:
        need(m["bypass_actors"] == [], "Native rule has bypass")
    rules = {x["type"]:x.get("parameters", {}) for x in m["rules"]}
    need(len(rules) == len(m["rules"]) and set(rules) ==
         {"deletion","non_fast_forward","pull_request","required_status_checks"}, "Wrong native rule set")
    p, s = rules["pull_request"],rules["required_status_checks"]
    need(p["required_approving_review_count"] >= 1 and p["require_last_push_approval"] is True
         and p["dismiss_stale_reviews_on_push"] is True and p["required_review_thread_resolution"] is True,
         "Native review gate missing")
    need(s["strict_required_status_checks_policy"] is True
         and {"context":"adversarial_contracts","integration_id":15368} in s["required_status_checks"],
         "Strict native CI missing")
    return {"ruleset":RULE, "rules":rules, "bypass_inventory_verified": "bypass_actors" in m}

def verifier_policy():
    rows = api("/rulesets?includes_parents=true&per_page=100")
    hits = [r for r in rows if r["name"] == "gaslux-main-verifier-immutable-v1"]
    need(len(rows) < 100 and len(hits) == 1,"Missing immutable verifier rule")
    m = api("/rulesets/" + str(hits[0]["id"]))
    need(m["source"] == REPO and m["source_type"] == "Repository"
         and m["target"] == "branch" and m["enforcement"] == "active"
         and m["conditions"] == {"ref_name":{"include":["refs/heads/"+REF],"exclude":[]}}
         and m.get("current_user_can_bypass") == "never","Verifier protection drift")
    if "bypass_actors" in m:
        need(m["bypass_actors"] == [], "Verifier bypass exists")
    expected = {"update","deletion","non_fast_forward"}
    need(len(m["rules"]) == 3 and {x["type"] for x in m["rules"]} == expected
         and all(not x.get("parameters") for x in m["rules"]),"Verifier rule mismatch")
    branch = urllib.parse.quote(REF,safe="")
    effective = api("/rules/branches/"+branch+"?per_page=100")
    own = [x for x in effective if x["ruleset_id"] == m["id"]]
    need(len(effective) < 100 and len(own) == 3 and {x["type"] for x in own} == expected
         and all(x["ruleset_source"] == REPO and x["ruleset_source_type"] == "Repository" for x in own),
         "Immutable verifier rule not effective")
    return {"ruleset":m["id"],"types":sorted(expected),
            "bypass_inventory_verified":"bypass_actors" in m}

def all_open_prs():
    rows = []
    ids = set()
    for page in range(1,21):
        items, more = api(f"/pulls?state=open&sort=created&direction=asc&per_page=100&page={page}",paged=True)
        need(isinstance(items,list) and len(items) <= 100 and (not more or len(items) == 100),
             "Incomplete PR page")
        for p in items:
            need(type(p["id"]) is int and p["id"] not in ids and p["state"] == "open",
                 "PR inventory drift")
            ids.add(p["id"])
            rows.append(p)
        if not more:
            return rows
    raise ValueError("PR inventory exceeds audit bound")

def unique_candidate(rows, n, pid, head, branch):
    # A commit status is SHA-scoped, not PR-scoped. Reject even a second
    # PR from another repository sharing the SHA, irrespective of target.
    matches = [p for p in rows if p["head"]["sha"] == head]
    need(len(matches) == 1,"Ambiguous candidate SHA")
    p = matches[0]
    need(p["id"] == pid and p["number"] == n and p["state"] == "open"
         and p["head"]["ref"] == branch and p["head"]["repo"]["id"] == RID
         and p["base"]["ref"] == "main" and p["base"]["repo"]["id"] == RID,
         "Candidate association or target drift")
    return True

class NoTokenRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        dest = urllib.parse.urlsplit(newurl)
        need(dest.scheme == "https" and dest.username is None and dest.password is None
             and dest.port in (None,443) and dest.hostname is not None
             and (dest.hostname.endswith(".blob.core.windows.net")
                  or dest.hostname.endswith(".actions.githubusercontent.com")
                  or dest.hostname == "api.github.com"),
             "Untrusted job log redirect")
        # The signed download URL is sufficient; do not forward GH_TOKEN.
        return urllib.request.Request(newurl,headers={"Accept":"application/octet-stream"})

def checkout_evidence(raw, n, composition):
    need(isinstance(raw,bytes) and len(raw) <= 8000000 and SHA.fullmatch(composition),"Invalid job log")
    lines = [re.sub(r"^\d{4}-\d{2}-\d{2}T\S+Z\s+", "", line).strip()
             for line in raw.decode("utf-8").splitlines()]
    target = f"refs/remotes/pull/{n}/merge"
    fetch = [i for i,x in enumerate(lines) if x.startswith("[command]/usr/bin/git ")
             and ("+"+composition+":"+target) in x]
    checkout = [i for i,x in enumerate(lines) if x == "[command]/usr/bin/git checkout --progress --force "+target]
    logs = [i for i,x in enumerate(lines) if x == "[command]/usr/bin/git log -1 --format=%H"]
    need(len(fetch)==len(checkout)==len(logs)==1 and fetch[0]<checkout[0]<logs[0]
         and logs[0]+1 < len(lines) and lines[logs[0]+1] == composition,
         "Actual checkout composition not proven")
    need(any("Run actions/checkout@11d5960a326750d5838078e36cf38b85af677262" in x
             for x in lines[:fetch[0]]),"Pinned checkout not observed")
    return {"tested_composition":composition,"job_log_sha256":hashlib.sha256(raw).hexdigest()}

def job_log(job_id):
    need(type(job_id) is int and job_id > 0,"Invalid job id")
    req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/actions/jobs/{job_id}/logs",
            headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],
                     "Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    opener = urllib.request.build_opener(NoTokenRedirect())
    with opener.open(req,timeout=25) as response:
        raw = response.read(8000001)
        need(len(raw) <= 8000000,"Oversize job log")
        return raw

def earlier_merges(n):
    current = BASE
    receipts = []
    for i, (head,tree,branch,pid) in ALLOW.items():
        if i >= n:
            break
        p = api("/pulls/" + str(i))
        need(p["id"] == pid and p["number"] == i and p["state"] == "closed" and p["merged"] is True
             and p["head"]["sha"] == head and p["base"]["ref"] == "main"
             and p["head"]["repo"]["id"] == p["base"]["repo"]["id"] == RID, "Predecessor not integrated")
        c = commit(p["merge_commit_sha"])
        need([x["sha"] for x in c["parents"]] == [current,head] and c["tree"]["sha"] == tree,
             "Predecessor composition mismatch")
        current = c["sha"]
        receipts.append({"pr":i,"head":head,"merge":current,"tree":tree})
    need(ref("main") == current, "Live main not exact preceding approved composition")
    return current, receipts

def exact_ci(n, p, base, head, composition):
    data = api("/actions/workflows/" + str(WORKFLOW) +
               "/runs?event=pull_request&head_sha=" + head + "&per_page=100")
    need(data["total_count"] == len(data["workflow_runs"]) < 100, "Incomplete CI inventory")
    def exact(r):
        links = r["pull_requests"]
        return (r["workflow_id"] == WORKFLOW and r["event"] == "pull_request"
                and r["head_sha"] == head and r["head_repository"]["id"] == RID
                and r["repository"]["id"] == RID and len(links) == 1
                and links[0]["id"] == p["id"] and links[0]["number"] == n
                and links[0]["head"]["sha"] == head and links[0]["head"]["repo"]["id"] == RID
                and links[0]["base"]["sha"] == base and links[0]["base"]["ref"] == "main"
                and links[0]["base"]["repo"]["id"] == RID)
    rows = [r for r in data["workflow_runs"] if exact(r)]
    need(rows, "No CI bound to current base and exact PR")
    r = max(rows, key=lambda x:(x["run_number"],x["run_attempt"],x["id"]))
    need(r["status"] == "completed" and r["conclusion"] == "success", "Latest composition CI not successful")
    jobs = api(f"/actions/runs/{r['id']}/attempts/{r['run_attempt']}/jobs?per_page=100")
    need(jobs["total_count"] == len(jobs["jobs"]) < 100, "Incomplete CI jobs")
    hits = [j for j in jobs["jobs"] if j["name"] == "adversarial_contracts"]
    need(len(hits) == 1 and hits[0]["status"] == "completed" and hits[0]["conclusion"] == "success"
         and hits[0]["head_sha"] == head, "Exact contract job missing")
    j = hits[0]
    checks = api("/commits/" + head + "/check-runs?per_page=100")
    need(checks["total_count"] == len(checks["check_runs"]) < 100,"Incomplete check runs")
    matched = [x for x in checks["check_runs"] if x["id"] == j["id"]]
    need(len(matched) == 1,"Exact check run missing")
    check = matched[0]
    need(check["app"]["id"] == 15368 and check["head_sha"] == head
         and check["name"] == j["name"] and check["conclusion"] == "success"
         and check["check_suite"]["id"] == r["check_suite_id"], "Wrong check source")
    observed = checkout_evidence(job_log(j["id"]),n,composition)
    return {"workflow":WORKFLOW,"run":r["id"],"attempt":r["run_attempt"],"job":j["id"],
            "suite":r["check_suite_id"],"base":base,"head":head,**observed}

def snapshot(n, verifier):
    need(n in ALLOW, "Outside bounded bootstrap")
    head,tree,branch,pid = ALLOW[n]
    base,predecessors = earlier_merges(n)
    p = api("/pulls/" + str(n))
    need(p["id"] == pid and p["number"] == n and p["state"] == "open" and p["merged"] is False
         and p["base"]["ref"] == "main" and p["base"]["sha"] == base
         and p["head"]["ref"] == branch and p["head"]["sha"] == head
         and p["head"]["repo"]["id"] == p["base"]["repo"]["id"] == RID
         and ref(branch) == head and p["mergeable"] is True, "Candidate or base drift")
    need(commit(head)["tree"]["sha"] == tree, "Unapproved candidate tree")
    m = commit(p["merge_commit_sha"])
    need([x["sha"] for x in m["parents"]] == [base,head] and m["tree"]["sha"] == tree,
         "Exact composed tree not approved")
    unique_candidate(all_open_prs(),n,pid,head,branch)
    ci = exact_ci(n,p,base,head,m["sha"])
    need(ref("main") == base and ref(branch) == head and ref(REF) == verifier,"Snapshot drift")
    return {"schema":"gaslux-main-bootstrap-v1","repository":REPO,"repository_id":RID,"target":"main",
            "pr":n,"pr_id":pid,"head":head,"base":base,"tree":tree,"composition":m["sha"],
            "predecessors":predecessors,"verifier":verifier,"ci":ci,"draft":p["draft"]}

def decision_payload(evidence, decision):
    need(decision in ("approve","withdraw"), "Invalid decision")
    return {"schema":"gaslux-independent-safety-v1","role":"infrastructure-safety",
            "decision":decision,"evidence":evidence}

def verify_signed_decision(evidence, decision, signature_b64, public_key_pem):
    # The key fingerprint is an immutable separately reviewed trust root,
    # never read from the PR, comment, dispatch input, or mutable variable.
    need(isinstance(SAFETY_KEY_SHA256,str) and re.fullmatch(r"[0-9a-f]{64}",SAFETY_KEY_SHA256),
         "Independent signing trust root not provisioned")
    need(hashlib.sha256(public_key_pem).hexdigest() == SAFETY_KEY_SHA256, "Untrusted Safety key")
    sig = base64.b64decode(signature_b64, validate=True)
    need(len(sig) == 64, "Invalid Ed25519 signature length")
    with tempfile.TemporaryDirectory() as d:
        paths = [os.path.join(d,x) for x in ("pub.pem","message","signature")]
        for path,content in zip(paths,(public_key_pem,canonical(decision_payload(evidence,decision)),sig)):
            with open(path,"wb") as f:
                f.write(content)
        rc = subprocess.run(["openssl","pkeyutl","-verify","-pubin","-inkey",paths[0],
                             "-rawin","-in",paths[1],"-sigfile",paths[2]],
                            timeout=10,capture_output=True)
        need(rc.returncode == 0, "Independent Safety signature invalid")
    return digest(decision_payload(evidence,decision))

def status_marker(evidence, decision_digest, state):
    need(state in ("success","failure") and re.fullmatch(r"[0-9a-f]{64}",decision_digest),"Invalid receipt")
    return f"MAIN-V1:{evidence['pr']}:{evidence['base']}:{decision_digest}:{state}"

def validate_transition(rows, evidence, approve_digest, withdraw_digest, state, actor_id):
    need(isinstance(actor_id,int) and actor_id > 0 and len(rows) < 100
         and len({r["id"] for r in rows}) == len(rows),"Incomplete history or invalid issuer")
    for row in rows:
        expected = approve_digest if row["state"] == "success" else withdraw_digest
        need(row["context"] == CONTEXT and row["creator"]["id"] == actor_id
             and row["creator"]["type"] == "Bot" and row["state"] in ("success","failure")
             and expected is not None and row["description"] == status_marker(evidence,expected,row["state"]),
             "Untrusted receipt or wrong binding")
    if state == "success":
        need(not any(r["state"] == "failure" for r in rows),"Terminal withdrawal")
        need(not rows,"Already issued: do not replay")
    else:
        need(state == "failure" and rows and rows[0]["state"] == "success"
             and not any(r["state"] == "failure" for r in rows),"No active receipt to withdraw")
    return True

def main():
    # This revision has NO status-writing or merge path, irrespective of inputs.
    verifier = boundary()
    n = int(os.environ["PR"])
    policy = native_policy()
    immutable = verifier_policy()
    first = snapshot(n,verifier)
    second = snapshot(n,verifier)
    need(first == second and policy == native_policy() and immutable == verifier_policy()
         and boundary() == verifier,"Evidence or policy drift")
    print(json.dumps({"evidence":first,"evidence_sha256":digest(first),"native":policy,
        "verifier_protection":immutable,"independent_signer_provisioned":False,"infrastructure_app_provisioned":False,
        "authorization_published":False,"merge_authorized":False},sort_keys=True))

if __name__ == "__main__":
    main()
