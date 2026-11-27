"""Deterministic hosted bootstrap evaluator.

Only exact #436--438 compositions already independently reviewed are in
scope. This does not assess arbitrary new candidate code. Never execute
candidate code or treat user-supplied review text as authorization.
"""
import os
import hosted_safety as h
import authority_contract as a
import main_bootstrap as v

# Populate ONLY in reviewed frozen control release, after independent
# review of exact PR/HEAD/tree and approved evidence digest. No input override.
REVIEWED_EVIDENCE={}
RELEASE_REF=None
RELEASE_SHA=None

def boundary():
    h.pins()
    v.need(isinstance(RELEASE_REF,str) and RELEASE_REF.startswith("refs/heads/") and
           isinstance(RELEASE_SHA,str) and v.SHA.fullmatch(RELEASE_SHA) and
           os.environ.get("GITHUB_ACTIONS")=="true" and
           os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted" and
           os.environ.get("GITHUB_REPOSITORY")==h.CONTROL_REPO and
           os.environ.get("GITHUB_REPOSITORY_ID")==str(h.CONTROL_ID) and
           os.environ.get("GITHUB_REF")==RELEASE_REF and os.environ.get("GITHUB_SHA")==RELEASE_SHA and
           os.environ.get("GITHUB_EVENT_NAME") in ("schedule","workflow_dispatch"),
           "Untrusted hosted evaluator boundary")

def exact_evidence(n):
    v.need(n in v.ALLOW and n in REVIEWED_EVIDENCE and
           isinstance(REVIEWED_EVIDENCE[n],str) and a.HEX64.fullmatch(REVIEWED_EVIDENCE[n]),
           "No independently reviewed evidence pin")
    v.need(v.ref(v.REF)==a.EVIDENCE_ENGINE,"Evidence verifier drift")
    v.native_policy()
    v.verifier_policy()
    e=v.snapshot(n,a.EVIDENCE_ENGINE)
    a.evidence_shape(e)
    v.need(e["draft"] is False and v.digest(e)==REVIEWED_EVIDENCE[n],
           "Unreviewed or stale composition")
    v.need(v.snapshot(n,a.EVIDENCE_ENGINE)==e and v.ref(v.REF)==a.EVIDENCE_ENGINE,
           "Live evidence drift")
    return e

def evaluate(writer,n):
    boundary()
    e=exact_evidence(n)
    return writer.append(e,"approve")

def main():
    boundary()
    # Deliberately no dispatch input for arbitrary code, evidence or decision.
    # Only a single first open reviewed bootstrap PR per run. No authority
    # to mark ready or merge; those actions require separate reviewed gates.
    import sys
    import json
    v.need(sys.argv[1:]==[],"Unexpected evaluator arguments")
    token=os.environ["SAFETY_LEDGER_TOKEN"]
    key=os.environ["SAFETY_SIGNING_KEY"].encode("ascii")
    writer=h.HostedWriter(token,key)
    for n in v.ALLOW:
        row=v.api("/pulls/"+str(n))
        if row["state"]=="closed" and row["merged"] is True: continue
        v.need(row["state"]=="open" and row["merged"] is False,"Unexpected closure")
        if n not in REVIEWED_EVIDENCE:
            print(json.dumps({"pr":n,"state":"awaiting_independent_evidence_review"}))
            return
        tip,entry=evaluate(writer,n)
        print(json.dumps({"pr":n,"state":"signed","ledger_tip":tip}))
        return
    print(json.dumps({"state":"bootstrap_complete"}))

if __name__=="__main__":
    main()
