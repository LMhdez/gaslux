"""Sole protected hosted authority controller (bootstrap; disabled by default).

One frozen workflow runs this code. Other ledger writers and merge
credential copies are forbidden by reviewed deployment. Never execute
candidate code in this job. All decisions and status/merge intents persist
in the respective protected Git histories; no artifact restores authority.
"""
import json
import os
from pathlib import Path
import tempfile
import sys
import authority_contract as a
import authority_publisher as publisher
import github_authority_transport as g
import github_main_merge as gm
import github_witness as gw
import hosted_client as hc
import hosted_evaluator as evaluator
import hosted_merge_executor as executor
import hosted_publisher_state as state
import hosted_safety as h
import main_bootstrap as v

def fact_view(n):
    p=v.api("/pulls/"+str(n))
    return {"number":p["number"],"id":p["id"],"state":p["state"],"merged":p["merged"],
            "draft":p["draft"],"head":p["head"]["sha"],"head_ref":p["head"]["ref"],
            "head_repo":p["head"]["repo"]["id"],"base_ref":p["base"]["ref"],
            "base_repo":p["base"]["repo"]["id"],"main":v.ref("main")}

def invalid_facts(e,row):
    head,tree,branch,pid=v.ALLOW[e["pr"]]
    v.need(row["number"]==e["pr"] and row["id"]==pid,"PR identity drift")
    return (row["head"]!=head or row["head_ref"]!=branch or row["head_repo"]!=v.RID
            or row["base_ref"]!="main" or row["base_repo"]!=v.RID
            or row["state"]!="open" or row["merged"] is not False
            or row["draft"] is not False or row["main"]!=e["base"])

def refresh_revocations(writer,reader,merger):
    """Bounded independent factual revocation evaluator, not general semantics.

    A reproducible definite adverse fact or changed exact evidence is signed
    terminally; an unavailable/ambiguous read blocks new authority but never
    fabricates a signed decision. Check all retained approvals independently.
    """
    errors=[]
    _,_,states,_,_,_,_=writer.snapshot_full()
    for row in sorted(states.values(),key=lambda x:x["evidence"]["pr"]):
        if row["decision"]!="approve": continue
        e=row["evidence"]
        n=e["pr"]
        try:
            first=fact_view(n)
            v.need(first==fact_view(n),"Revocation evidence unstable")
            if first["state"]=="closed" and first["merged"] is True:
                v.need(merger is not None and merger.receipt(e,reader) is not None,
                       "Unexpected merged PR")
                continue
            if invalid_facts(e,first):
                writer.append(e,"withdraw")
                continue
            # Only exact stable independently observed evidence changes
            # authorize revocation. API/CI errors do not become decisions.
            observed=reader.snapshot(n)
            v.need(observed==reader.snapshot(n),"Revocation snapshot unstable")
            if observed!=e:
                writer.append(e,"withdraw")
        except Exception as exc:
            errors.append({"pr":n,"stage":"revocation_evaluation","error":type(exc).__name__})
    return errors

def feed_cycle(reader,journal,*,deny_only):
    entries,pem=reader.hosted_safety.poll()
    return publisher.cycle(reader,journal,entries,pem,deny_only=deny_only)

def run(writer,reader,merger,journal):
    executor.controller_boundary(writer)
    errors=[]
    results=[]
    # Ingest known terminal denials before any production API calls. A
    # failure cannot authorize positives, but independent revocation
    # assessment may still discover and deliver additional denials.
    try: results.extend(feed_cycle(reader,journal,deny_only=True))
    except publisher.CycleBlocked as exc:
        results.extend(exc.results)
        errors.extend(exc.errors)
    errors.extend(refresh_revocations(writer,reader,merger))
    try: results.extend(feed_cycle(reader,journal,deny_only=True))
    except publisher.CycleBlocked as exc:
        results.extend(exc.results)
        errors.extend(exc.errors)
    if errors:
        return {"state":"blocked","results":results,"unresolved":errors,"merge_authorized":False}
    _,_,states,_,active,_,incidents=writer.snapshot_full()
    if incidents:
        return {"state":"incident","results":results,"merge_authorized":False}
    if active is not None:
        if merger is None:
            return {"state":"merge_unresolved","results":results,"merge_authorized":False}
        executor.boundary(writer)
        with journal.exclusive():
            recovered=executor.recover(writer,reader,merger)
        return {"state":"reconciliation","result":recovered,"merge_authorized":False}
    # Reconcile prior published receipts before issuing a new decision.
    try: results.extend(feed_cycle(reader,journal,deny_only=False))
    except publisher.CycleBlocked as exc:
        return {"state":"blocked","results":results+exc.results,
                "unresolved":exc.errors,"merge_authorized":False}
    for n in v.ALLOW:
        pr=v.api("/pulls/"+str(n))
        if pr["state"]=="closed" and pr["merged"] is True:
            v.need(merger is not None and reader._merged_chain(),"Unverified prior integration")
            continue
        v.need(pr["state"]=="open" and pr["merged"] is False,"Unexpected closure")
        head=v.ALLOW[n][0]
        if head not in states:
            if n not in evaluator.REVIEWED_EVIDENCE:
                return {"state":"awaiting_independent_evidence_review","pr":n,"merge_authorized":False}
            evaluator.evaluate(writer,n)
        else:
            v.need(states[head]["decision"]=="approve","Terminal Safety denial")
        # Refresh complete retained decisions after a newly committed A.
        try: results.extend(feed_cycle(reader,journal,deny_only=False))
        except publisher.CycleBlocked as exc:
            return {"state":"blocked","results":results+exc.results,
                    "unresolved":exc.errors,"merge_authorized":False}
        if not executor.BOOTSTRAP_MERGE_ENABLED:
            return {"state":"publication_only","pr":n,"results":results,"merge_authorized":False}
        v.need(merger is not None,"Missing merge transport")
        e=evaluator.exact_evidence(n)
        merged=executor.execute(writer,reader,merger,journal,e)
        return {"state":"merge_operation","result":merged,"results":results}
    return {"state":"bootstrap_complete","results":results,"merge_authorized":False}

def install_secret(root,name,env):
    value=os.environ[env]
    v.need(isinstance(value,str) and 0<len(value)<=65536,"Missing or oversized protected credential")
    path=root/name
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w") as f: f.write(value)
    return path

def main():
    os.umask(0o077)
    v.need(sys.argv[1:]==[],"No caller-supplied controller arguments")
    evaluator.boundary()
    v.need(executor.HOSTED_CONTROLLER_ENABLED is True and g.SAFETY_BACKEND=="hosted",
           "Hosted controller not activated")
    writer=h.HostedWriter(os.environ["SAFETY_LEDGER_TOKEN"],os.environ["SAFETY_SIGNING_KEY"].encode("ascii"))
    executor.controller_boundary(writer)
    with tempfile.TemporaryDirectory(prefix="gaslux-authority-") as tmp:
        # Only transient credential files, never journal authority. No
        # caller-selected path, candidate checkout or artifact persistence.
        root=Path(tmp).resolve()
        install_secret(root,"publisher-app.pem","GASLUX_STATUS_APP_KEY")
        install_secret(root,"admin-read-token","GASLUX_POLICY_READ_TOKEN")
        install_secret(root,"safety-control-read-token","GASLUX_SAFETY_CONTROL_READ_TOKEN")
        install_secret(root,"publisher-github-witness-token","GASLUX_PUBLISHER_LEDGER_TOKEN")
        fd=os.open(root/"safety-signing-public.pem",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,"wb") as f: f.write(writer.pem)
        g.ROOT=gm.ROOT=gw.ROOT=hc.ROOT=root
        reader=g.GitHubAuthority()
        merger=None
        if executor.BOOTSTRAP_MERGE_ENABLED:
            install_secret(root,"main-merge-app.pem","GASLUX_MAIN_MERGE_APP_KEY")
            merger=gm.MainMerge()
        j=state.HostedJournal(state.SnapshotStore())
        try:
            result=run(writer,reader,merger,j)
            print(json.dumps(result,sort_keys=True))
            if result["state"] in ("blocked","incident","merge_unresolved"):
                raise SystemExit(1)
        finally: j.close()

if __name__=="__main__":
    main()
