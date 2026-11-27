"""Bounded live publisher service entrypoint, disabled by deployment pins."""
import json
from pathlib import Path
import sys
import os
import authority_contract as a
import authority_anchor as anchor
import github_authority_transport as g
import safety_client as safety
import safety_feed as feed
import main_bootstrap as v

JOURNAL=Path("/var/lib/gaslux-authority-publisher/receipts.sqlite")

class CycleBlocked(ValueError):
    def __init__(self,results,errors):
        self.results=results
        self.errors=errors
        super().__init__("Unresolved authority operations; new approvals blocked")

def reconcile_existing(transport,journal,e,digest):
    h=e["head"]
    row=journal.row(h)
    v.need(row is not None and row[0]==v.canonical(e) and row[1]==digest
           and row[2] is None,"Existing approval evidence or denial mismatch")
    a.identity(transport)
    if row[3] in ("approval_reserved","approval_posting"):
        a.reconcile_approval(transport,journal,e)
        row=journal.row(h)
    v.need(row[3] in ("approved","consumed"),"Unresolved or quarantined approval")
    rows,successes,failures=a.historical_rows(transport,e,row)
    v.need(len(successes)==1 and not failures and row[4]==row[5]==successes[0]["id"],
           "Missing exact authenticated approval receipt")
    receipt=transport.merged_receipt(e)
    if receipt is not None:
        # This adapter proves exact authenticated PR closure, approved
        # composition and the complete bounded ancestry to live main.
        if row[3]=="approved":
            journal.change(h,("approved",),"consumed")
        return {"pr":e["pr"],"state":"consumed","merge":receipt["merge"]}
    v.need(row[3]=="approved" and a.eligible(transport,e),
           "Consumed receipt missing or approval no longer eligible")
    return {"pr":e["pr"],"state":"already_approved"}

def cycle(transport,journal,entries,pem):
    results=[]
    errors=[]
    verified=[]
    v.need(type(entries) is list and len(entries)<=len(v.ALLOW),"Invalid decision feed size")
    for row in entries:
        try:
            e,d,sig=row["evidence"],row["decision"],row["signature_b64"]
            digest=a.verify(e,d,sig,pem)
            verified.append((e,d,sig,digest))
        except Exception as exc:
            errors.append({"stage":"verify","error":type(exc).__name__})
    # A malformed or duplicate feed can never authorize success; still
    # reserve and attempt each authenticated distinct denial.
    heads=[e["head"] for e,_,_,_ in verified]
    if len(set(heads))!=len(heads):
        errors.append({"stage":"feed","error":"DuplicateHead"})
    denials=sorted((x for x in verified if x[1]=="withdraw"),key=lambda x:x[0]["pr"])
    approvals=sorted((x for x in verified if x[1]=="approve"),key=lambda x:x[0]["pr"])
    with journal.exclusive() as lease:
        # Persist ALL verified denial intents before ANY remote request,
        # holding the same lease used by future integration. A fault in
        # one head does not prevent attempts for other heads.
        reserved=[]
        for e,d,sig,digest in denials:
            try:
                journal.reserve_denial(e,digest)
                reserved.append((e,d,sig,digest))
            except Exception as exc:
                errors.append({"pr":e["pr"],"stage":"reserve_denial","error":type(exc).__name__})
        for e,d,sig,digest in reserved:
            try:
                results.append(a.process_locked(transport,journal,e,d,sig,pem,lease))
            except Exception as exc:
                errors.append({"pr":e["pr"],"stage":"withdraw","error":type(exc).__name__})
        if journal.heads()-set(heads):
            errors.append({"stage":"feed","error":"MissingRetainedDecision"})
        if errors:
            raise CycleBlocked(results,errors)
        # Reconcile every existing positive intent before any new success.
        # Never repeat a success POST, even after a lost response.
        pending=[]
        for e,d,sig,digest in approvals:
            try:
                if journal.row(e["head"]) is None:
                    pending.append((e,d,sig))
                else:
                    results.append(reconcile_existing(transport,journal,e,digest))
            except Exception as exc:
                errors.append({"pr":e["pr"],"stage":"reconcile","error":type(exc).__name__})
        if journal.unresolved_heads():
            errors.append({"stage":"journal","error":"UnresolvedIntent"})
        if errors:
            raise CycleBlocked(results,errors)
        for e,d,sig in pending:
            try:
                results.append(a.process_locked(transport,journal,e,d,sig,pem,lease))
            except Exception as exc:
                errors.append({"pr":e["pr"],"stage":"approve","error":type(exc).__name__})
                raise CycleBlocked(results,errors) from exc
    return results

def main():
    os.umask(0o077)
    v.need(sys.argv[1:]==["cycle"],"Use cycle; journal initialization is separate")
    if g.SAFETY_BACKEND=="hosted":
        from hosted_client import HostedClient
        from github_witness import ScopedPublisherWitness
        j=a.Journal(JOURNAL,witness=ScopedPublisherWitness())
        reader=HostedClient()
    else:
        v.need(g.SAFETY_BACKEND=="ssh","Safety backend not provisioned")
        j=a.Journal(JOURNAL)
        reader=safety.SafetyClient()
    try:
        entries,pem=reader.poll()
        t=g.GitHubAuthority()
        try:
            results=cycle(t,j,entries,pem)
        except CycleBlocked as exc:
            print(json.dumps({"results":exc.results,"unresolved":exc.errors,
                              "merge_authorized":False},sort_keys=True))
            raise SystemExit(1)
        print(json.dumps({"results":results,"merge_authorized":False},sort_keys=True))
    finally: j.close()

if __name__=="__main__":
    main()
