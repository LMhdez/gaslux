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

def cycle(transport,journal,entries,pem):
    results=[]
    # Verify each retained decision again. A failed withdrawal aborts this
    # cycle before any approval, and remains in the source ledger for retry.
    entries=sorted(entries,key=lambda r:(r["decision"]!="withdraw",r["evidence"]["pr"]))
    for row in entries:
        e,d,sig=row["evidence"],row["decision"],row["signature_b64"]
        a.verify(e,d,sig,pem)
        if d=="approve":
            with journal.exclusive():
                existing=journal.row(e["head"])
                if existing is not None:
                    # Never replay success. A pending or denied row blocks
                    # all further approvals until independently reconciled.
                    if existing[2] is not None or existing[3]!="approved":
                        raise ValueError("Unresolved or terminal approval intent")
                    v.need(a.integration_permitted_locked(transport,journal,e,journal._lease[0]),
                           "Existing approval not currently eligible")
                    results.append({"pr":e["pr"],"state":"already_approved"})
                    continue
        results.append(a.process(transport,journal,e,d,sig,pem))
    return results

def main():
    os.umask(0o077)
    v.need(sys.argv[1:]==["cycle"],"Use cycle; journal initialization is separate")
    t=g.GitHubAuthority()
    j=a.Journal(JOURNAL)
    try:
        entries,pem=safety.SafetyClient().poll()
        results=cycle(t,j,entries,pem)
        print(json.dumps({"results":results,"merge_authorized":False},sort_keys=True))
    finally: j.close()

if __name__=="__main__":
    main()
