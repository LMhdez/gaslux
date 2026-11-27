"""Staged authority state machine; no production transport, signer or workflow.

A deployment must separately prove exclusive credential custody and a durable
single-writer service. This module cannot issue a production status by itself.
"""
import base64
import hashlib
import fcntl
import json
import os
import re
import sqlite3
import stat
import subprocess
import tempfile
import threading
import secrets
import time
import authority_anchor as anchor
from contextlib import contextmanager
from pathlib import Path

import main_bootstrap as v

APP = 5952630
ACTOR = 361970320
INSTALLATION = 186499041
SLUG = "gaslux-main-infrastructure-auth"
EVIDENCE_ENGINE = "3459813c7a191fd81f10e1bbdcbee3d5a8758013"
# Deliberately unconfigured; pin a public key only after independent review.
SIGNER_PEM_SHA256 = None
HEX64 = re.compile(r"[0-9a-f]{64}")
ED25519_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")

def evidence_shape(e):
    v.need(type(e) is dict and set(e)=={
        "schema","repository","repository_id","target","pr","pr_id","head",
        "base","tree","composition","predecessors","verifier","ci","draft"
    },"Unexpected evidence fields")
    v.need(e["schema"]=="gaslux-main-bootstrap-v1" and e["repository"]==v.REPO
           and e["repository_id"]==v.RID and e["target"]=="main"
           and e["verifier"]==EVIDENCE_ENGINE and type(e["pr"]) is int
           and e["pr"] in v.ALLOW,"Wrong evidence scope")
    h,t,b,pid=v.ALLOW[e["pr"]]
    v.need(e["head"]==h and e["tree"]==t and e["pr_id"]==pid
           and all(isinstance(e[k],str) and v.SHA.fullmatch(e[k])
                   for k in ("head","tree","base","composition"))
           and type(e["draft"]) is bool,"Wrong candidate identity")
    c=e["ci"]
    v.need(type(c) is dict and set(c)=={"workflow","run","attempt","job","suite",
             "base","head","tested_composition","job_log_sha256"}
           and c["workflow"]==v.WORKFLOW and c["base"]==e["base"]
           and c["head"]==h and c["tested_composition"]==e["composition"]
           and isinstance(c["job_log_sha256"],str) and HEX64.fullmatch(c["job_log_sha256"])
           and all(type(c[k]) is int and c[k]>0 for k in ("run","attempt","job","suite")),
           "Wrong CI evidence")
    pred=e["predecessors"]
    expected=[i for i in v.ALLOW if i<e["pr"]]
    v.need(type(pred) is list and [x["pr"] for x in pred]==expected,"Wrong predecessor order")
    for x in pred:
        v.need(set(x)=={"pr","head","merge","tree"} and x["head"]==v.ALLOW[x["pr"]][0]
               and x["tree"]==v.ALLOW[x["pr"]][1] and v.SHA.fullmatch(x["merge"]),
               "Wrong predecessor receipt")
    v.need(e["base"]==(pred[-1]["merge"] if pred else v.BASE),"Wrong predecessor base")
    return v.digest(e)

def verify_bytes(payload,sig_b64,pem):
    v.need(isinstance(SIGNER_PEM_SHA256,str) and HEX64.fullmatch(SIGNER_PEM_SHA256)
           and isinstance(pem,bytes) and len(pem)<=4096
           and hashlib.sha256(pem).hexdigest()==SIGNER_PEM_SHA256,
           "Independent signing trust root not provisioned or mismatched")
    # A 64-byte signature alone is not an algorithm check.
    der=subprocess.run(["openssl","pkey","-pubin","-outform","DER"],input=pem,
                       timeout=10,capture_output=True,check=True).stdout
    v.need(len(der)==44 and der.startswith(ED25519_DER_PREFIX),"Not an Ed25519 public key")
    sig=base64.b64decode(sig_b64,validate=True)
    v.need(len(sig)==64,"Invalid Ed25519 signature")
    with tempfile.TemporaryDirectory() as d:
        paths=[Path(d)/x for x in ("pub","msg","sig")]
        for p,raw in zip(paths,(pem,payload,sig)):
            p.write_bytes(raw)
        result=subprocess.run(["openssl","pkeyutl","-verify","-pubin","-inkey",str(paths[0]),
              "-rawin","-in",str(paths[1]),"-sigfile",str(paths[2])],
              timeout=10,capture_output=True)
        v.need(result.returncode==0,"Independent signature invalid")
    return hashlib.sha256(payload).hexdigest()

def verify(e,decision,sig_b64,pem):
    evidence_shape(e)
    return verify_bytes(v.canonical(v.decision_payload(e,decision)),sig_b64,pem)

def query_payload(e,nonce,state):
    evidence_shape(e)
    v.need(isinstance(nonce,str) and HEX64.fullmatch(nonce) and
           state in ("approved","withdrawn","unknown","denied"),"Invalid query response")
    return {"schema":"gaslux-independent-safety-current-v1","repository_id":v.RID,
            "head":e["head"],"evidence_sha256":v.digest(e),"nonce":nonce,
            "state":state,"decision_sha256":v.digest(v.decision_payload(e,"approve"))}

def verify_current(e,nonce,response,pem):
    v.need(type(response) is dict and set(response)=={"payload","signature_b64"},
           "Invalid signer response")
    payload=response["payload"]
    v.need(payload==query_payload(e,nonce,payload["state"]),"Signer response binding mismatch")
    verify_bytes(v.canonical(payload),response["signature_b64"],pem)
    return payload["state"]=="approved"

def authentic_history(raw, combined, head):
    v.need(type(raw) is list and len(raw)<100 and len({r["id"] for r in raw})==len(raw)
           and combined["sha"]==head and combined["repository"]["id"]==v.RID
           and combined["total_count"]==len(combined["statuses"])<100,"Incomplete status history")
    rows=[r for r in raw if r["context"].casefold()==v.CONTEXT.casefold()]
    latest=[r for r in combined["statuses"] if r["context"].casefold()==v.CONTEXT.casefold()]
    v.need(len(latest)==bool(rows),"Ambiguous latest status")
    for row in rows:
        u=row["creator"]
        v.need(row["context"]==v.CONTEXT and row["state"] in ("success","failure")
               and u["id"]==ACTOR and u["login"]==SLUG+"[bot]" and u["type"]=="Bot",
               "Unexpected status issuer or alias")
    if rows:
        v.need(all(rows[0].get(k)==latest[0].get(k) for k in
                   ("id","state","context","description","created_at","updated_at")),
               "Effective status mismatch")
    return rows

def read_stable(transport, head):
    a=transport.combined(head)
    raw=transport.history(head)
    b=transport.combined(head)
    v.need(a==b,"Status history drift")
    return authentic_history(raw,b,head)

class Journal:
    """Persistent same-host single writer. Transport must never retry a POST.

    The filesystem lock spans the entire network transaction and is released
    after process death. A committed posting intent survives process death.
    Lack of a visible receipt is NOT proof an HTTP request cannot arrive.
    """
    def __init__(self,path,*,initialize=False,witness=None):
        self._lease=None
        self.witness=witness if witness is not None else anchor.WitnessClient('publisher')
        self.path=Path(path).absolute()
        v.need(str(path)!=":memory:" and self.path.resolve()==self.path,
               "Persistent non-symlink journal required")
        if initialize:
            # Explicit installation-only operation; never performed by a
            # request handler or recovery. Refuse overwriting existing state.
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
            os.close(fd)
        st=self.path.lstat()
        v.need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid()
               and st.st_mode&0o077==0 and st.st_nlink==1,"Unsafe journal file")
        self.db=sqlite3.connect(self.path,timeout=15,isolation_level=None)
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            if initialize:
                self.db.execute("""CREATE TABLE receipts_v2 (
                  head TEXT PRIMARY KEY, evidence BLOB NOT NULL, approved TEXT NOT NULL,
                  withdrawn TEXT, phase TEXT NOT NULL, status_id INTEGER,
                  approval_id INTEGER)""")
            cols=[x[1] for x in self.db.execute("PRAGMA table_info(receipts_v2)")]
            v.need(cols==["head","evidence","approved","withdrawn","phase","status_id","approval_id"],
                   "Missing or incompatible authority journal")
            # Old schema cannot prove network phase. Never silently migrate.
            old=self.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='receipts'").fetchone()
            v.need(old is None or self.db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]==0,
                   "Old nonempty journal requires independent recovery")
            self.witness.assert_state(anchor.digest_state("publisher",self.db))
        except BaseException:
            self.db.close()
            raise
    def close(self):
        self.db.close()
    @contextmanager
    def exclusive(self):
        fd=os.open(str(self.path)+".writer.lock",os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError("Writer already active") from exc
            v.need(self._lease is None,"Journal lock already held")
            lease=object()
            self._lease=(lease,threading.get_ident())
            try:
                self.witness.assert_state(anchor.digest_state('publisher',self.db))
                yield lease
            finally:
                self._lease=None
        finally:
            os.close(fd)
    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            before=anchor.digest_state("publisher",self.db)
            self.witness.assert_state(before)
            yield
            after=anchor.digest_state("publisher",self.db)
            # Witness first: crash between remote CAS and local commit
            # deliberately blocks recovery rather than accepting old state.
            self.witness.advance(before,after)
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction: self.db.execute("ROLLBACK")
            raise
    def row(self,head):
        return self.db.execute("SELECT evidence,approved,withdrawn,phase,status_id,approval_id "
                               "FROM receipts_v2 WHERE head=?",(head,)).fetchone()
    def reserve_approval(self,e,d):
        with self.transaction():
            v.need(self.row(e["head"]) is None,"Replay, concurrent or terminal request")
            self.db.execute("INSERT INTO receipts_v2 VALUES (?,?,?,NULL,'approval_reserved',NULL,NULL)",
                            (e["head"],v.canonical(e),d))
    def reserve_denial(self,e,d):
        """Persist authenticated terminal intent BEFORE any network operation.

        For W-before-A, no success POST has been issued by this journal.
        Derive A's exact payload digest without trusting/accepting A.
        Unknown remote history still blocks acknowledgement, not this denial.
        """
        v.need(self._lease is not None and self._lease[1]==threading.get_ident(),
               "Active writer lease required")
        raw=v.canonical(e)
        approve=v.digest(v.decision_payload(e,"approve"))
        with self.transaction():
            row=self.row(e["head"])
            if row is None:
                self.db.execute("INSERT INTO receipts_v2 VALUES (?,?,?,?,'withdrawal_reserved',NULL,NULL)",
                                (e["head"],raw,approve,d))
            else:
                v.need(row[0]==raw and row[1]==approve and row[2] in (None,d),
                       "Different historical evidence or denial")
                self.db.execute("UPDATE receipts_v2 SET withdrawn=? WHERE head=?",
                                (d,e["head"]))
    def change(self,head,old,new,*,status_id=None,approval_id=None,withdrawn=None):
        with self.transaction():
            row=self.row(head)
            v.need(row is not None and row[3] in old,"Unexpected journal phase")
            v.need(withdrawn is None or row[2] in (None,withdrawn),"Terminal denial digest drift")
            self.db.execute("UPDATE receipts_v2 SET phase=?,status_id=?,approval_id=?,withdrawn=? WHERE head=?",
                            (new,row[4] if status_id is None else status_id,
                             row[5] if approval_id is None else approval_id,
                             row[2] if withdrawn is None else withdrawn,head))

def identity(transport):
    p=transport.identity_proof()
    v.need(p=={"repository_id":v.RID,"app":APP,"actor":ACTOR,
              "installation":INSTALLATION,"exclusive_writer":True},
           "Unproven writer identity")
    return p

def approval_policy(transport):
    p=transport.policy_proof()
    v.need(p=={"repository_id":v.RID,"app":APP,"actor":ACTOR,
               "installation":INSTALLATION,"native_review_retained":True,
               "source_pinned_gate":True,"complete_actor_inventory":True,
               "exclusive_writer":True,"paused":True},"Unproven production policy")
    return p

def historical_rows(transport,e,row):
    rows=read_stable(transport,e["head"])
    successes=[x for x in rows if x["state"]=="success"]
    failures=[x for x in rows if x["state"]=="failure"]
    v.need(len(successes)<=1 and len(failures)<=2,"Unexpected duplicate receipt")
    for x in successes:
        v.need(x["description"]==v.status_marker(e,row[1],"success"),"Unknown approval receipt")
        if row[5] is not None:
            v.need(x["id"]==row[5],"Approval receipt ID drift")
    for x in failures:
        v.need(row[2] is not None and x["description"]==v.status_marker(e,row[2],"failure"),
               "Unknown withdrawal receipt")
    sequence=tuple(x["state"] for x in rows)
    v.need(sequence in ((),("success",),("failure",),("failure","success"),
                        ("success","failure"),("failure","success","failure")),
           "Unexpected receipt sequence")
    if sequence in (("success","failure"),("failure","success","failure")):
        v.need(row[3] in ("withdrawal_unsettled_posting","withdrawal_repair_reserved",
                           "withdrawal_repair_posting","withdrawn"),
               "Unexpected success after withdrawal")
    if row[3]=="withdrawn":
        v.need(rows and rows[0]["state"]=="failure" and rows[0]["id"]==row[4],
               "Terminal receipt drift")
    return rows,successes,failures

def settled(transport,head,state):
    # Requires independently validated transport-specific settlement proof,
    # NOT a timeout, empty GET, process lock, or requester-provided flag.
    # GitHub REST alone does not provide a documented request fence.
    return transport.outbound_settled(head,state) is True

def send(transport,head,e,d,state,rows):
    payload={"context":v.CONTEXT,"state":state,"description":v.status_marker(e,d,state)}
    result=transport.publish(head,payload)
    v.need(type(result["id"]) is int and result["id"]>0 and all(result[k]==x for k,x in payload.items()),
           "Unconfirmed status write")
    actual=read_stable(transport,head)
    v.need(len(actual)==len(rows)+1 and actual[0]["id"]==result["id"]
           and all(actual[0][k]==x for k,x in payload.items()) and actual[1:]==rows,
           "Unconfirmed effective authorization")
    return result["id"]

def current_approval(transport,e):
    nonce=secrets.token_hex(32)
    start=time.monotonic()
    response,pem=transport.current_decision(e,nonce)
    v.need(time.monotonic()-start<=15,"Signer query expired")
    return verify_current(e,nonce,response,pem)

def eligible(transport,e):
    try:
        return (e["draft"] is False and transport.snapshot(e["pr"])==e
                and bool(approval_policy(transport)) and current_approval(transport,e))
    except Exception:
        return False

def reconcile_approval(transport,journal,e):
    h=e["head"]
    row=journal.row(h)
    rows,successes,failures=historical_rows(transport,e,row)
    v.need(not failures,"Unexpected failure before withdrawal")
    if row[3]=="approval_reserved":
        v.need(not rows,"Receipt before outbound intent")
        journal.change(h,("approval_reserved",),"aborted")
        return
    if row[3]=="approval_posting":
        if successes:
            # One exact visible receipt proves the single non-retried POST
            # reached the server, but eligibility still needs live review.
            sid=successes[0]["id"]
            journal.change(h,("approval_posting",),"approved" if eligible(transport,e) else "quarantined",
                           status_id=sid,approval_id=sid)
        elif settled(transport,h,"success"):
            journal.change(h,("approval_posting",),"aborted")
        # Otherwise preserve unresolved posting; never retry success.

def acknowledge_failure(transport,journal,e,row):
    h=e["head"]
    rows,successes,failures=historical_rows(transport,e,row)
    v.need(failures and rows[0]["state"]=="failure","Effective failure not proven")
    # If no success receipt was ever seen, the original success request
    # must be proven unable to arrive before a withdrawal is acknowledged.
    # A visible exact success is conclusive only with a no-retry transport.
    if not successes and row[5] is None and row[3]=="withdrawal_unsettled_posting":
        v.need(settled(transport,h,"success"),"Possible delayed success; withdrawal not acknowledged")
    v.need(identity(transport) and read_stable(transport,h)==rows,"Withdrawal readback drift")
    journal.change(h,(row[3],),"withdrawn",status_id=failures[0]["id"],
                   approval_id=successes[0]["id"] if successes else None)
    return {"pr":e["pr"],"head":h,"state":"failure","status_id":failures[0]["id"],"merge_authorized":False}

def withdraw(transport,journal,e,d):
    h=e["head"]
    row=journal.row(h)
    v.need(row is not None and row[0]==v.canonical(e) and row[2]==d,
           "Missing authenticated denial intent")
    if row[3] in ("approval_reserved","approval_posting"):
        reconcile_approval(transport,journal,e)
        row=journal.row(h)
    if row[3] in ("approved","quarantined","aborted","approval_posting"):
        # Persist signed denial. Never retry an approval after this transition.
        phase="withdrawal_unsettled_reserved" if row[3]=="approval_posting" else "withdrawal_reserved"
        journal.change(h,(row[3],),phase,withdrawn=d)
        row=journal.row(h)
    v.need(row[2]==d and row[3] in ("withdrawal_reserved","withdrawal_posting",
             "withdrawal_unsettled_reserved","withdrawal_unsettled_posting",
             "withdrawal_repair_reserved","withdrawal_repair_posting","withdrawn"),
             "Different withdrawal or phase")
    rows,successes,failures=historical_rows(transport,e,row)
    if failures and rows[0]["state"]=="failure":
        return acknowledge_failure(transport,journal,e,row)
    v.need(row[3]!="withdrawn","Missing terminal failure")
    if failures:
        # An exact late success after the initial unacknowledged failure.
        # The single success and first failure are now visible; repair with
        # a second denial, never a success. Receipt order is authenticated.
        v.need(len(failures)==len(successes)==1 and row[3] in
               ("withdrawal_unsettled_posting","withdrawal_repair_reserved","withdrawal_repair_posting"),
               "Unproven late receipt sequence")
        if row[3]=="withdrawal_unsettled_posting":
            journal.change(h,(row[3],),"withdrawal_repair_reserved",approval_id=successes[0]["id"])
            row=journal.row(h)
    pending={
        "withdrawal_reserved":"withdrawal_posting",
        "withdrawal_unsettled_reserved":"withdrawal_unsettled_posting",
        "withdrawal_repair_reserved":"withdrawal_repair_posting",
    }
    if row[3] in pending:
        journal.change(h,(row[3],),pending[row[3]])
    else:
        # Do not retry ambiguous failure requests without an actual fence.
        v.need(settled(transport,h,"failure"),"Withdrawal POST unresolved")
    v.need(identity(transport) and read_stable(transport,h)==rows,"Denial identity/history drift")
    send(transport,h,e,d,"failure",rows)
    return acknowledge_failure(transport,journal,e,journal.row(h))

def process(transport,journal,e,decision,sig,pem):
    """Unwired contract. No live GitHub transport or production signer here."""
    evidence_shape(e)
    v.need(decision in ("approve","withdraw"),"Unknown decision")
    d=verify(e,decision,sig,pem)
    h=e["head"]
    with journal.exclusive():
        if decision=="withdraw":
            # Even if the writer identity check or history API fails, retain
            # a verified denial. It must precede any request to GitHub.
            journal.reserve_denial(e,d)
            identity(transport)
            return withdraw(transport,journal,e,d)
        v.need(decision=="approve","Unknown decision")
        row=journal.row(h)
        if row is not None:
            v.need(row[2] is None,"Terminal signed withdrawal")
            v.need(row[0]==v.canonical(e) and row[1]==d,"Different approval evidence")
            identity(transport)
            if row[3] in ("approval_reserved","approval_posting"):
                reconcile_approval(transport,journal,e)
            raise ValueError("Replay or recovered approval; never republish")
        identity(transport)
        proof=approval_policy(transport)
        v.need(eligible(transport,e),"Stale or draft approval")
        rows=read_stable(transport,h)
        v.need(not rows,"Prior status exists")
        journal.reserve_approval(e,d)
        v.need(identity(transport) and approval_policy(transport)==proof
               and read_stable(transport,h)==rows and eligible(transport,e),
               "Prepublication drift")
        journal.change(h,("approval_reserved",),"approval_posting")
        sid=send(transport,h,e,d,"success",rows)
        if not eligible(transport,e):
            journal.change(h,("approval_posting",),"quarantined",status_id=sid,approval_id=sid)
            raise ValueError("Postpublication drift; signed withdrawal required")
        journal.change(h,("approval_posting",),"approved",status_id=sid,approval_id=sid)
        return {"pr":e["pr"],"head":h,"state":"success","status_id":sid,"merge_authorized":False}

def integration_permitted_locked(transport,journal,e,lease):
    """Predicate only. Future real merge must keep this lease until readback."""
    v.need(journal._lease==(lease,threading.get_ident()),"Active writer lease required")
    row=journal.row(e["head"])
    if row is None or row[2] is not None or row[3]!="approved" or row[0]!=v.canonical(e):
        return False
    try:
        identity(transport)
        rows,successes,failures=historical_rows(transport,e,row)
        return len(successes)==1 and not failures and eligible(transport,e)
    except Exception:
        return False

def integration_permitted(transport,journal,e):
    """Diagnostic predicate; no production merge authority."""
    with journal.exclusive() as lease:
        return integration_permitted_locked(transport,journal,e,lease)
