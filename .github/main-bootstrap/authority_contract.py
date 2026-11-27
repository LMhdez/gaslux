"""Staged authority state machine; no production transport, signer or workflow.

A deployment must separately prove exclusive credential custody and a durable
single-writer service. This module cannot issue a production status by itself.
"""
import base64
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import tempfile
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

def verify(e, decision, sig_b64, pem):
    evidence_shape(e)
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
    payload=v.canonical(v.decision_payload(e,decision))
    with tempfile.TemporaryDirectory() as d:
        paths=[Path(d)/x for x in ("pub","msg","sig")]
        for p,raw in zip(paths,(pem,payload,sig)):
            p.write_bytes(raw)
        result=subprocess.run(["openssl","pkeyutl","-verify","-pubin","-inkey",str(paths[0]),
              "-rawin","-in",str(paths[1]),"-sigfile",str(paths[2])],
              timeout=10,capture_output=True)
        v.need(result.returncode==0,"Independent signature invalid")
    return hashlib.sha256(payload).hexdigest()

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
    """Single durable writer journal. Never place on ephemeral Actions storage.

    Pending intents are committed before network writes. After an uncertain
    outcome we intentionally deny all further commands for that HEAD. An
    independently reviewed recovery path must reconcile the actual server
    receipt; this revision does not pretend exactly-once delivery.
    """
    def __init__(self,path):
        self.db=sqlite3.connect(path,timeout=15,isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS receipts (
          head TEXT PRIMARY KEY, evidence BLOB NOT NULL, approved TEXT NOT NULL,
          withdrawn TEXT, phase TEXT NOT NULL, status_id INTEGER)""")
    def close(self):
        self.db.close()
    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        else:
            self.db.execute("COMMIT")
    def row(self,head):
        row=self.db.execute("SELECT evidence,approved,withdrawn,phase,status_id FROM receipts WHERE head=?",
                            (head,)).fetchone()
        return row
    def reserve_approval(self,e,d):
        with self.transaction():
            v.need(self.row(e["head"]) is None,"Replay, concurrent or terminal request")
            self.db.execute("INSERT INTO receipts VALUES (?,?,?,NULL,'approval_pending',NULL)",
                            (e["head"],v.canonical(e),d))
    def reserve_withdrawal(self,e,d,old_id):
        with self.transaction():
            row=self.row(e["head"])
            v.need(row is not None and row[0]==v.canonical(e) and row[3]=="approved"
                   and row[4]==old_id,"No matching active approval or pending intent")
            self.db.execute("UPDATE receipts SET withdrawn=?,phase='withdrawal_pending' WHERE head=?",
                            (d,e["head"]))
    def complete(self,head,state,sid):
        pending,done=("approval_pending","approved") if state=="success" else ("withdrawal_pending","withdrawn")
        with self.transaction():
            row=self.row(head)
            v.need(row is not None and row[3]==pending and type(sid) is int and sid>0,
                   "Missing reserved intent")
            self.db.execute("UPDATE receipts SET phase=?,status_id=? WHERE head=?",(done,sid,head))

def process(transport,journal,e,decision,sig,pem):
    """Unwired adapter. Requires an independently attested policy and transport.
    
    Transport has to enforce exact complete effective policy/actor inventory,
    exclusive credential, paused migration and immutable execution. No such
    production transport is supplied here. Tests use fake transport only.
    """
    d=verify(e,decision,sig,pem)
    head=e["head"]
    state="success" if decision=="approve" else "failure"
    # policy_proof is a trusted adapter boundary, NOT a boolean from the PR,
    # dispatch or configuration. It must be implemented and independently reviewed.
    proof=transport.policy_proof()
    v.need(proof["repository_id"]==v.RID and proof["app"]==APP and proof["actor"]==ACTOR
           and proof["installation"]==INSTALLATION and proof["native_review_retained"] is True
           and proof["source_pinned_gate"] is True and proof["complete_actor_inventory"] is True
           and proof["exclusive_writer"] is True and proof["paused"] is True,"Unproven production policy")
    rows=read_stable(transport,head)
    if state=="success":
        v.need(e["draft"] is False and transport.snapshot(e["pr"])==e,"Stale or draft approval")
        v.need(not rows,"Prior status exists")
        journal.reserve_approval(e,d)
    else:
        # Withdrawal uses the ORIGINAL signed evidence; never require the
        # candidate still be open or its base still be current.
        row=journal.row(head)
        v.need(row is not None and row[0]==v.canonical(e),"Unknown historical approval")
        v.validate_transition(rows,e,row[1],d,state,ACTOR)
        v.need(len(rows)==1 and rows[0]["id"]==row[4],"Historical receipt mismatch")
        journal.reserve_withdrawal(e,d,row[4])
    v.need(transport.policy_proof()==proof and read_stable(transport,head)==rows,
           "Policy or history drift after reservation")
    if state=="success":
        v.need(transport.snapshot(e["pr"])==e,"Evidence drift before publication")
    payload={"context":v.CONTEXT,"state":state,"description":v.status_marker(e,d,state)}
    result=transport.publish(head,payload)
    v.need(type(result["id"]) is int and result["id"]>0
           and all(result[k]==x for k,x in payload.items()),"Unconfirmed status write")
    actual=read_stable(transport,head)
    v.need(len(actual)==len(rows)+1 and actual[0]["id"]==result["id"]
           and all(actual[0][k]==x for k,x in payload.items()) and actual[1:]==rows,
           "Unconfirmed effective authorization")
    journal.complete(head,state,result["id"])
    return {"pr":e["pr"],"head":head,"state":state,"status_id":result["id"],
            "merge_authorized":False}
