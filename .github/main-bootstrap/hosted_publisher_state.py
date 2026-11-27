"""Persistent publisher state on protected Git, not ephemeral runner disk.

A trusted single hosted controller owns the write credential. The remote
append-only history contains full reconstructable state and checkpoint
digest in the SAME commit. No unsigned external artifact restores state.
"""
import sqlite3
import threading
from contextlib import contextmanager
import authority_contract as a
import authority_anchor as anchor
import github_witness as gw
import safety_signer as signer
import main_bootstrap as v

SCHEMA="gaslux-hosted-publisher-state-v1"
PHASES={
    "approval_reserved","approval_posting","approved","quarantined","aborted","consumed",
    "withdrawal_reserved","withdrawal_posting","withdrawal_unsettled_reserved",
    "withdrawal_unsettled_posting","withdrawal_repair_reserved","withdrawal_repair_posting","withdrawn"}
TRANSITIONS={
    "approval_reserved":{"approval_posting","aborted"},
    "approval_posting":{"approved","quarantined","aborted","withdrawal_unsettled_reserved"},
    "approved":{"consumed","withdrawal_reserved"},
    "quarantined":{"withdrawal_reserved"},
    "aborted":{"withdrawal_reserved"},
    "consumed":{"withdrawal_reserved"},
    "withdrawal_reserved":{"withdrawal_posting"},
    "withdrawal_unsettled_reserved":{"withdrawal_unsettled_posting"},
    "withdrawal_repair_reserved":{"withdrawal_repair_posting"},
    "withdrawal_posting":{"withdrawn"},
    "withdrawal_unsettled_posting":{"withdrawn","withdrawal_repair_reserved"},
    "withdrawal_repair_posting":{"withdrawn"},
    "withdrawn":set(),
}

def state_digest(rows):
    v.need(type(rows) is list and len(rows)<=len(v.ALLOW),"Invalid publisher state size")
    heads=[]
    for row in rows:
        v.need(type(row) is list and len(row)==7,"Invalid publisher row")
        h,raw,approval,withdrawal,phase,sid,aid=row
        v.need(isinstance(raw,str) and len(raw)<=32768 and raw==raw.upper(),"Invalid evidence encoding")
        evidence=signer.strict_json(bytes.fromhex(raw))
        a.evidence_shape(evidence)
        v.need(v.canonical(evidence).hex().upper()==raw and evidence["head"]==h
               and approval==v.digest(v.decision_payload(evidence,"approve"))
               and withdrawal in (None,v.digest(v.decision_payload(evidence,"withdraw")))
               and phase in PHASES and all(x is None or (type(x) is int and x>0) for x in (sid,aid)),
               "Invalid publisher state binding")
        if phase in ("approved","consumed","quarantined"):
            v.need(sid is not None and aid==sid,"Missing approval receipt")
        if phase.startswith("withdrawal_") or phase=="withdrawn":
            v.need(withdrawal is not None,"Missing terminal denial")
        if phase=="withdrawn":
            v.need(sid is not None,"Missing withdrawal receipt")
        heads.append(h)
    v.need(heads==sorted(set(heads)),"Duplicate or unordered publisher head")
    return v.digest({"schema":"gaslux-authority-checkpoint-v1","role":"publisher",
                     "repository_id":v.RID,"pin":[],"rows":rows})

def transition(before,after):
    state_digest(before)
    state_digest(after)
    old={row[0]:row for row in before}
    new={row[0]:row for row in after}
    v.need(set(old)<=set(new),"Publisher history removed")
    changed=[h for h in new if new[h]!=old.get(h)]
    v.need(len(changed)==1,"Noncanonical publisher state transition")
    h=changed[0]
    row=new[h]
    prev=old.get(h)
    if prev is None:
        v.need(row[4] in ("approval_reserved","withdrawal_reserved") and row[5:]==[None,None]
               and ((row[3] is None)==(row[4]=="approval_reserved")),"Invalid initial publisher intent")
        return
    v.need(row[:3]==prev[:3] and (prev[3] is None or row[3]==prev[3])
           and (prev[6] is None or row[6]==prev[6]),"Publisher evidence or terminal state changed")
    if row[4]==prev[4]:
        v.need(prev[3] is None and row[3] is not None and row[5:]==prev[5:],
               "Invalid same-phase publisher change")
    else:
        v.need(row[4] in TRANSITIONS[prev[4]],"Invalid publisher phase transition")
        v.need(row[3]==prev[3],"Denial intent must precede phase change")
        if row[4] not in ("approved","quarantined","withdrawn","withdrawal_repair_reserved"):
            v.need(row[5:]==prev[5:],"Unexpected receipt update")

class SnapshotStore(gw.ScopedPublisherWitness):
    MAX_EVENT_BYTES=131072
    def make_state_event(self,seq,previous,rows):
        base=super().make_event(seq,previous,state_digest(rows))
        return {**base,"schema":SCHEMA,"state":rows}
    def validate_event(self,value):
        v.need(type(value) is dict and value==self.make_state_event(
                   value["sequence"],value["previous"],value["state"]),
               "Publisher state event mismatch")
    def snapshot(self):
        tip,events=super().snapshot()
        v.need(events[0]["state"]==[],"Publisher genesis not empty")
        for before,after in zip(events,events[1:]):
            transition(before["state"],after["state"])
        return tip,events
    def load(self):
        _,events=self.snapshot()
        return events[-1]["state"]
    def advance_rows(self,before,rows):
        tip,events=self.snapshot()
        v.need(events[-1]["digest"]==before,"External checkpoint mismatch")
        if events[-1]["state"]==rows: return
        transition(events[-1]["state"],rows)
        digest=state_digest(rows)
        v.need(digest not in {e["digest"] for e in events},"Checkpoint rollback/reuse")
        self.append_event(tip,events,self.make_state_event(len(events),before,rows))

class HostedJournal(a.Journal):
    """Reconstructable SQLite view; Git history alone is authoritative.

    The remote CAS must be confirmed BEFORE returning a transaction to code
    that can issue an external request. An ambiguous CAS poisons this view.
    Next run reloads the actual protected ref; never retries from stale RAM.
    """
    def __init__(self,store):
        self.store=store
        self._lease=None
        self._mutex=threading.Lock()
        self.poisoned=False
        rows=store.load()
        state_digest(rows)
        self.db=sqlite3.connect(":memory:",isolation_level=None)
        try:
            self.db.execute("""CREATE TABLE receipts_v2 (
              head TEXT PRIMARY KEY, evidence BLOB NOT NULL, approved TEXT NOT NULL,
              withdrawn TEXT, phase TEXT NOT NULL, status_id INTEGER, approval_id INTEGER)""")
            self.db.executemany("INSERT INTO receipts_v2 VALUES (?,?,?,?,?,?,?)",
                [(x[0],bytes.fromhex(x[1]),*x[2:]) for x in rows])
            v.need(self.rows()==rows,"Publisher reconstruction mismatch")
            self.assert_current()
        except BaseException:
            self.db.close()
            raise
    def rows(self):
        return [list(x) for x in self.db.execute(
            "SELECT head,hex(evidence),approved,withdrawn,phase,status_id,approval_id FROM receipts_v2 ORDER BY head")]
    def assert_current(self):
        v.need(not self.poisoned,"Poisoned publisher state; reload required")
        self.store.assert_state(state_digest(self.rows()))
    @contextmanager
    def exclusive(self):
        v.need(self._mutex.acquire(blocking=False),"Writer already active")
        try:
            self.assert_current()
            lease=object()
            self._lease=(lease,threading.get_ident())
            try: yield lease
            finally: self._lease=None
        finally: self._mutex.release()
    @contextmanager
    def transaction(self):
        v.need(self._lease is not None and self._lease[1]==threading.get_ident(),
               "Active writer lease required")
        self.assert_current()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            before=state_digest(self.rows())
            yield
            rows=self.rows()
            # Even an unchanged state must be checked against live remote.
            self.store.advance_rows(before,rows)
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction: self.db.execute("ROLLBACK")
            # May have advanced Git before the response/local commit failed.
            self.poisoned=True
            raise
