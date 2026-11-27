"""Protected hosted merge executor, no activation or live credentials.

Only one frozen controller may write the signed ledger and issue merge
requests. All revocation-producing paths must be serialized with it.
The actual deployment must verify this exclusivity; GitHub Actions
concurrency alone is not an authority proof.
"""
import secrets
import os
import authority_contract as a
import hosted_evaluator as evaluator
import hosted_safety as hosted
import github_main_merge as gm
import github_authority_transport as g
import main_bootstrap as v

CONTROLLER_REVIEW=None
HOSTED_CONTROLLER_ENABLED=False
BOOTSTRAP_MERGE_ENABLED=False
CONTROLLER_WORKFLOW=None

def controller_boundary(writer):
    v.need(HOSTED_CONTROLLER_ENABLED is True and isinstance(CONTROLLER_REVIEW,str)
           and a.HEX64.fullmatch(CONTROLLER_REVIEW)
           and isinstance(CONTROLLER_WORKFLOW,str) and
           os.environ.get("GITHUB_WORKFLOW_REF")==CONTROLLER_WORKFLOW,
           "Protected merge controller not activated")
    evaluator.boundary()
    evaluator.verify_release(writer)

def boundary(writer):
    controller_boundary(writer)
    v.need(BOOTSTRAP_MERGE_ENABLED is True,"Bootstrap merge not activated")
    gm.pins()

def reservation_state(writer,e,rid,phase,expected_tip=None):
    tip,_,states,_,active,consumed,incidents=writer.snapshot_full()
    v.need((expected_tip is None or tip==expected_tip) and not incidents
           and e["head"] not in consumed
           and active=={"evidence":e,"reservation":rid,"phase":phase}
           and states.get(e["head"],{}).get("decision")=="approve"
           and states[e["head"]]["evidence"]==e,
           "Reservation revoked, changed or unresolved")
    a.verify(e,"approve",states[e["head"]]["signature_b64"],writer.pem)
    return tip,states

def exact_status(reader,journal,e,states):
    """The publisher's complete persistent state is mandatory, not a flag."""
    v.need(not journal.unresolved_heads() and journal.heads()==set(states),
           "Incomplete or unresolved publisher ledger")
    for h,decision in states.items():
        ev=decision["evidence"]
        row=journal.row(h)
        v.need(row is not None and row[0]==v.canonical(ev) and
               row[1]==v.digest(v.decision_payload(ev,"approve")),"Publisher evidence drift")
        history,successes,failures=a.historical_rows(reader,ev,row)
        if decision["decision"]=="withdraw":
            v.need(row[2]==v.digest(v.decision_payload(ev,"withdraw")) and row[3]=="withdrawn"
                   and failures and history[0]["state"]=="failure"
                   and history[0]["id"]==row[4],"Withdrawal not acknowledged")
        else:
            v.need(row[2] is None and row[3] in ("approved","consumed") and
                   len(successes)==1 and not failures and row[4]==row[5]==successes[0]["id"],
                   "Approval receipt not effective")
            if row[3]=="consumed":
                v.need(reader.merged_receipt(ev) is not None,"Consumed receipt drift")
    v.need(journal.row(e["head"])[3]=="approved","Target approval not active")

def preflight(writer,reader,merger,journal,e,states):
    boundary(writer)
    v.need(e["draft"] is False,"Draft cannot merge")
    merger.proof()
    a.identity(reader)
    a.approval_policy(reader)
    exact_status(reader,journal,e,states)
    v.need(reader.snapshot(e["pr"])==e and reader.merged_receipt(e) is None,
           "Candidate/base/CI drift")
    v.need(evaluator.exact_evidence(e["pr"])==e,"Independent evidence drift")

def recover(writer,reader,merger):
    _,_,_,_,active,_,incidents=writer.snapshot_full()
    v.need(not incidents,"Hosted merge incident; stop")
    if active is None: return None
    e,rid=active["evidence"],active["reservation"]
    if active["phase"]=="reserved":
        # Sole protected controller may clear a never-posted reservation
        # after restart. No PUT is permitted without durable posting intent.
        writer.append_operation(e,"merge_aborted",rid)
        return {"pr":e["pr"],"state":"reserved_aborted"}
    v.need(active["phase"]=="posting","Unknown reservation phase")
    receipt=merger.receipt(e,reader)
    if receipt is None:
        return {"pr":e["pr"],"state":"merge_unresolved"}
    writer.append_operation(e,"merge_confirmed",rid,receipt)
    _,_,_,_,_,_,incidents=writer.snapshot_full()
    return {"pr":e["pr"],"state":"incident" if incidents else "merged_recovered","merge":receipt["merge"]}

def execute(writer,reader,merger,journal,e):
    """One exact candidate. Persist intent before PUT, never retry it.

    Caller must be the independently reviewed sole hosted controller. The
    persistent journal must be reconstructed and externally witnessed before
    calling; an ephemeral runner database/artifact is not authoritative.
    """
    boundary(writer)
    a.evidence_shape(e)
    with journal.exclusive() as lease:
        if (pending:=recover(writer,reader,merger)) is not None:
            return pending
        _,_,states,_,active,consumed,incidents=writer.snapshot_full()
        v.need(active is None and not incidents and e["head"] not in consumed
               and states.get(e["head"],{}).get("decision")=="approve"
               and states[e["head"]]["evidence"]==e,"No current exact approval")
        a.verify(e,"approve",states[e["head"]]["signature_b64"],writer.pem)
        preflight(writer,reader,merger,journal,e,states)
        rid=secrets.token_hex(32)
        reserved,_=writer.append_operation(e,"reserve_merge",rid)
        _,states=reservation_state(writer,e,rid,"reserved",reserved)
        preflight(writer,reader,merger,journal,e,states)
        # Last policy/evidence check before durable posting; any concurrent
        # withdrawal changes signed tip and invalidates the reservation.
        posting,_=writer.append_operation(e,"merge_posting",rid)
        _,states=reservation_state(writer,e,rid,"posting",posting)
        preflight(writer,reader,merger,journal,e,states)
        # This fresh read is immediately before dispatch. Between this read
        # and PUT, only the exclusive hosted controller may append; no
        # competing writer or separately runnable signing workflow allowed.
        journal.assert_current()
        reservation_state(writer,e,rid,"posting",posting)
        merged_sha=merger.dispatch_once(e)
        receipt=merger.receipt(e,reader)
        v.need(receipt is not None and receipt["merge"]==merged_sha,"Merge readback unconfirmed")
        writer.append_operation(e,"merge_confirmed",rid,receipt)
        _,_,_,_,_,_,incidents=writer.snapshot_full()
        return {"pr":e["pr"],"state":"incident" if incidents else "merged","merge":merged_sha}
