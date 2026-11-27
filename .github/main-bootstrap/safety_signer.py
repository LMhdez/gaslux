#!/usr/bin/env python3
"""Independent Safety signing worker; NOT a semantic evaluator or deployed service.

Run only on a separately administered Safety host/account. Request input
cannot select key, policy, token, or journal. The policy must originate from
an independent Safety evaluator, not the Integrator or candidate repository.
"""
import base64
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
import authority_contract as a
import authority_anchor as anchor
import safety_feed as feed
import main_bootstrap as v

ROOT=Path("/var/lib/gaslux-safety-signing")
MAX=131072

def private_dir(root):
    v.need(root.is_absolute() and root.resolve()==root,"Unsafe custody path")
    st=root.stat()
    v.need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid()
           and st.st_mode & 0o077==0,"Custody directory not private")
    for p in root.parents:
        s=p.stat()
        v.need(s.st_uid in (0,os.geteuid()) and s.st_mode & 0o022==0,
               "Writable custody ancestor")

def private_read(root,name,limit=MAX):
    fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as f:
        st=os.fstat(f.fileno())
        v.need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid()
               and st.st_mode & 0o077==0 and st.st_nlink==1,
               "Unsafe custody file")
        raw=f.read(limit+1)
        v.need(0<len(raw)<=limit,"Invalid custody file size")
        return raw

def strict_json(raw):
    def pairs(items):
        d={}
        for k,x in items:
            v.need(k not in d,"Duplicate JSON field")
            d[k]=x
        return d
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid JSON constant")))

def public_pem(key):
    pem=subprocess.run(["openssl","pkey","-pubout"],input=key,check=True,
                       capture_output=True,timeout=10).stdout
    der=subprocess.run(["openssl","pkey","-pubin","-outform","DER"],input=pem,
                       check=True,capture_output=True,timeout=10).stdout
    v.need(len(der)==44 and der.startswith(a.ED25519_DER_PREFIX),"Not Ed25519")
    return pem

def sign_bytes(key,payload):
    with tempfile.TemporaryDirectory() as tmp:
        k=Path(tmp)/"key"
        msg=Path(tmp)/"message"
        fd=os.open(k,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,"wb") as f: f.write(key)
        msg.write_bytes(payload)
        sig=subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(k),
                            "-rawin","-in",str(msg)],check=True,capture_output=True,timeout=10).stdout
    v.need(len(sig)==64,"Unexpected signature")
    return base64.b64encode(sig).decode("ascii")

def open_db(root,fp,init=False):
    p=root/"decisions.sqlite"
    if init:
        fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        os.close(fd)
    st=p.lstat()
    v.need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid()
           and st.st_mode&0o077==0 and st.st_nlink==1,"Unsafe decision journal")
    db=sqlite3.connect(p,timeout=15,isolation_level=None)
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        if init:
            db.execute("CREATE TABLE root_pin (fingerprint TEXT PRIMARY KEY)")
            db.execute("INSERT INTO root_pin VALUES (?)",(fp,))
            db.execute("""CREATE TABLE decisions (head TEXT PRIMARY KEY,
              evidence BLOB NOT NULL, approve_sig TEXT NOT NULL, withdraw_sig TEXT)""")
        v.need(db.execute("SELECT fingerprint FROM root_pin").fetchall()==[(fp,)],
               "Signer key or journal drift")
        return db
    except BaseException:
        db.close()
        raise

def policy_entry(root,e,decision):
    policy=strict_json(private_read(root,"policy.json"))
    v.need(type(policy) is dict and set(policy)=={"schema","decisions"}
           and policy["schema"]=="gaslux-independent-safety-policy-v1"
           and type(policy["decisions"]) is list and len(policy["decisions"])<=3,
           "Invalid independent policy")
    rows=policy["decisions"]
    for row in rows:
        v.need(type(row) is dict and set(row)=={"head","evidence_sha256","decision"}
               and v.SHA.fullmatch(row["head"]) and a.HEX64.fullmatch(row["evidence_sha256"])
               and row["decision"] in ("approve","withdraw"),"Invalid policy row")
    v.need(len({r["head"] for r in rows})==len(rows),"Ambiguous independent policy")
    v.need({"head":e["head"],"evidence_sha256":v.digest(e),"decision":decision} in rows,
           "Independent decision not authorized")
    return v.digest(policy)

def live_approval(root,e):
    # Read-only credential from separate custody; no signer-side write token.
    token=private_read(root,"read-token",4096).decode("ascii").strip()
    v.need(bool(token) and not any(x.isspace() for x in token),"Invalid read credential")
    old=os.environ.get("GH_TOKEN")
    os.environ["GH_TOKEN"]=token
    try:
        pin=a.EVIDENCE_ENGINE
        v.need(v.ref(v.REF)==pin and e["draft"] is False,"Wrong verifier or draft")
        p=v.native_policy()
        immutable=v.verifier_policy()
        v.need(v.snapshot(e["pr"],pin)==e and v.snapshot(e["pr"],pin)==e
               and v.native_policy()==p and v.verifier_policy()==immutable
               and v.ref(v.REF)==pin,"Independent live evidence drift")
    finally:
        if old is None: os.environ.pop("GH_TOKEN",None)
        else: os.environ["GH_TOKEN"]=old

def issue(root,request,live=live_approval,*,witness=None):
    private_dir(root)
    v.need(type(request) is dict and set(request)=={"evidence","decision"},"Invalid request")
    e=request["evidence"]
    decision=request["decision"]
    a.evidence_shape(e)
    v.need(decision in ("approve","withdraw"),"Unknown decision")
    key=private_read(root,"signer.pem",4096)
    pem=public_pem(key)
    fp=hashlib.sha256(pem).hexdigest()
    db=open_db(root,fp)
    try:
        db.execute("BEGIN IMMEDIATE")
        witness=witness if witness is not None else anchor.WitnessClient("signer")
        before=anchor.digest_state("signer",db)
        witness.assert_state(before)
        policy=policy_entry(root,e,decision)
        row=db.execute("SELECT evidence,approve_sig,withdraw_sig FROM decisions WHERE head=?",
                       (e["head"],)).fetchone()
        raw=v.canonical(e)
        payload=v.canonical(v.decision_payload(e,decision))
        if decision=="approve":
            v.need(row is None or (row[0]==raw and row[2] is None),"Terminal withdrawal or different evidence")
            live(root,e)
            sig=sign_bytes(key,payload)
            if row is None:
                db.execute("INSERT INTO decisions VALUES (?,?,?,NULL)",(e["head"],raw,sig))
            else: v.need(row[1]==sig,"Approval journal mismatch")
        else:
            v.need(row is not None and row[0]==raw,"No matching historical signed approval")
            sig=sign_bytes(key,payload)
            if row[2] is None:
                db.execute("UPDATE decisions SET withdraw_sig=? WHERE head=?",(sig,e["head"]))
            else: v.need(row[2]==sig,"Withdrawal journal mismatch")
        v.need(policy_entry(root,e,decision)==policy,"Independent policy changed during decision")
        witness.advance(before,anchor.digest_state("signer",db))
        db.execute("COMMIT")
        # No signature leaves the worker before durable commit.
        return {"schema":"gaslux-independent-safety-receipt-v1","decision":decision,
                "evidence_sha256":v.digest(e),"decision_sha256":hashlib.sha256(payload).hexdigest(),
                "policy_sha256":policy,"public_key_sha256":fp,"signature_b64":sig}
    except BaseException:
        if db.in_transaction: db.execute("ROLLBACK")
        raise
    finally: db.close()

def query(root,request,*,witness=None):
    private_dir(root)
    v.need(type(request) is dict and set(request)=={"evidence","nonce"},"Invalid query")
    e=request["evidence"]
    nonce=request["nonce"]
    a.evidence_shape(e)
    v.need(isinstance(nonce,str) and a.HEX64.fullmatch(nonce),"Invalid nonce")
    key=private_read(root,"signer.pem",4096)
    fp=hashlib.sha256(public_pem(key)).hexdigest()
    db=open_db(root,fp)
    try:
        db.execute("BEGIN IMMEDIATE")
        witness=witness if witness is not None else anchor.WitnessClient("signer")
        before=anchor.digest_state("signer",db)
        witness.assert_state(before)
        row=db.execute("SELECT evidence,approve_sig,withdraw_sig FROM decisions WHERE head=?",
                       (e["head"],)).fetchone()
        state="unknown"
        if row is not None:
            v.need(row[0]==v.canonical(e),"Different historical evidence")
            if row[2] is not None:
                state="withdrawn"
            else:
                try:
                    policy_entry(root,e,"approve")
                    state="approved"
                except (ValueError,OSError,KeyError,TypeError):
                    state="denied"
        payload=a.query_payload(e,nonce,state)
        sig=sign_bytes(key,v.canonical(payload))
        witness.assert_state(before)
        if state=="approved":
            policy_entry(root,e,"approve")
        db.execute("COMMIT")
        return {"payload":payload,"signature_b64":sig}
    except BaseException:
        if db.in_transaction: db.execute("ROLLBACK")
        raise
    finally: db.close()

def poll(root,request,*,witness=None):
    private_dir(root)
    v.need(type(request) is dict and set(request)=={"nonce"},"Invalid feed query")
    nonce=request["nonce"]
    key=private_read(root,"signer.pem",4096)
    fp=hashlib.sha256(public_pem(key)).hexdigest()
    db=open_db(root,fp)
    try:
        db.execute("BEGIN IMMEDIATE")
        witness=witness if witness is not None else anchor.WitnessClient("signer")
        before=anchor.digest_state("signer",db)
        witness.assert_state(before)
        entries=[]
        for head,raw,approval,withdrawal in db.execute(
                "SELECT head,evidence,approve_sig,withdraw_sig FROM decisions ORDER BY head"):
            e=strict_json(raw)
            v.need(e["head"]==head,"Signer ledger association drift")
            entries.append({"evidence":e,"decision":"withdraw" if withdrawal else "approve",
                            "signature_b64":withdrawal or approval})
        payload=feed.payload(nonce,entries)
        sig=sign_bytes(key,v.canonical(payload))
        witness.assert_state(before)
        db.execute("COMMIT")
        return {"payload":payload,"signature_b64":sig}
    except BaseException:
        if db.in_transaction: db.execute("ROLLBACK")
        raise
    finally: db.close()

def main():
    os.umask(0o077)
    private_dir(ROOT)
    if sys.argv[1:]==["init-journal"]:
        key=private_read(ROOT,"signer.pem",4096)
        pem=public_pem(key)
        fp=hashlib.sha256(pem).hexdigest()
        db=open_db(ROOT,fp,init=True)
        genesis=anchor.digest_state("signer",db)
        db.close()
        print(json.dumps({"public_key_sha256":fp,"public_key_pem":pem.decode("ascii"),"witness_genesis":genesis}))
        return
    v.need(sys.argv[1:] in (["sign"],["query"],["poll"]),"Use init-journal, sign, query or poll")
    raw=sys.stdin.buffer.read(MAX+1)
    v.need(0<len(raw)<=MAX,"Invalid request size")
    handler={"query":query,"sign":issue,"poll":poll}[sys.argv[1]]
    print(json.dumps(handler(ROOT,strict_json(raw)),sort_keys=True))

if __name__=="__main__":
    main()
