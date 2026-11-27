"""External checkpoint protocol. Witness must be outside both DB rollback domains.

Client SSH authenticates a pinned witness host, and witness authenticates a
dedicated role key with a fixed forced command. No live endpoint provisioned.
"""
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import main_bootstrap as v

ROLES=("signer","publisher")
HEX=re.compile(r"[0-9a-f]{64}")
# Must be set in an independently reviewed release, not request/environment.
WITNESS_HOST=None
WITNESS_USER=None
ROOT=Path("/var/lib/gaslux-authority-witness")
CLIENT_ROOT=Path("/etc/gaslux-authority")
MAX=8192

def digest_state(role,db):
    v.need(role in ROLES,"Unknown witness role")
    if role=="signer":
        rows=db.execute("SELECT head,hex(evidence),approve_sig,withdraw_sig FROM decisions ORDER BY head").fetchall()
        pin=db.execute("SELECT fingerprint FROM root_pin").fetchall()
    else:
        rows=db.execute("SELECT head,hex(evidence),approved,withdrawn,phase,status_id,approval_id FROM receipts_v2 ORDER BY head").fetchall()
        pin=[]
    return v.digest({"schema":"gaslux-authority-checkpoint-v1","role":role,
                     "repository_id":v.RID,"pin":pin,"rows":rows})

def checked_file(path,private=False):
    v.need(path.is_absolute() and path.resolve()==path,"Unsafe custody path")
    s=path.lstat()
    v.need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and
           s.st_uid in (0,os.geteuid()) and not s.st_mode&0o022
           and (not private or s.st_mode&0o077==0),"Unsafe custody file")

class SSH:
    def __init__(self,host,user,identity,known_hosts,command):
        v.need(isinstance(host,str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}",host)
               and isinstance(user,str) and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}",user),
               "Independent SSH endpoint not provisioned")
        checked_file(identity,True)
        checked_file(known_hosts)
        self.args=["/usr/bin/ssh","-F","/dev/null","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes",
                   "-o","UserKnownHostsFile="+str(known_hosts),"-o","GlobalKnownHostsFile=/dev/null",
                   "-o","IdentitiesOnly=yes","-o","IdentityAgent=none","-o","ClearAllForwardings=yes",
                   "-o","ConnectTimeout=5","-i",str(identity),user+"@"+host,command]
    def request(self,payload,limit=MAX):
        raw=v.canonical(payload)
        v.need(len(raw)<=131072,"Oversize SSH request")
        result=subprocess.run(self.args,input=raw,capture_output=True,timeout=15,check=True)
        v.need(0<len(result.stdout)<=limit,"Invalid SSH response")
        return json.loads(result.stdout)

class WitnessClient:
    def __init__(self,role):
        v.need(role in ROLES,"Unknown witness role")
        self.role=role
    def request(self,op,**kwargs):
        ssh=SSH(WITNESS_HOST,WITNESS_USER,CLIENT_ROOT/(self.role+"-witness.key"),
                CLIENT_ROOT/"witness.known_hosts","gaslux-witness-v1")
        return ssh.request({"operation":op,"role":self.role,**kwargs})
    def assert_state(self,digest):
        result=self.request("read")
        v.need(result=={"role":self.role,"digest":digest},"External checkpoint mismatch")
    def advance(self,before,after):
        if before==after:
            self.assert_state(before)
            return
        result=self.request("advance",before=before,after=after)
        v.need(result=={"role":self.role,"digest":after},"Checkpoint advance unconfirmed")

class WitnessStore:
    """Independent host service. Never initialize on a client request."""
    def __init__(self,path,role,*,genesis=None):
        v.need(role in ROLES,"Unknown witness role")
        self.role=role
        path=Path(path).absolute()
        if genesis is not None:
            v.need(HEX.fullmatch(genesis),"Invalid genesis")
            fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
            os.close(fd)
        checked_file(path,True)
        self.db=sqlite3.connect(path,timeout=10,isolation_level=None)
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            if genesis is not None:
                self.db.execute("CREATE TABLE events (seq INTEGER PRIMARY KEY,role TEXT NOT NULL,digest TEXT NOT NULL UNIQUE)")
                self.db.execute("INSERT INTO events VALUES (0,?,?)",(role,genesis))
            self.read()
        except BaseException:
            self.db.close()
            raise
    def close(self):
        self.db.close()
    def read(self):
        rows=self.db.execute("SELECT seq,role,digest FROM events ORDER BY seq").fetchall()
        v.need(rows and all(x[0]==i and x[1]==self.role and HEX.fullmatch(x[2])
                           for i,x in enumerate(rows)),"Witness journal invalid")
        return rows[-1][2]
    def assert_state(self,digest):
        v.need(self.read()==digest,"External checkpoint mismatch")
    def advance(self,before,after):
        v.need(HEX.fullmatch(before) and HEX.fullmatch(after),"Invalid checkpoint")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.assert_state(before)
            if before!=after:
                v.need(not self.db.execute("SELECT 1 FROM events WHERE digest=?",(after,)).fetchone(),
                       "Checkpoint rollback/reuse")
                self.db.execute("INSERT INTO events(role,digest) VALUES (?,?)",(self.role,after))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
    def handle(self,req):
        v.need(type(req) is dict and req.get("role")==self.role,"Wrong witness scope")
        if set(req)=={"role","operation"} and req["operation"]=="read":
            return {"role":self.role,"digest":self.read()}
        v.need(set(req)=={"role","operation","before","after"} and req["operation"]=="advance",
               "Invalid witness request")
        self.advance(req["before"],req["after"])
        return {"role":self.role,"digest":req["after"]}

def main():
    os.umask(0o077)
    # role is selected by administrator-installed forced command, never stdin.
    v.need(len(sys.argv) in (3,4) and sys.argv[1] in ROLES,"Invalid command")
    role=sys.argv[1]
    path=ROOT/(role+".sqlite")
    if sys.argv[2]=="init":
        v.need(len(sys.argv)==4,"Explicit genesis required")
        WitnessStore(path,role,genesis=sys.argv[3]).close()
        return
    v.need(sys.argv[2]=="serve" and len(sys.argv)==3,"Invalid serve command")
    raw=sys.stdin.buffer.read(MAX+1)
    v.need(0<len(raw)<=MAX,"Invalid witness request size")
    store=WitnessStore(path,role)
    try: print(json.dumps(store.handle(json.loads(raw)),sort_keys=True))
    finally: store.close()

if __name__=="__main__":
    main()
