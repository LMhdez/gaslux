#!/usr/bin/python3
"""Forced SSH entrypoint. No shell interpolation or caller-selected role."""
import os
import sys

CODE="/opt/gaslux-authority"
COMMANDS={
    ("safety","gaslux-safety-query-v1"):("safety_signer.py","query"),
    ("safety","gaslux-safety-feed-v1"):("safety_signer.py","poll"),
    ("witness-signer","gaslux-witness-v1"):("authority_anchor.py","signer","serve"),
    ("witness-publisher","gaslux-witness-v1"):("authority_anchor.py","publisher","serve"),
}

def main():
    if len(sys.argv)!=2:
        raise SystemExit(64)
    command=COMMANDS.get((sys.argv[1],os.environ.get("SSH_ORIGINAL_COMMAND","")))
    if command is None:
        raise SystemExit(64)
    os.umask(0o077)
    os.chdir(CODE)
    os.execve("/usr/bin/python3",["/usr/bin/python3","-B",CODE+"/"+command[0],*command[1:]],
              {"PATH":"/usr/bin:/bin","HOME":"/nonexistent","LANG":"C.UTF-8"})

if __name__=="__main__":
    main()
