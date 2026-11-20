#!/usr/bin/env python3
"""Guest streaming BIO witness for one owned Pop-only QCOW2 partition pair.

Runs inside signed Pop ISO QEMU. Streams kernel block_bio_queue, bounds memory,
and refuses incomplete/foreign/discard writes. Does not claim BIO completion.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import sys
import time

TRACE = Path("/sys/kernel/tracing")
STOP = Path("/run/gaslux-pop-bio-stop")
READY = Path("/run/gaslux-pop-bio-ready")
REPORT = Path("/run/gaslux-pop-bio-report.json")
EVENT = re.compile(r"\bblock_bio_queue:\s+(\d+),(\d+)\s+([A-Z]+)\s+(\d+)\s+\+\s+(\d+)")
PID = re.compile(r"(.+)-(\d+)\s+\[")
SECTOR_COUNT = 32*1024**3//512
PARTITIONS = ((2048,2048+2097152),(2099200,2099200+58720256))
MAX_EVENTS = 2_000_000


def fail(msg):
    REPORT.write_text(json.dumps({"observationComplete": False, "refusal": msg})+"\n")
    sys.exit(1)


def coverage(intervals):
    merged=[]
    for start,end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1]=(merged[-1][0],max(merged[-1][1],end))
        else:
            merged.append((start,end))
    h=hashlib.sha256()
    for start,end in merged:
        h.update(f"{start}:{end}\n".encode("ascii"))
    return h.hexdigest(),len(merged)


def main():
    if os.geteuid()!=0 or not Path("/sys/firmware/efi").is_dir():
        fail("not privileged EFI lab")
    target=Path("/dev/disk/by-id/virtio-GASLUXPOPFULLVM").resolve(strict=True)
    assert str(target).startswith("/dev/vd")
    mm=Path("/sys/class/block") .joinpath(target.name, "dev").read_text().strip()
    major,minor=(int(x) for x in mm.split(":"))
    zram=set()
    for candidate in Path("/sys/block").glob("zram*"):
        if candidate.resolve().is_relative_to(Path("/sys/devices/virtual/block")):
            zram.add(tuple(int(x) for x in (candidate/"dev").read_text().strip().split(":")))
    event_enable=TRACE/"events/block/block_bio_queue/enable"
    if not event_enable.is_file() or not (TRACE/"trace_pipe").is_file():
        fail("required BIO tracepoint missing")
    (TRACE/"tracing_on").write_text("0\n")
    (TRACE/"trace").write_text("")
    (TRACE/"buffer_size_kb").write_text("8192\n")
    event_enable.write_text("1\n")
    (TRACE/"tracing_on").write_text("1\n")
    READY.write_text(mm+"\n")
    stats={"blockBioQueueEventCount":0,"writeEvents":0,"writeBytes":0,
           "flushEvents":0,"foreignWritableEvents":0,"unsupportedEvents":0}
    intervals=[]
    procs={}
    start=time.monotonic()
    last_stop=None
    try:
        with (TRACE/"trace_pipe").open("r",errors="replace") as pipe:
            while time.monotonic()-start < 1800:
                r,_,_=select.select([pipe],[],[],0.2)
                if not r:
                    if STOP.exists():
                        if last_stop is None: last_stop=time.monotonic()
                        elif time.monotonic()-last_stop>2: break
                    continue
                line=pipe.readline()
                if not line: continue
                if "block_bio_queue:" not in line: continue
                match=EVENT.search(line)
                if match is None: fail("unparseable BIO queue event")
                m,n,flags,sector,count=(
                    int(match[1]),int(match[2]),match[3],int(match[4]),int(match[5]))
                if (m,n) in zram: continue
                if (m,n)!=(major,minor):
                    stats["foreignWritableEvents"]+=1
                    fail("write-like BIO on unowned guest block device")
                stats["blockBioQueueEventCount"]+=1
                if any(flag in flags for flag in ("D","Z")):
                    stats["unsupportedEvents"]+=1
                    fail("discard/write-zeroes observed")
                if count==0:
                    if sector!=0 or not flags.startswith("F") or "W" not in flags:
                        fail("malformed zero-length BIO")
                    stats["flushEvents"]+=1
                    continue
                if count<0 or "W" not in flags or not 0 <= sector < sector+count <= SECTOR_COUNT:
                    fail("invalid BIO write bounds")
                if not any(lo<=sector and sector+count<=hi for lo,hi in PARTITIONS):
                    fail("BIO write touched GPT or non-owned disk space")
                stats["writeEvents"]+=1
                stats["writeBytes"]+=count*512
                intervals.append((sector,sector+count))
                pm=PID.search(line.split("block_bio_queue:",1)[0])
                if pm:
                    process=pm.group(1).strip()
                    procs[process]=procs.get(process,0)+1
                if stats["blockBioQueueEventCount"]>MAX_EVENTS:
                    fail("BIO observation bounded-event limit exceeded")
            else:
                fail("BIO witness timed out before shutdown marker")
    finally:
        (TRACE/"tracing_on").write_text("0\n")
    loss=[]
    for p in (TRACE/"per_cpu").glob("cpu*/stats"):
        for text in p.read_text().splitlines():
            if re.match(r"^(overrun|commit overrun|dropped events):\s*[1-9]",text):
                loss.append(text)
    if loss: fail("BIO tracefs buffer loss")
    if not stats["writeEvents"]: fail("no installed-target BIO write evidence")
    digest,groups=coverage(intervals)
    stats.update({"observationComplete":True,"targetMajorMinor":mm,
                  "writeCoverageSha256":digest,"mergedIntervalCount":groups,
                  "processWriteEventCounts":dict(sorted(procs.items())),
                  "blockRqIssueEvidenceAvailable":False,
                  "bioCompletionVerified":False,"transientNVRAMProvenAbsent":False})
    REPORT.write_text(json.dumps(stats,sort_keys=True,separators=(",",":"))+"\n")


if __name__=="__main__":
    try:
        main()
    except (OSError,ValueError,AssertionError) as exc:
        fail(str(exc))
