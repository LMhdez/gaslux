# GASLUX-OBSERVER — kernel peer / transport FD / claimed session

**DENY-ONLY diagnostic, not a guest trust root or Bazzite channel.**

## Pinned dependencies and scope

The new `guest_transport_peer_boundary.py` consumes only the frozen
`ProcessSeal` type from Observer [#312](https://github.com/LMhdez/gaslux/pull/312),
pinned at `2ec6c97cbd72a52349e0efdcdf3a75b0d120fa64`.
This avoids copying or importing the experimental #259 state machine, QEMU
launcher, authorization ledger or GPT/Windows stack.

[Bazzite #280](https://github.com/LMhdez/gaslux/pull/280), HEAD
`8d5e8c11d9e86bf66f0902d099ff4393f86b71b2`, remains unchanged and
`REFUSED_NO_AUTHENTICATED_GUEST_COLLECTOR_CHANNEL`. Original pinned contract
tests are rerun. #267 Safety and #286 canonical GPT FD are also pinned
and tested. The `dev` Observer `boundary_model.py` is a **synthetic model**,
not a real Linux socket peer witness; #312 already supplies HOST identity.

## What is actually measured

For an existing Linux AF_UNIX stream socket, the witness samples at start
and end: actual FD dev/inode via fstat, SO_PEERCRED PID/UID, procfs start
ticks, command SHA-256 and executable dev/inode. Linux poll detects a
disconnected FD. All observations are read-only; there is no socket
send/recv, QMP execution, Anaconda/guest command, QEMU launch or disk I/O.

Externally supplied process/session pins and the untrusted envelope are
**claims**, including hostVmId, disk SHA, collector SHA, session UUID,
transaction UUID and challenge. They must match exactly; any missing,
extra or positive authority/provenance field is rejected. Matching claims
never become independent evidence. Only the **local host peer descriptor**
is reported as LOCALLY_MEASURED.

On a positive local sample, the result STILL says:
`status=BLOCKED_TRUST_ROOT`, `classification=NOT_INDEPENDENT`,
`safetyAssessment=DIAGNOSTIC_ONLY`. Guest/VM/disk/collector/Anaconda
authentication remains false. All of `inputAuthorized`,
`diskWritesAuthorized`, `productionInstallationAuthorized`,
`productionWriteAuthorized`, `installationAuthorized`,
`guestCommandChannelAuthorized`, `externallyAttested`,
`freshnessAuthenticated`, `replayProtected`,
`persistentLedgerVerified` and `operationalApprovalVerified` remain false.

## Limitations and next required trust root

`SO_PEERCRED` authenticates the **local Linux peer**, not a guest origin;
a host-side proxy or synthetic Python child can pass. Supplied reference
pins are not externally approved. Two samples cannot exclude ABA,
transient exec/FD substitution, hostile host interference or identity
reuse. Single use is enforced only in memory in the current witness
instance; it is **not** a persistent replay-resistant ledger.
The disk backend→QEMU FD association, delivery of an authenticated guest
collector, Anaconda process identity, independent signed approval,
cryptographic freshness and Windows recovery are **not established**.

CI uses a Linux-hosted disposable Python peer and real AF_UNIX socket.
Attacks include divergent process/UID/start ticks/argv/exe, changed VM,
disk and collector claim, forged provenance, closed/replaced FD, process
exit/disconnect, stale session and attempted write authority. The
workflow checks exact upstream #312, Bazzite #280, Safety #267 and GPT
#286 SHA pins, plus Ruff/compileall and inherited F-01/F-02/F-03 tests.

**Next:** independent protected issuer linking actual QEMU process,
backend/disk FD, controlled guest delivery and exact guest collector
process, with persistent challenge consumption and separate Safety
approval. None of that is supplied or enabled here.

No QEMU, guest, installer, GPT/ESP/BCD/WinRE/NVRAM or disk writes, no merge.
