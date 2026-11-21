# GASLUX-OBSERVER — experimental HOST/QEMU FD evidence (NO QEMU launch)

**Mode: OFFLINE_DIAGNOSTIC / DENY ONLY.** This implementation collects
read-only, *local* host evidence from externally pinned process/file identity.
It **does not** create or approve a VM; it cannot serve as an execution,
partitioning, boot, input, replay, rollback or recovery authority.

References pinned on 2026-11-21:
- Original Observer [PR #259](https://github.com/LMhdez/gaslux/pull/259),
  HEAD e9055bf6e9d83d5c758b69a3a77a8c4a6fd48748, implements
  lab_identity.process_seal and allowlisted QMP read-only query-block.
- GPT producer [PR #272](https://github.com/LMhdez/gaslux/pull/272),
  audited dd3e7bf26e36499f89701393773df464ce713e4f, owns
  capture_fresh_immediate and _qemu_executable_hash; NOT modified.
- One-shot [PR #275](https://github.com/LMhdez/gaslux/pull/275),
  HEAD 1a6446b408c78386e720f8d2b1f2063c1d3f7db1: execution still
  BLOCKED until independently protected controller and durable grant.
- GPT FD [PR #286](https://github.com/LMhdez/gaslux/pull/286),
  HEAD 9aed36cfdb8c09a461dc38811c326c54180273de, is **sole**
  GPT FD parser and CRC/geometry authority. Its inspect_gpt_fd,
  read_header and exact_read are used directly. No duplicate GPT parser.
- Safety no-writer [PR #267](https://github.com/LMhdez/gaslux/pull/267),
  HEAD 0be04192acd542646a5b6cd952e01620379edf5d; optional
  verify_chain from its existing QEMU lab validates QCOW2/backing at a
  caller-owned private workspace. No new cryptographic verifier.
- Crosscheck [PR #290](https://github.com/LMhdez/gaslux/pull/290),
  HEAD 0cfdeab547643ed9f57e51a3b77e38251b6b896b, independent
  Safety audit [#7065611081](https://github.com/LMhdez/gaslux/pull/290#issuecomment-7065611081)
  = ACCEPTABLE_DENY_ONLY, without independent provenance or permission.
  This experiment does not repeat #290's structural-comparison audit.
- One-shot ledger [PR #285](https://github.com/LMhdez/gaslux/pull/285),
  HEAD fda13b8a2a48d8e5f00c3f9be306499d85e0d336, is an
  **OFFLINE model**, not an operational grant issuer. Not imported.

## Interfaces

Use module auto_tests/installer_observer/host_qemu_fd_evidence.py.

1. HostPins: externally supplied immutable *expected* ProcessSeal, exact
   executable SHA-256, PID/start ticks/UID, transaction ID, VM UUID,
   challenge, virtual device name/serial, FD number, canonical file identity,
   disk geometry. **Caller declarations are not authenticated** by
   constructing a dataclass.
2. borrowed_readonly_proc_fd: observes /proc/PID/fd/N and fdinfo read-only,
   checks the descriptor's original flags, regular-file kind, owner,
   link count, path, device/inode/size/mtime/ctime; reopens the procfd only
   O_RDONLY and rechecks the pinned identity across the capture. The reopened
   handle is a new local file description, **not** a duplicated QEMU handle.
   No block device, symlinked media or hardlinked media is accepted.
3. observe_descriptor: returns first-sector SHA-256 plus actual FD identity
   and means of observation as LOCALLY_MEASURED. This does **not** prove
   that the process is QEMU or a disk is linked to any VM.
4. measure_gpt_from_proc_fd: invokes the pinned #286 inspect_gpt_fd on that
   read-only descriptor. Only after successful full primary/secondary GPT CRC,
   PMBR and topology validation does it return per-region *actual bytes*
   SHA-256, measured with pinned #286 read_header and exact_read. It does
   **not** hash full partition contents or claim physical sector size.
   Input must be RAW; QCOW2 must not be parsed as raw sectors.
5. query_qemu_block_readonly: when an independently prepared QEMU process
   actually exists, reuse #259 bounded QMP framing/allowlisted
   qmp_capabilities/query-block with Linux SO_PEERCRED to the fixed PID+UID
   and a private Unix socket. The module does **not** spawn QEMU. A QMP
   query is *not* a guest command. The requesting controller must separately
   be authorized to observe the existing VM.
6. correlate_qmp_fd: cross-check QMP inserted block path/format/read-only
   and declared device against measured FD device/inode/size. It refuses
   missing, ambiguous, swapped device/file, inconsistent declared VM UUID
   or serial. **QMP query-block alone does not cryptographically bind its
   virtual device to the exact kernel FD or independently attest VM UUID /
   serial**, even if the claims are identical. Thus it NEVER sets
   deviceFdAssociationProven or vmDiskBindingProven to true.
7. observe_pinned_qcow2_chain: optional, same-runner read-only QCOW2 header
   plus pinned #267 verify_chain, with explicit workspace/backing. It
   validates QCOW2/path/inode/hash/geometry locally but **does not** prove
   the overlay's effective GPT from the backing RAW image. It is NOT called
   automatically by RAW GPT capture.
8. observe_host_qemu: available ONLY to a separately authorized observer of
   a pre-existing process. It repeats #259 process_seal, checks exact
   process identity and #272 executable hash, measures real FD/GPT and
   optionally queries QMP. Failure of process/FD/GPT refuses measurement.
   Missing or unverified QMP association results in
   associationDecision=DENY_UNVERIFIED_VM_FD_BINDING. It cannot launch,
   write, send guest input or authorize execution.

**No local CLI or GitHub Action invokes observe_host_qemu on a real QEMU
process.** The CI uses real disposable Python child processes and FDs
without QEMU. A synthetic QMP list is tested ONLY by injecting untrusted
data into correlate_qmp_fd; this is never a measurement.

## Measured / claimed / not proved (no EXTERNALLY_ATTESTED emitted)

| Field | Source | Label and scope |
|---|---|---|
| PID/start ticks/UID | #259 process_seal on existing QEMU | LOCALLY_MEASURED, only when process exists and exactly matches external pins |
| Executable inode and full SHA-256 | #259 process_seal and #272 executable reader | LOCALLY_MEASURED, when process available; only same-host identity |
| FD number + dev/inode/size/timestamps | procfs FD and pinned local reopen | LOCALLY_MEASURED, not a VM device proof |
| GPT headers/arrays, CRC, GUID/PARTUUID, geometry | #286 inspect_gpt_fd/read_header/exact_read on pinned **RAW FD** | LOCALLY_MEASURED, whole partition content NOT hashed |
| Backing chain and QCOW2 metadata | #267 verify_chain when invoked in controlled private workspace | LOCALLY_MEASURED, same-host; no immutable external checkpoint |
| Virtual device label from genuine query-block | #259 QMP socket peer credential + query-block | LOCALLY_MEASURED, still no independently authenticated disk-to-FD binding |
| Serial/VM UUID/transaction/challenge | external HostPins or QMP claims | CLAIMED; comparison != attestation |
| QMP test-injected device/path | controlled JSON fixture | CLAIMED only, NEVER measured |
| Controller authority, issuance and consumption | None in module | NOT PROVED; no EXTERNALLY_ATTESTED |
| Replay/freshness/checkpoint immutability | No protected ledger or externally issued challenge | NOT PROVED; replayProtected=false |
| Windows health/dual boot/rollback | No Windows testing | NOT PROVED |
| Disk-write or guest-input authority | None | ALWAYS false |

An attacker controlling the same host/UID can alter process state/QMP data.
Matching file hashes, inode, serial, VM UUID and transaction strings are
consistency checks, **not** an independently authenticated chain of custody.
No timestamp, hash or digital signature is treated as authorization.
A stale old snapshot with identical regions may remain locally equal.
No replay database or second cryptographic signature implementation exists.

## Evidence sample, CI and adversarial testing

[docs/samples/OBSERVER_HOST_FD_SYNTHETIC.json](samples/OBSERVER_HOST_FD_SYNTHETIC.json)
is an explicitly **UNMEASURED synthetic illustration**, not a fabricated
host observation. Runtime measurements only exist when resources have
actually been examined; test fixture values never claim external attest.

Offline workflow: .github/workflows/observer-host-fd-evidence-offline.yml
- Ubuntu 24.04 disposable runner; checkout action SHA pinned, all sources
  checked out by full SHAs; persist-credentials=false, contents:read.
- Tests: genuine Linux subprocess + /proc fd, wrong PID, start ticks,
  executable inode, wrong FD, path replacement, hardlink/symlink,
  missing process, altered backing, wrong virtual device/serial/VM UUID,
  stale PARTUUID and invalid GPT CRCs, repeated challenge and absence of
  measured origin, plus negative QMP mapping and workflow trigger checks.
- Pinned #286 canonical GPT FD tests and pinned #267 no-writer tests.
- Ruff/compileall, clean checkouts before/after tests; NO QEMU binary,
  process, VM, guest, disks from Windows or installer/writer tests invoked.
- Failures are not retried as successful evidence. Run artifacts are CI
  logs only, not a signed host attestation. No QCOW2 image is uploaded.

## Safety boundary and future requirements

**Classification:** NOT_INDEPENDENT / DIAGNOSTIC_ONLY. Operational flags
inputAuthorized=false, diskWritesAuthorized=false,
productionInstallationAuthorized=false, productionWriteAuthorized=false,
writerAuthorized=false, originAuthenticated=false,
freshnessAuthenticated=false, replayProtected=false,
externallyAttested=false. All binding/privilege promotion is denied.

Before independent evidence becomes possible, GASLUX-INTEGRATOR/Safety
must supply (outside requesting branch) a protected observer and controller,
a signed/verified VM-to-device mapping, independent authenticated challenge
issuer/consumer with persistent one-time replay protection, immutable
checkpoint/fencing or new read after state changes, a trusted QMP-device
to FD linkage (or alternative independent virtualization evidence), and
backing+overlay binding backed by a protected run contract. Re-audit scope,
permissions and actual resource use. #275 remains fail-closed.
Do not merge, declare stable, launch QEMU or touch Windows storage on the
basis of this diagnostic evidence.
