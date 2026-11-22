# AUTHENTICATED-DESTINATION-01 — read-only host/FD contract (experimental)

**Date:** 2026-11-22 UTC. **Scope:** isolated Linux runner with a previously
started, paused QEMU and *private disposable* regular-file QCOW2 + RAW backing.
**No Windows guest, OS installation, disk writer, ESP/BCD/WinRE mutation,
firmware changes or production permission.**

## Implemented core

`auto_tests/installer_observer/authenticated_destination.py` exports
`assess_authenticated_destination(...)`. Its name describes the future
authentication goal; the **current result does not authenticate the destination
end-to-end**. It consumes, without reimplementation:

- `QemuLocalDiskWitness` from merged Observer #325, with `ProcessSeal`,
  pidfd, local read-only `/proc/PID/fd` witness and QMP peer identity;
- existing `inspect_gpt_fd` and `assert_snapshot_matches` from `dev`,
  applied to a pinned RAW backing **never to QCOW2 bytes**;
- unchanged experimental Safety #267 `decide_no_writer`, imported from the
  SHA-pinned test checkout, to validate plan/transaction, three MAC-bound
  snapshots and exclusively claimed/owned write extents.

Additionally, the core opens **no files** on behalf of the caller and
accepts only caller-opened read-only FDs, checked against real `fstat` and
`lstat` (device, inode, size, mtime, ctime, owner, one hard link, exact path).
It measures QCOW2/backing SHA-256 from those FDs, checks actual QCOW2 magic,
and invokes `qemu-img info --backing-chain` on inherited
`/proc/self/fd/N` with `pass_fds` to compare observed virtual geometry and
the explicitly pinned RAW backing. It reads actual primary and secondary GPT
through the canonical FD parser on the RAW backing, and checks GUIDs, partition
UUIDs and offsets via the existing snapshot matcher.

A separate caller-opened read-only checkpoint FD has its bytes, SHA-256,
transaction, source hashes and GPT identity compared. It is a *diagnostic
receipt*, not an independently authenticated recovery or proof that Windows
can be restored. The checkpoint `restoreProven` must be explicitly `false`.
The optional ISO/OCI/native ISO source identity is **CLAIMED**, never verified
by this shared component. OCI/RPM checking remains Bazzite-specific.

Any guest claim is refused because no independent collector trust root exists.
The QEMU witness correlates local process, observed open FD and peer-checked
QMP reply, but QMP is still a QEMU claim, not a proof of the *internal backend
pointer* or guest-visible data. A borrowed procfd is a newly opened local
descriptor, not the original QEMU kernel file description. Transient
fd-table ABA and concurrent in-place mutations are not fully prevented.

## Property matrix

| Property | Assessment | Meaning |
|---|---|---|
| Local QEMU process/PID start and SO_PEERCRED of QMP | **PROVEN** | Local measurement only |
| Open read-only QEMU FD and own QCOW2 FD identity | **PROVEN** | Same measured file dev/inode/size at sampled boundaries |
| RAW backing regular-file FD and SHA-256 | **PROVEN** | Sampled local bytes match expected caller hash |
| QCOW2 backing path/virtual geometry | **PROVEN locally** | qemu-img read-only inspection of held QCOW2 FD |
| Signed origin of transaction/plan and source ISO/OCI | **CLAIMED** | #267 HMAC is not an independent plan signature |
| QEMU internal backend to original FD | **UNPROVEN** | QMP claims are not independent backend attestation |
| Guest-effective GPT, ESP/FAT32, BCD, WinRE | **UNPROVEN** | RAW backing GPT is not QCOW2 overlay/guest GPT |
| GPT primary/backup and PARTUUID of RAW backing | **PROVEN locally** | Canonical FD reader verifies both |
| Proposed region ownership | **CLAIMED** | #267 validates declared intervals, not creation provenance |
| Checkpoint bytes and SHA-256 | **PROVEN locally** | Independent trust/Windows restore unproven |
| Independent checkpoint transaction/authenticity | **UNPROVEN** | Hash supplied by caller, may be self-authored |
| Guest origin and collector authentication | **DENIED** | No independent guest root of trust |
| Installation/write/release/stability authority | **DENIED** | Always false |

On a structurally valid input the status is
`READONLY_STRUCTURE_OBSERVED`, authorization `DENY_NO_WRITER` and
`productionStorageWritesAuthorized=false`,
`guestCommandChannelAuthorized=false`, `rollbackProven=false`,
`sameDiskDualBootVerified=false`, `stable=false`.

## Adversarial regressions

The real stopped-QEMU CI reuses the isolated runner conditions and scripts
from #325. It exercises:
`DESTINATION_SWAP`, `FOREIGN_FD` (QCOW2, RAW and checkpoint),
`QCOW2_BACKING_SWAP`, `GPT_GEOMETRY_MISMATCH`,
`TRANSACTION_MISMATCH`, `UNOWNED_WRITESET`,
`CHECKPOINT_TAMPER`, `SPOOFED_GUEST`, and a
`VALID_READONLY_INSPECTION` that **cannot grant writes**. The original
#327 BZD-DEST-01 known-gap suite remains unchanged in its pinned checkout.
Its historical gap tests are **not** reinterpretations of successful denials.
The new suite exercises real fd/path/byte attacks against this new concrete
interface.

Workflow:
`.github/workflows/contracts-authenticated-destination-readonly.yml`.
Pinned #267 `0be04192acd542646a5b6cd952e01620379edf5d`,
BZD #327 `45c430b6861ba3dce3b9e33bf3f9cccfb2b29a52`,
GPT #286 `9aed36cfdb8c09a461dc38811c326c54180273de`.
Only the canonical GPT parser present on `dev` is invoked by the new
destination module; the historical GPT pin is used by reused QEMU fixtures.

**No positive test certifies end-to-end authenticated destination.**
Before a writer, Safety/Observer must prove external plan authority,
the original QEMU backend-FD association, effective guest GPT,
independent collector origin/freshness, checkpoint provenance,
Windows recovery and rollback; do not use this module as a writer gate.
