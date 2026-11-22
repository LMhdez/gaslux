# BZD-DEST-01 — contract-driven negative tests (read-only)

## Status and provenance

This is a **test-only** proposal based on `dev` at `8e68a475d6397ba8fef2e0f9f83758545e202a5f`.
It uses the **actual** unmodified experimental no-writer gate from PR #267,
pinned to commit `0be04192acd542646a5b6cd952e01620379edf5d`.
The Bazzite #320 OCI/RPM contract and #319 HOST/FD are NOT modified. No
writer, QEMU process, guest collector, Windows boot or rollback is exercised.

A positive fixture must produce `ACCEPT_NO_WRITER`, NOT installation authority.
Mutation cases accepting invalid snapshots are failures.

## Five adversarial families

| Family | Executed tests on #267 | Missing authenticated contract |
|---|---|---|
| A DESTINATION_SWAP | Altered GUID, disk size and PARTUUID deny | Swapping QCOW2 path/inode/backing after signing identical JSON: strict XFAIL |
| B FD_ALIAS | No real backend-FD correlation in #267 | Two FDs/path aliases associated with different objects: strict XFAIL |
| C GPT_GEOMETRY_MISMATCH | Wrong disk GUID, sector, disk size and partition offset deny | Complete raw GPT/PMBR readback through pinned FD prior to writer |
| D CHECKPOINT_TAMPERING | Foreign owned region denies | Actual durable checkpoint bytes, transaction and independent restoration: strict XFAIL |
| E GUEST_EVIDENCE_SPOOF | Invalid MAC or wrong VM/source denies | A guest channel independently authenticated against VM/process: strict XFAIL |

**XFAIL(strict=True) is not PASS, not DENY, and not implementation completion.**
It deliberately captures an unmet contract: on the current gate, the altered
outside-world destination/checkpoint/guest provenance cannot be supplied.
On an eventual shared contract, replace those markers with exercised real
observations and assert explicit denial. A validator that simply denies every
input does NOT satisfy this suite because the positive `ACCEPT_NO_WRITER`
fixture must still pass, although this never grants writing.

## Required shared interface (Integrator 2 owns implementation)

Define a reusable **read-only** `assess_authenticated_destination(...)` contract,
keeping existing no-writer semantics. Inputs must bind all of:

* Immutable signed OCI manifest/config/diffids/bootc RPM digest and immutable transaction plan.
* Pinned host FD identity (dev/inode/size, process seal/startticks), exact QCOW2
  backing chain/child provenance and guest effective disk identity; no trust
  from QMP path declarations alone.
* GPT primary/backup CRCs, logical/physical sector geometry, protected
  partition GUID/PARTUUID ranges, ESP, Windows BCD and WinRE read-only baseline.
* Durable checkpoint manifest, owner transaction, recoverability and
  post-restoration independent verification.
* Guest provenance from independent protected issuer/transport; keys embedded
  in runner or HMAC on self-declared observations cannot attest the guest.
* Explicit decision `DENY` on any inconsistent/absent link, or
  `STRUCTURALLY_CONSISTENT_NO_WRITER` if all **authenticated** prerequisites
  are present. Never return write authorization or rollback success from
  this read-only gate.

Do not map the existing `ACCEPT_NO_WRITER` to installation permission. Before
a writer exists, demand independent Safety review, durable rollback proof,
Bazzite UEFI/GPT-only compatibility and authorized disposable VM trials.

## Limits

These fixtures are only 16 MiB synthetic identity documents, not authenticated
QCOW2, raw GPT, actual process FD, guest attestation or rollback evidence.
No real disk bytes are written. The tests are useful *precisely because* they
distinguish existing protections from the missing transaction-to-destination
binding and cannot be offered as a release gate.
