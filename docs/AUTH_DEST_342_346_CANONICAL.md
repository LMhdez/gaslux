# D342-D346-CANONICAL-COMPOSE-01 — proposed read-only 128 GiB contract

**Date:** 2026-11-22 UTC. **Scope:** independent comparison of Draft
[#342](https://github.com/LMhdez/gaslux/pull/342)
HEAD `986ccf6d5ee11427e969022f6b8b5d5f48ec16c3`
and Draft [#346](https://github.com/LMhdez/gaslux/pull/346)
HEAD `9306d0fff8cc89794b83fe002ae133c110e641ae`.
Parent [#337](https://github.com/LMhdez/gaslux/pull/337)
HEAD `f1e082c37ab58887f942b1e9ab0a841cb4b2b02a`
has the independent D-337-01 complete-read SHA-256 correction.
**No upstream branch is modified by this composition.**

## Exact ancestry and boundaries

Relative to the present parent #337, #342 is historically stacked on old
#337: it has *diverged* (four commits ahead, eight behind at inspection);
the later Safety D-337-01 changes are not all in its ancestry. It changes
six paths, including the old `authenticated_destination.py`, a workflow,
tests and documentation. Do not copy that old parser/guard or use its entire
branch as a base for integration.

#346 is a descendant of current #337 (ten commits ahead, zero behind at
inspection) and changes seven paths relative to #337: a standalone large
read-only inspector, tests, workflow, docs and one additional full receipt
read-length check. It preserves the parent's digest and independent RED
regressions and uses QEMU/FD, canonical GPT and #267 no-writer contracts.
This composition builds on #346 only.

## Differential property matrix

| Area | #342 | #346 | Canonical decision |
| --- | --- | --- | --- |
| Host QCOW2 and RAW regular-file FD identity | fstat/lstat, O_PATH and foreign FD refusal | pinned QCOW2, RAW and checkpoint FDs plus QEMU witness | Keep #346; no second `_pin` |
| Maximum virtual capacity | metadata-only, 128 GiB | 128 GiB RAW GPT, QCOW2 virtual/backing chain via qemu-img | Keep stronger #346 |
| QCOW2 header | 32 bytes, version 2/3 and virtual size checked | 4-byte magic plus qemu-img virtual-size validation | Transport bounded 32-byte version/size cross-check into #346 |
| QEMU/guest observations | no QEMU process proof | real stopped QEMU ProcessSeal, QMP/procfd host witness | Keep #346; internal backend/guest origin still unproven |
| GPT primary/backup | no GPT parse | canonical `inspect_gpt_fd` on pinned RAW | Keep #346 |
| Full integrity | none, 512 MiB cap noted | QCOW2 full SHA, 64 KiB RAW sampled, whole 128 GiB RAW SHA denied | Keep explicit `FULL_BACKING_HASH_NOT_COMPLETED` refusal |
| Capacity/free-space estimate | `statvfs` compared with full 128 GiB checkpoint reserve | minimum 1 MiB host free + caller-provided 64 MiB quota | Add informational full-reserve estimate, NEVER a reservation or authorization |
| Allocation blocks | `st_blocks` and final recheck | stricter per-image and aggregate bounds, final identity only | Keep stricter #346 and add final `st_blocks` recheck |
| Receipt/transacted plan | no checkpoint/transaction | pinned receipt SHA/bytes, #267 plan/write-set check | Keep #346: source/MAC/checkpoint independence still CLAIMED |
| Adversarial tests | 12 separate metadata-only probes, QCOW header, capacity | paused-QEMU 128 GiB GPT/backing/receipt, short FD, quota, mutations; plus #337, #267, #327 | Replay #342 original tests in its own immutable checkout and test transported checks against the canonic API |
| Documentation | older #337-era scope and 512 MiB budget | #346 resource taxonomy with 64 MiB apparent QCOW, <=32 MiB allocated per image | Retain dated records, document this composition |

## Proposed single contract

`auto_tests/installer_observer/large_sparse_destination.py`
exports `assess_sparse_128g_readonly(...)` and remains the **only proposed
canonical large-destination assessment**. It is not a production installer
or authenticated guest-device mapping. This composition deliberately does
**not** add `probe_destination_scale_metadata` to #346 and does not copy
the older #342 `authenticated_destination.py` body.

The first 32 bytes of the real pinned QCOW2 are read once with an exact
length requirement; version 2/3 and big-endian virtual size are checked
against the pinned RAW backing before the existing `qemu-img` backing-chain
inspection. The final allocation-block measurements must match initial
ones, in addition to existing dev/inode/size/mtime/ctime identity.
`statvfs` free bytes compared with 128 GiB are exposed only as
`checkpointCapacityEstimateSufficient`, together with
`checkpointReserveProven=false`. A caller-supplied quota is never an
independent quota attestation; even a simulated sufficient estimate grants
**zero** additional authority.

On a valid structurally observed 128-GiB RAW, the function **raises**
`LargeDestinationRefused("FULL_BACKING_HASH_NOT_COMPLETED")` with bounded
diagnostic status `STRUCTURE_OBSERVED_FULL_HASH_DENIED` and
`DENY_NO_WRITER`. Only 64 KiB RAW edge sampling was performed; a sample
SHA is not a whole-file SHA, and 128 GiB of full bytes are explicitly
**not authenticated**. The original small-file positive #337 SHA/FD tests
remain part of the regression set.

## Regressions and acceptance

`.github/workflows/auth-dest-342-346-canonical.yml` runs on an isolated
GitHub-hosted Linux runner, with SHA-pinned checkouts of #267, GPT #286,
#327 and #342, no persisting credentials or guests. The immutable #342
metadata suite is executed in its **own** checkout, not imported as a
second runtime API. The current branch runs the actual #346 paused-QEMU
suite, extra canonical header/version/capacity/allocation/foreign-recovery
negatives, #337 independent D-337-01 RED + positive SHA tests, #327 BZD,
#267, HOST/FD, six-backend schema, Ruff and compileall.

Refuse truncated or foreign RAW backing, inconsistent QCOW2 header/GPT,
short read, concurrent inode/allocation mutation, claimed quota unknown,
checkpoint with invalid transaction or caller-updated false recovery,
guest source spoofing, full RAW digest not completed and all writes.
No Windows install, guest OS, physical block device, ESP/BCD/WinRE/NVRAM
or functional Windows rollback is invoked.

**State:** draft candidate pending exact-head CI and independent Safety
differential review, including future findings on #346. Do not close
#342 or #346 or merge any branch before that review, an integration
decision and preservation proof. A green QEMU run cannot certify
Windows dual boot, source provenance, independent checkpoint identity,
QEMU backend→FD binding, guest collector origin, rollback or stability.

## Exact implementation CI (2026-11-22 UTC)

The composition code HEAD `72106b2dfe4d38612ea37cdc8b0618a33298fa9e`
has two independent GitHub Action executions:
[push #45037589606](https://github.com/LMhdez/gaslux/actions/runs/45037589606)
and [PR #45037640437](https://github.com/LMhdez/gaslux/actions/runs/45037640437),
**both SUCCESS at the same exact SHA**. These runs include:
- New #346 canonical QEMU-stopped/128GiB sparse RAW GPT, QCOW2 header,
  checkpoint capacity-estimate, final allocation-block, truncated backing,
  SHA-incomplete and spoofed checkpoint/guest cases;
- Full original #342 12-case metadata probe suite executed without
  modifying its checkout at `986ccf6d5ee11427e969022f6b8b5d5f48ec16c3`;
- Exact original #337 independent D-337-01 short-pread, EOF and EIO oracle,
  existing #337 small full-SHA positive, #327 BZD-DEST-01, #267 typed-plan
  no-writer, HOST/FD, six-distribution schema, Ruff and compileall.

These results certify **test-owned, local HOST evidence only**.
They do not grant write, guest command, independent quota, Windows restore,
whole RAW 128GiB authenticity, dual boot or release authority. No real
Windows checkpoint or root-of-trust was supplied. A fresh Safety verdict
for this composition remains pending; the prior #346 APPROVED_OFFLINE_DENY_ONLY
is applicable only to its exact earlier SHA.

## 2026-11-22 — non-destructive #346 fixed + #356 QCOW2 differential

Draft #356 reconciles original child `83489eee123c124266b0c514b8f20e6e19ca9bc2` with corrected parent #346 `49389810a46d43bee407304a237b912b2faebc07` via a non-destructive two-parent merge. The `_bounded_info()` subprocess cleanup is byte-for-byte identical to the exact #346 version [independently approved for that parent only](https://github.com/LMhdez/gaslux/pull/355#issuecomment-7083769456). #356's 32-byte QCOW2 v2/v3/header capacity checks, `statvfs` checkpoint estimate, final `st_blocks` comparison, dedicated original #342 checks and synthetic regressions remain. The original [Safety-2 #355](https://github.com/LMhdez/gaslux/pull/355) oracle is pinned by immutable ref in the existing #356 workflow, and a new exact-head CI plus fresh independent Safety-2 differential assessment are required. `checkpointReserveProven=false`, `checkpointRestorationProven=false`, `FULL_BACKING_HASH_NOT_COMPLETED`, `DENY_NO_WRITER` and all writer/rollback/guest flags remain denied; no extra API, install, real Windows recovery or release promotion is introduced.

## 2026-11-22 — exact-head combined CI and independent oracle replay

Composed #356 merge commit `22d8da1df232e0216a882242d349562bbecdcd7d` has parents `83489eee123c124266b0c514b8f20e6e19ca9bc2` and corrected #346 `49389810a46d43bee407304a237b912b2faebc07`. The follow-up `a6e2f01ee061f05917eb1930dadbc1dfb099905d` changes **only** checkout fetch depth to allow the CI to verify both ancestors, not operational code. Canonical large module blob: `a1a6364b12cf9a6b988eb124e2aa66e374c32cfe`, producer tests: `3aec49b49c53d17c90684bb14431425e2b9f08fb`.

**CI verified exact code HEAD `a6e2f01ee061f05917eb1930dadbc1dfb099905d`:** [QEMU push #45057466420](https://github.com/LMhdez/gaslux/actions/runs/45057466420) SUCCESS; [QEMU PR #45057470701](https://github.com/LMhdez/gaslux/actions/runs/45057470701) SUCCESS; [dossier static #45057470700](https://github.com/LMhdez/gaslux/actions/runs/45057470700) SUCCESS. Both QEMU runs executed real stopped QEMU on private sparse file images; original #342 metadata suite (12), #337 D-337-01 digest tests, #346 original plus extra #356 QCOW2 tests, #327/#267 contracts, HOST/FD/peer, strict Ruff/compile and six distro contracts. The existing workflow checked out immutable #355 Safety oracle `f4f882565af2c8cf08b8b656122f9ef9c9dc01a2` with original test blob `c29c68a13967377c4a3ee89c13087b2ce6bad6b5`; all **15 independent oracle cases passed against imported composed blob**. Explicit real-process startup/cleanup failure refusal and foreign-session protections also passed.

**Scope:** PASS_COMPOSITION_READY_FOR_SAFETY (engineering only), not a Safety-2 verdict. `SAFETY2-346-01` remains CLOSED_OFFLINE_ONLY on #346; this new combined candidate awaits independent differential assessment of QCOW2 header v2/v3, `statvfs` estimates, final allocated-block readback and inherited subprocess semantics. Incomplete 128 GiB RAW stays `FULL_BACKING_HASH_NOT_COMPLETED`, `DENY_NO_WRITER`, `checkpointReserveProven=false`, `checkpointRestorationProven=false`; no full Windows readback, installed guest, dual boot, actual rollback or writer authorization. No integration/merge.
