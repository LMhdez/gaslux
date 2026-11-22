# AUTH-DEST-128G-READONLY-01 — 128 GiB sparse geometry, not full integrity

**2026-11-22.** This stacked branch depends on [Draft PR #337](https://github.com/LMhdez/gaslux/pull/337)
at `7e0d1a27aa16f012fae41e2979fc9791066a7ee7`. It does not alter
the parent branch. The new lane is read-only and fail-closed, never a writer,
installer, Windows recovery, guest provenance, or release gate.

## Precise interpretation

`assess_sparse_128g_readonly` in
`auto_tests/installer_observer/large_sparse_destination.py` can inspect
a **128 GiB virtual/apparent RAW backing**, whose allocated physical blocks
may be a few KiB/MiB, plus a small QCOW2 overlay and a bounded checkpoint
receipt. It consumes the existing `QemuLocalDiskWitness`, ProcessSeal,
QMP/procfd observations, `inspect_gpt_fd`, and the pinned #267
`decide_no_writer`. Neither QEMU's internal backend pointer nor the guest
is independently attested. The raw backing's GPT may be unrelated to actual
guest-effective QCOW2 overlay content; the **historical 128 GiB Windows
checkpoint is not itself measured or authenticated by this synthetic test**.

On successful structural observation, the function deliberately **raises**
`LargeDestinationRefused("FULL_BACKING_HASH_NOT_COMPLETED")` and attaches
a bounded `observed` diagnostic with
`status=STRUCTURE_OBSERVED_FULL_HASH_DENIED`,
`authorization=DENY_NO_WRITER`,
`rawBackingFullSha256Verified=false`,
`fullRawContentBytesAuthenticated=0`, and all writer/guest/rollback/stability
flags `false`. A locally sampled SHA-256 (first + last 32 KiB of RAW)
has the explicit name `locallyMeasuredRawSampleSha256`, and **never**
represents a whole-file digest or independent authentication. The QCOW2
overlay, capped at 64 MiB apparent, *is* hashed completely against a
caller-provided SHA; checkpoint JSON is also fully read and checked against
a caller-provided SHA. The hashes' external provenance remains CLAIMED.

The existing #337 smaller-image positive test continues to exercise actual
complete SHA-256 checking of its QCOW2, backing RAW and receipt; the large
geometry denial does **not** replace that positive fixture.

## Resource limits — all maximums, never minimum trust proof

| Scope | Limit | Failure semantics |
| --- | --- | --- |
| RAW backing apparent length / virtual capacity | exactly 128 GiB for this test, maximum 128 GiB | fail before GPT |
| QCOW2 overlay apparent length | maximum 64 MiB | fail before SHA |
| QCOW2 allocated blocks (`st_blocks * 512`) | maximum 32 MiB | deny |
| RAW backing allocated blocks | maximum 32 MiB | deny |
| Total allocated blocks (overlay + RAW + receipt) | maximum 64 MiB | deny |
| Checkpoint JSON apparent length | maximum 64 KiB | deny before parse |
| `qemu-img info` stdout | maximum 64 KiB | terminate subprocess, deny |
| QEMU metadata inspection | bounded by caller budget, default 15 s, max 30 s | terminate subprocess or deny at next deadline |
| Working-memory raw samples | 2 × 32 KiB | no RAW full read |
| Whole RAW SHA-256 | **not performed** on 128 GiB | explicit `FULL_BACKING_HASH_NOT_COMPLETED` refusal |
| Quota | explicit positive caller claim and `statvfs` free-space observation | unknown quota => `QUOTA_UNKNOWN`, never acceptance |

The quota value is *not* independently attested. `statvfs` free space
is **not** proof that container/runner storage quotas are enforced, or that
an external 128 GiB Windows image is recoverable. Only disposable private
files, no block devices. Full-path aliases, foreign FDs, writable FDs,
`O_PATH`, non-owned files and inconsistent device/inode/size/ctime/mtime
are refused. The original #325 QEMU observer retains its conservative
512 MiB host **QCOW2 file** cap, appropriate here because the small overlay
and 128 GiB **virtual capacity** are distinct quantities.

The subprocess has an output-size cap and a hard user-space timeout/kill.
The whole assessment has elapsed-time checks between bounded operations;
a kernel filesystem read that itself never returns is not forcibly
interrupted by this Python-only observer. The GitHub Action has an additional
30-minute job timeout. No claim of a hard deadline for all possible OS I/O.

## Independent Safety D-337-01 and other known gaps

[Independent Safety finding D-337-01](https://github.com/LMhdez/gaslux/pull/337#issuecomment-7080704589)
proved that `_digest()` in parent #337 skipped positive short `pread()`
without refusing; a hash over missing bytes could match the caller's
misleading expected hash. This dependent branch changes only its own copy
of the inherited module to require **exact requested byte counts**, an
exact accumulated byte total, stable FD identity, and full-checkpoint
read length. It adds direct positive and short-read/EIO regressions.
**The #337 HEAD and its pending Safety audit are unchanged.**

The following remain unresolved by the 128 GiB experiment:
external ISO/OCI plan signatures; any QEMU internal backend→FD proof;
true QCOW2 guest-effective GPT, ESP/BCD/WinRE, independent guest collector
origin and replay prevention; independent checkpoint trust; Windows restore
and dual boot; hardware behavior; same-UID attacker ABA/TOCTOU across the
test-owned workspace. The observed checkpoint is a synthetic JSON receipt
with `restoreProven=false`, never a restored Windows disk.

## Disposable test evidence

`auto_tests/tests/test_auth_dest_128g_readonly.py` creates the sparse RAW
with `ftruncate(128 * 2**30)` and GPT entries using `sgdisk`. It creates
a small QCOW2 backing overlay via `qemu-img create`, starts QEMU with
`-S` (guest CPU never executes), and measures the regular-file FDs.
Foreign RAW image fixtures are created using sparse `ftruncate` and
64 KiB of GPT edge copy, **not** `shutil.copyfile` over 128 GiB.

Negative cases include quota missing, allocated-block limit, qemu-img
metadata output limit, timeout, short reads, hash mismatch, backing alias,
path replacement, GPT mismatch, unrelated transaction/checkpoint, guest
spoofing, concurrent backing mutation, positive short `pread` over a
small complete SHA and injected EIO. All large-image cases must fail
closed. Workflow:
`.github/workflows/auth-dest-128g-readonly.yml`, restricted to isolated
GitHub-hosted Linux with immutable #267/#286/#327 dependencies and inherited
#337/QEMU regressions. Its target PR is **stacked onto #337**, not `dev`,
and is not eligible for integration until Safety has cleared all dependent
changes and CI on the exact HEAD. No physical disks, Windows or guest OS.

**Verified base implementation CI:** [Actions #45034846402](https://github.com/LMhdez/gaslux/actions/runs/45034846402)
completed **SUCCESS** on commit `6a94093271610dbd2ff908c2b8692e332e1585a1`:
real stopped QEMU with a synthetic sparse 128 GiB backing, all newly
parametrized deny-only resource and identity tests, complete small-image
#337 regression suite, pinned original #327/#267 tests, HOST/FD, Ruff,
compileall, and six-backend capability schema contracts. The CI proves
local lab observation only, not a 128 GiB *Windows* image, complete 128 GiB
content hash, guest provenance, Windows rollback or installation.


## 2026-11-22 — upstream Safety D-337-01 reconciled without modifying #337

At reconciliation time, #337 had advanced to
`f1e082c37ab58887f942b1e9ab0a841cb4b2b02a` with independent real-code D-337-01
fix/tests and the existing 64-KiB checkpoint cap. This branch now merges
that parent commit **without changing the parent ref**. The upstream
`_digest` complete-byte accounting and Safety test files have priority.
The separate 128-GiB structural observer remains additive; its own test
also expects the upstream `FD_READ_FAILED` diagnostic on injected EIO.
A one-line checkpoint receipt length guard remains unique to this branch.
Do not claim these inherited upstream Safety fixes are new independent
work in this scalability PR. #342 remains a separate metadata-only draft.


## 2026-11-22 — SAFETY2-346-01 subprocess cleanup (correction under review)

Independent [Safety-2 #355](https://github.com/LMhdez/gaslux/pull/355)
reproduced **RED** against the immutable #346 source
`9306d0fff8cc89794b83fe002ae133c110e641ae`.
[Actions #45037813419](https://github.com/LMhdez/gaslux/actions/runs/45037813419)
returned SUCCESS **because it explicitly expected the failing oracle**:
`SAFETY2-346-01 RED: descendant is still alive after _bounded_info() refused the timed-out pipe`.
No prior process cleanup was proven.

#346 now has a bounded POSIX process-session correction: implementation commit
[`4ab0f13b`](https://github.com/LMhdez/gaslux/commit/4ab0f13b718fabf4d8cb5598626ae3df67eafce1),
real subprocess regression addition
[`431599b0`](https://github.com/LMhdez/gaslux/commit/431599b0b5e6f04f9b7617c028bfb1091771cef7)
and follow-up test lint correction
[`00f93376`](https://github.com/LMhdez/gaslux/commit/00f93376210c3bce8ab01e3ceb237a70cb0a78b8).
The `qemu-img` diagnostic starts with `start_new_session=True`; `waitid(WNOWAIT)`
observes exit without reaping the session leader before `killpg`.
Cleanup terminates only the verified owned group, then reaps the direct child and
checks group disappearance within a finite cleanup window. Unexpected session,
signal, wait or cleanup-timeout errors produce `QEMU_INFO_CLEANUP_FAILED`;
original output, JSON and read-only refusals remain intact.
The correction does **not** authorize any guest or disk writer.

**Independent oracle compatibility finding:** the original #355
`_fake_popen` launcher does not forward `start_new_session` (or other
process-session kwargs) to its real Python subprocess. A GREEN replay
therefore requires Safety-2 to preserve the same adversarial assertion but
forward the process-session argument and pin the corrected checkout.
Producer regression tests forward all Popen kwargs and use real disposable
children. Until #355 independently verifies the fixed exact HEAD, the
finding remains **OPEN / correction not approved**. #356 remains stacked
on its original #346 ancestor and is not integrated.


### 2026-11-22 — producer CI GREEN (not independent Safety clearance)

The producer candidate at `6c2af28acd7da24ce127de0909c66e15147ff873`
has both [push Actions #45054177113](https://github.com/LMhdez/gaslux/actions/runs/45054177113)
and [PR Actions #45054181689](https://github.com/LMhdez/gaslux/actions/runs/45054181689)
**SUCCESS** on the same exact SHA. The existing workflow ran strict Ruff,
Python compilation, six-backend contracts, real stopped-QEMU sparse-128GiB
adversarial cases (including the new orphan and foreign-session subprocess
tests), inherited small complete-FD readback, #327/#267 no-writer and
Observer HOST/FD regressions, and final checkout integrity. This GREEN is
**producer-side**, not the unchanged independent #355 oracle. The original
#355 adapter omits `start_new_session` forwarding; independent Safety-2
review was requested in
[comment #7083477427](https://github.com/LMhdez/gaslux/pull/355#issuecomment-7083477427).
The finding remains OPEN pending independent corrected-oracle replay.

## 2026-11-22 — #356 composition after Safety-2 cleanup closure

The [independent Safety-2 verdict](https://github.com/LMhdez/gaslux/pull/355#issuecomment-7083769456) closed **only** `SAFETY2-346-01` in #346 at `49389810a46d43bee407304a237b912b2faebc07`. Draft #356 now composes that corrected subprocess function through a non-destructive two-parent merge with the earlier #356 branch (`83489eee123c124266b0c514b8f20e6e19ca9bc2`). The function retains separate POSIX session, `waitid(WNOWAIT)`, owned group SIGKILL before leader reaping, bounded disappearance and `QEMU_INFO_CLEANUP_FAILED`. The independent oracle is unchanged and replayed using an immutable #355 checkout. The #356-specific QCOW2 header/geometry, estimated free-space checkpoint capacity `checkpointReserveProven=false` and final allocated-block recheck remain. The new composed SHA needs independent *differential* Safety review and exact-head CI; parent approval is not transitively granted. `FULL_BACKING_HASH_NOT_COMPLETED`, `DENY_NO_WRITER`, and `checkpointRestorationProven=false` remain mandatory. No guest, actual Windows rollback, full RAW hash or writer authorization.
