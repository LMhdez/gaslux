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

## 2026-11-22 — independent SAFETY2-346-01 subprocess cleanup verdict (PR #355)

Original producer [#346](https://github.com/LMhdez/gaslux/pull/346) at `9306d0fff8cc89794b83fe002ae133c110e641ae` (module Git blob `5eac9642d942e7ecdff2ea14adb654da57dfca6e`) leaks a real orphan descendant retaining stdout after the bounded information reader times out. Historical [expected-RED #45037813419](https://github.com/LMhdez/gaslux/actions/runs/45037813419) and the unchanged adversarial failure message are retained.

The corrected producer at **`49389810a46d43bee407304a237b912b2faebc07`**, module blob **`61e7c7abc7de14cc6b449eea1a6e02b92e19ef3a`**, isolates `qemu-img` using `start_new_session=True`, observes the unreaped leader with `waitid(WNOWAIT)`, signals only its verified owned process group before reaping the leader, and refuses failed cleanup as `QEMU_INFO_CLEANUP_FAILED`. The **independent** [#355](https://github.com/LMhdez/gaslux/pull/355) changes only the real `Popen` adapter to forward `start_new_session`, not the oracle's descendant/PID assertion or producer implementation. Its test blob is `c29c68a13967377c4a3ee89c13087b2ce6bad6b5`.

**Independent [Actions #45055861221](https://github.com/LMhdez/gaslux/actions/runs/45055861221) SUCCESS**: two immutable producer checkouts; exact Git blobs and imported module paths checked at RED and GREEN; same test produces the explicit expected RED on the old SHA and GREEN on the corrected SHA; 31 inherited producer tests and 15 Safety-2 tests passed in separate pytest processes; real-process start/cleanup failure injections refused; original source files were not modified. Earlier workflow retries [#45055475885](https://github.com/LMhdez/gaslux/actions/runs/45055475885), [#45055652334](https://github.com/LMhdez/gaslux/actions/runs/45055652334), [#45055764708](https://github.com/LMhdez/gaslux/actions/runs/45055764708) failed due to test-harness summary/collection issues, not a successful producer cleanup proof; they remain historically visible.

**Safety-2 verdict: SAFETY_APPROVED_OFFLINE_DENY_ONLY for SAFETY2-346-01 only**, producer exact SHA `49389810a46d43bee407304a237b912b2faebc07`. The local 128 GiB RAW remains incompletely authenticated; expected diagnostic is still `FULL_BACKING_HASH_NOT_COMPLETED` with `DENY_NO_WRITER` and `productionStorageWritesAuthorized=false`. No Windows/Linux guest installation, actual Windows recovery, guest trust, whole-backing hash, writer, merge, `main` promotion or #356 clearance follows from this verdict.
