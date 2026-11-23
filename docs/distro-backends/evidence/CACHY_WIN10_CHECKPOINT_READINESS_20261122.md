# CachyOS Windows 10 — checkpoint A/B readiness (2026-11-22)

**State:** `CHECKPOINT_SOURCE_UNAVAILABLE` / `DENY_ONLY`. This is a dated,
read-only engineering qualification for [PR #263](https://github.com/LMhdez/gaslux/pull/263),
not permission to reboot Windows, run Archiso/pacstrap or write BCD/ESP.

## Authoritative historical sources checked

- [Actions run #44900941635](https://github.com/LMhdez/gaslux/actions/runs/44900941635):
  the sole retained artifact #14706886498,
  `cachyos-win10-shared-root-pacstrap-cow-evidence`, is **254,828 ZIP bytes**,
  `sha256:4187fc513fa03f5d3a1e5428a9e94534b3f211546d83d4a02322722121c0ab84`.
  It contains bounded forensic evidence **not the original QCOW2, complete
  BCD/FAT32 hive, OVMF VARS or source TPM tree**. A correct artifact digest
  does **not** make the ZIP a restorable Windows checkpoint.
- In the currently accessible engineering workspace, no Windows 10 QCOW2,
  immutable backing image, matched checkpoint, original OVMF CODE/VARS and
  TPM/swtpm source were found as a complete verified group. Previous runner
  `/home/runner/work/_temp` data is ephemeral and is not supplied by Actions
  artifacts. Do not reconstruct missing source from mock GPT/NTFS fixtures.
- [Safety #335](https://github.com/LMhdez/gaslux/pull/335), HEAD
  `71f11c94f73e671296c4f8661e4c1bb42d17d67c`, observed **682 BCD bytes**
  changed at identical offset sets in A and B, but **different final hashes**.
  No independent authentic process/writer attribution or in-place restore is
  proven. [Issue #3](https://github.com/LMhdez/gaslux/issues/3) is still open.

## Existing A/B mechanisms reused, not reimplemented

`windows_cachyos_bcd_ab_control.py` already has private same-checkpoint
QCOW2 and OVMF duplication, exact clone SHA-256, distinct regular-file
inodes, QEMU guest-visible equality and backing metadata, initial protected
Windows files/GPT/BCD equality, independent TPM copies and guarded host
processes. `preflight_ab_clone_capacity` measures `statvfs.f_bavail`
rather than virtual or sparse size; it proves *a minimum file-copy headroom*
but **does not** prove external quota, guest overlay expansion or complete
forensic retention. The original checkpoint module reports
`snapshotIndependentlyRestorable=false`.

## Additional deny-only contract in #263

`auto_tests/tools/windows_cachyos_checkpoint_readiness.py` is entirely
read-only and imported only by offline contract tests. It uses private local
regular files and SHA-256 measured through stable, `O_NOFOLLOW` read FDs;
compares **caller-claimed** transaction and manifest; rejects FD aliases
and a known active FD in its *own* process; reuses the existing A/B capacity
function, adds minimum 16 GiB guest overlay-growth and 2 GiB private
forensic-retention reserves, checks claimed external quota, TPM tree
independence and claimed initial BCD hash equality. Its final outcome is
**always** `RESTORE_NOT_PROVEN` even if every synthetic claim matches.
No authentic image, QEMU command, Windows COM1 guest, controller, disk writer
or BCD reader is launched. A local hash is *not* external provenance.
No new Python or JSON field grants `productionStorageWritesAuthorized`.

| Negative gate | Structural diagnostic (not an external attestation) |
|---|---|
| A | `CHECKPOINT_NOT_FOUND` |
| B | `SOURCE_HASH_MISMATCH` |
| C | `SOURCE_STILL_IN_USE` (known process FD; absence elsewhere unproven) |
| D | `INSUFFICIENT_CAPACITY` including growth/retention |
| E | `UNKNOWN_QUOTA` (a caller's numeric quota is **not verified**) |
| F | `SHARED_OVMF_VARS` |
| G | `SHARED_TPM_STATE` |
| H | `FOREIGN_TRANSACTION` |
| I | `BACKING_IDENTITY_MISMATCH` (caller SHA comparison; real chain per #337) |
| J | `RESTORE_NOT_PROVEN` |

The negative tests exercise **synthetic owned files only**. In-use detection
from `/proc/self/fd` is not an exhaustive host process audit. Immutable
process-to-QCOW2/backend attribution and canonical GPT-by-FD remain owned
by [#337](https://github.com/LMhdez/gaslux/pull/337); do not infer a real
restoration or a guest identity from this new read-only contract.

## Minimum evidence for a future independently approved A/B run

Before *any* new real Windows/QEMU boot, a Safety-approved workflow must
produce and privately bind to a transaction and exact code/manifest SHA:

1. **Source:** legitimate Windows 10 installation media/version, a reusable
   owned QCOW2 plus immutable backing and private original checkpoint; full
   `qemu-img info --backing-chain`, actual file `fstat`, GPT geometry,
   ESP/BCD/WinRE hashes, disk/transaction identity and checkpoint SHA.
2. **Recoverability:** immutable baseline and separately materialized
   recovery clone, plus actual read-back of original/restored sectors and
   OVMF/TPM state under a verified transaction; **Windows reboot and Windows
   recovery need their own independent guest-boot evidence**. Hash equality
   of mocked files does not prove boot or WinRE recovery.
3. **Resource headroom:** bytes genuinely available to the runner and any
   external project/user quota; apparent copy bytes, real allocated blocks,
   planned peak simultaneous overlays, TPM and firmware clones, trace/logs,
   bounded private BCD/ESP captures and retained forensics. Reject unknown
   quotas, exhausted reservations or unproved restore capacity.
4. **Isolation:** independent owned A/B writable overlays, OVMF VARS,
   private TPM state directories and socket/log destinations; no live QEMU
   process uses the source; separate namespaces/transaction output paths;
   immutable source rehash before/after. A negative local /proc scan alone
   does not prove absence of a process in another namespace.
5. **Causality:** confidential *complete* BCD/ESP FAT32 captures including
   cluster and byte-offset maps, SHA-256 before/after each boot, GPT primary
   and backup and WinRE read-backs, NVRAM/OVMF/TPM deltas, independently
   timestamped QEMU block graph/ETW when available, executable/FD/PID
   identity from the Observer lane and verified guest boot observations.
   Never publish raw BCD, proprietary Windows files or secrets.

**No P4/P5/P6 claim.** Safety must first adjudicate the 682-byte BCD
mismatch; #337 separately validates read-only destination identity.
The **real KVM job remains explicitly `false &&` blocked** in #263.
The existence of a successful offline CI result does not reopen that gate.
