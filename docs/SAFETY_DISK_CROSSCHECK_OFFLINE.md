# Safety disk identity crosscheck — offline boundary (draft)

This note documents the **experimental** three-record comparator introduced by
[PR #287](https://github.com/LMhdez/gaslux/pull/287). This correction is stacked
on the verified #287 HEAD `d7f72b42ef73a788ff1e9b192c732a989c575872`.
Neither the comparator nor this note is installation authorization.

## Four distinct trust stages

| Stage | What is demonstrated | What is NOT demonstrated |
| --- | --- | --- |
| Syntactic validity | Exact expected JSON keys, positive and aligned extents, non-overlapping GPT partition list, digest *format* | Real GPT header/array CRC, file content correctness or origin |
| Offline comparison | Byte-equivalent normalized records labelled `windows`, `host` and `guest` at one supposed checkpoint | Independent collection, freshness, target-device binding or authentic source labels |
| Authenticated provenance | **NOT IMPLEMENTED** here | Signed trustworthy plan, trusted OS/host probe, key provisioning, challenge and anti-replay |
| Write authorization | **DENIED** | Any permission to shrink, repartition, install, update boot files or perform rollback |

A `True` return means only offline consistency. An attacker can provide three
identical forged records (including three matching forged `transactionId`
values) or replay one record as another source and receive `True`. The tests
**intentionally demonstrate these limitations**, not successful authentication.
The comparator is not wired to the installation state machine or any writer.

## FD / pathname boundary

`compare_files()` pins parent directories and the final regular-file
descriptor with POSIX `O_NOFOLLOW`, `O_DIRECTORY`, `O_NONBLOCK`,
`O_CLOEXEC` and `O_RDONLY`. It checks `lstat`-equivalent
`os.stat(..., follow_symlinks=False)` before open, then compares the inode,
device, mode, link count, size, mtime and ctime via `fstat` and fresh directory
entry checks. All three file descriptors remain open during comparison.
The reader uses `os.pread` on those same descriptors, rejects files larger
than 8 MiB, parses strict UTF-8 JSON with no duplicate keys, and rereads all
bytes through the pinned descriptors before returning.

The reader rejects terminal and directory symlinks, hardlinks, FIFOs,
non-regular entries, detectable replacement, truncation, malformed JSON and
metadata changes during observation. On systems without these POSIX APIs,
it **fails closed**. All read-only flags apply to the evidence files, not to
the data-disk image or a Windows volume.

These checks do NOT prevent privileged changes, malicious same-inode rewrites,
ABA changes between checks, changes immediately after return, shared backing
stores, or forged file metadata. External immutable checkpoint enforcement
and independent trustworthy provenance remain prerequisites. No claim is made
that equal JSON proves an unchanged physical disk.

## GPT-only experimental gate

This comparator rejects `partitionStyle="MBR"` because it does not model
primary/extended/logical entries, EBR chains, active partition, MBR/PBR boot
code, disk signature or LBA limits. This gate applies **only to this experimental
offline comparator**. It does not change BIOS/MBR support in the working Mint
or Zorin production firmware adapters, and does not change any schema.

The comparator also does not itself recalculate GPT primary/backup CRCs.
Do not duplicate the canonical GPT parser:
[PR #265](https://github.com/LMhdez/gaslux/pull/265) implements it;
[PR #286](https://github.com/LMhdez/gaslux/pull/286) binds the parser to a
caller-pinned read-only image FD. Integration must use that established parser,
not trust a `partitionTableSha256` claimed by the JSON.

## Future authenticated handoff (not implemented)

Before any writer could use independently attested evidence, an integrator
would have to bind **outside the self-reported JSON**:

- Authenticated signed installation plan digest and exact `transactionId`,
  approved firmware/layout, affected disk identities, extent allowlist and
  ownership of permitted artifacts.
- Host VM identity, selected QEMU disk attachment and stable backing-chain
  identity, trusted image FD, logical/physical sectors and size.
- Genuine Windows and Linux independent collectors, collector code identity,
  authenticated source role, host/guest mapping, and exact disk
  `partitionTableId`, PARTUUIDs, types, offsets and lengths.
- Single-use fresh challenge, monotonic checkpoint/ledger state, image
  immutability/fencing, replay protection and key custody.
- Verified Windows BCD, WinRE, ESP/boot files, NVRAM, BitLocker state, and
  first-boot and rollback proof before any stability declaration.

[PR #267](https://github.com/LMhdez/gaslux/pull/267) separately explores
authenticated transaction association with an **ACCEPT_NO_WRITER** outcome.
That work remains experimental and is **not imported or duplicated here**.
The existing shared plan, state machine, and compensating rollback stay
authoritative. Human review and integration acceptance are required.

## Reproduction and CI

The original #287 implementation checks `Path.is_symlink()` /
`Path.is_file()`, then reopens with `Path.read_text()`. A deterministic
test replaces `guest.json` with a symlink at that exact boundary: the old
implementation returns `True`. The corrected FD implementation rejects
it. Tests also cover substitution between `stat` and `open`, in-place
changes, path replacement during read, invalid JSON, missing inventory,
source exchange/replay, forged identical inputs and MBR refusal.

Commands executed by the dedicated non-destructive workflow:

```bash
python -m compileall -q auto_tests/tools/disk_identity_crosscheck.py auto_tests/test_disk_identity_crosscheck.py auto_tests/test_disk_identity_crosscheck_hardening.py
python -m ruff check --config auto_tests/pyproject.toml auto_tests/tools/disk_identity_crosscheck.py auto_tests/test_disk_identity_crosscheck.py auto_tests/test_disk_identity_crosscheck_hardening.py
python -m unittest auto_tests.test_disk_identity_crosscheck -v
python -m unittest auto_tests.test_disk_identity_crosscheck_hardening -v
```

All tests create temporary, disposable JSON files; there are **no QEMU
guests, live disk probes, boot mutations, physical disk writes or demonstrated
Windows recovery operations**.
