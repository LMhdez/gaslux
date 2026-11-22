# CACHY-BCD-682 — independent offline root-cause boundary

**Status:** forensic diagnostics only; no installed dual boot, no BCD allowlist.
Historical run [#44900941635](https://github.com/LMhdez/gaslux/actions/runs/44900941635)
at source SHA `78fceddb85649ce63b58459c75f4668db1446feb`.
Artifact `14706886498` (expiry 2026-11-28 UTC), ZIP SHA-256
`4187fc513fa03f5d3a1e5428a9e94534b3f211546d83d4a02322722121c0ab84`
was independently downloaded and ZIP CRC checked. The artifact contains
read-only JSON forensic summaries, two QEMU traces, COM1 logs and status
files, **but no full before/after BCD hive bytes**.

## Actual historical observation, not inferred authorship

| Property | Windows-only A | Archiso/pacstrap + Windows B |
|---|---|---|
| Initial BCD SHA-256 | `7017e17de91070a7c91b1e725a7b7437bb0df74676437e11862362388d1d172f` | same |
| Initial/final BCD size | 28672 bytes | 28672 bytes |
| Changed bytes | 682 | 682 |
| Changed contiguous runs | 189 | 189 |
| Changed-offset digest | `c499a5a15454a30afceda835609464a9d8e050dde2fb3643f83f1581250cd2b2` | same |
| Final BCD SHA-256 | `ed11faf6d3f76e55b9e3db49dab7194d203f940262a28ca87ed7362f332be30d` | `be917b89b38c8cf23f9d6a7524921fd7de1f0449cfa7aaf5f6d07d2106d08ed2` |
| Protected mutation authorized | NO | NO |

The same 682 changed **offsets** do not imply the same values, hive fields,
writer, sequence or cause. The two postboot BCD hashes differ. Both are
observations *after a Windows boot*, with no guaranteed pre-kernel capture.
Original branch correctly raised `PostPacstrapWindowsError` for
`espBcdSha256`; `bcdAbComparison.classification` in the historical
artifact is `INVALID_OR_MALFORMED_BCD_AB_EVIDENCE`, not a certified causal
assessment. Neither guest trace authenticates a Windows PID, BCD FAT32
physical sector nor QEMU node→QCOW2 identity. Even if Windows-alone
reproduces the offset pattern, **do not accept or whitelist 682 bytes**.

## Timeline supported by source code, not wall-clock attestation

* Pre-fourth Windows boot: verified QEMU/COW and protected GPT/BCD/ESP/WinRE
  baseline; fifth root is a proposed free-space operation.
* After fourth Windows boot, pre-treatment: `prepare_matched_checkpoint_clones()`
  copies treatment QCOW2 and OVMF VARS; initial BCD hashes, protected hashes,
  guest-visible GPT and fresh independently cloned TPM state are compared.
* Control A: Windows-only fifth boot; postboot BCD read-only via libguestfs.
* Treatment B: fifth partition/root and pacstrap path with signed handoff
  and installed-root proofs, then fifth Windows boot via
  `verify_windows_post_ext4()`; subsequent read-only BCD capture.
* During post-treatment inspection: `verify_windows_with_installed_root()`
  compares Windows protected hashes and refuses the BCD mismatch even when
  GPT and Linux root are preserved. The signed plan and guest serial logs
  are not process/write-sector attestation.

These are **ordered workflow stages**, not independently measured and
authenticated timestamps. Serial and QEMU trace timestamps are not
cross-clock-calibrated proof of write chronology or process authorship.

## Source trust and test coverage

Tests import unchanged real `summarize_bcd_difference()` (from #263)
and `validate_bcd_forensic()` / `compare_bcd_ab()` (from #314), pinned
to `7d55bd4a81007dc60df7c2252bb11ca623a2a423`. Synthetic
`regf`-prefixed bytes verify valid positive diagnostics, binary difference
without writer claims, invalid initial A/B bytes, false digest, mutation
authorization and truncated summaries. A **separate test-only** context gate
rejects mismatched transaction/checkpoint/initial BCD/OVMF/TPM/capture phase/
boot ordinal/shared clone identity/missing writer. That gate is NOT an
integrated authenticator, does NOT verify genuine signatures, and its success
is only `STRUCTURAL_AB_ONLY_NOT_CAUSAL`. It is not a production implementation,
and tests must not claim operational writer attribution.

## Minimum operational A/B proof for Integrator 3

1. Get explicit human authorization for two disposable matched Windows
   10 runs with independent QCOW2, OVMF VARS and TPM snapshots and tested
   restoration of each checkpoint; do not run here.
2. Authenticate **same starting bytes** by independent read-only BCD hive
   snapshots, primary+backup GPT and FAT32 cluster map, Windows ESP/Boot
   Manager/BCD, WinRE, BCD baseline and precise disk backing and ownership.
3. Bind each QEMU process, backend FD, guest GPT/partition IDs and exact
   disk sector geometry to its own signed transaction; no QMP self-claims.
4. Instrument Windows boot, file and disk writes with complete ETW provenance
   and explicit clock, missing-buffer, pre-kernel and FileObject/IRP reuse
   limitations; do not infer unknown writers.
5. Compare **full private** before/after BCD hives offline by authenticated
   byte snapshots, validate known registry hive structure, FAT cluster map
   and matching physical sector writes. Publish only hashes/offset summaries,
   never private BCD content.
6. A result with changed protected BCD stays DENY regardless of symmetry
   or a plausible Windows origin. Any relaxation needs a separately reviewed
   Windows recovery and integrity policy, not an automatic allowlist.
7. Verify both Windows boot and Linux boot, updates, in-place rollback,
   BCD/WinRE/EFI restoration and NVRAM state independently before claiming
   Issue #3 closure. Logs/markers and discarding a child QCOW2 alone are
   insufficient.

## Permanent restrictions

`approvedMutation=false`; `productionStorageWritesAuthorized=false`;
`sameDiskDualBootVerified=false`; `rollbackProven=false`;
`releaseEligible=false`; `stable=false`.
