# GASLUX-Q4OS — ISO signed provenance (Q4OS-ISO-SIGNED-PROVENANCE-01)

**22 November 2026 — UNSIGNED / EXPERIMENTAL / DENY-ONLY.**
Stacked parent: [PR #345](https://github.com/LMhdez/gaslux/pull/345).
Neither independent Safety review on #338 nor a signed ISO provenance
chain has been verified. The previous #318 `CHANGES_REQUIRED` does not
become approval merely because the latest offline CI passes.

## Official source and cryptographic trust

- The [Q4OS downloads page](https://q4os.org/downloads1.html) lists
  Plasma native Live media separately from WinSetup.exe; the latter
  is not a native dual-boot installation backend.
- The [official SourceForge stable folder](https://sourceforge.net/projects/q4os/files/stable/)
  lists ISO files and `md5sum.txt`. The [exact release page](https://sourceforge.net/projects/q4os/files/stable/q4os-6.10-x64.r2.iso/download)
  publishes SHA-256
  `1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d`.
- **No ISO-specific detached signature, trustworthy signing-key
  fingerprint, or independent publisher signing chain was located**
  in the checked official listings. This is **NOT_VERIFIED**, not
  a proof that none could exist elsewhere. Signing keys for the
  Q4OS APT repository do **not** validate native ISO releases.
- The historical Gaslux signed catalogue signs other artifacts,
  not this Q4OS 6.10 r2 ISO. Never generate a fake release key or
  sign the proposed experimental candidate with an unauthorized key.

## Current full-byte inspection, 22 November 2026

[Action #45036542249](https://github.com/LMhdez/gaslux/actions/runs/45036542249)
completed **SUCCESS** at SHA
`fee6674f504cc7e994161be52f940b36d9566d28`. On a disposable
runner, the **actual** official Q4OS 6.10 r2 x86_64 native ISO was
downloaded into a private mode-0700 folder, mode-0600 file; full
SHA-256 was independently checked, and the filesystem was inspected
without executing code from the ISO.

| Actual observation | Result |
| --- | --- |
| ISO | `q4os-6.10-x64.r2.iso` |
| **Measured exact size** | **1 851 392 000 bytes** |
| Measured complete SHA-256 | `1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d` |
| SourceForge public checksum | MATCH |
| ISO9660 / El Torito | PASS |
| Live SquashFS | PASS |
| Debian OS identity | `ID=debian`, `VERSION_ID=13` |
| Native Q4OS release marker | `6.10-deb13uN` pattern verified |
| Kernel and initramfs | Present under `/live`, names stored in evidence |
| Native installer | **Calamares**, settings sequence present |
| Calamares `installEFIFallback` | **true** (potential Windows ESP hazard) |
| Independent publisher signing key and signature | **NOT VERIFIED** |
| Signed Gaslux ISO catalogue entry | **NOT AVAILABLE** |
| QEMU boot / Guest / installation | **NOT EXECUTED** |

The actual measurement differs from historical evidence:
[ISO bytes #43936058057](https://github.com/LMhdez/gaslux/actions/runs/43936058057)
and [Calamares config #43964771409](https://github.com/LMhdez/gaslux/actions/runs/43964771409)
both dated 16 Nov 2026. They are useful comparison, not a substitute
for fresh byte measurements or a publisher signature.

## Code and independent readback

[`auto_tests/tools/q4os_official_iso_provenance.py`](../auto_tests/tools/q4os_official_iso_provenance.py)
uses the existing pinned read-only descriptor SHA-256 contract:
`O_NOFOLLOW`, directory FD, private ownership, regular file with
one link, stable `fstat` identity, exact byte hashing with `pread`.
It checks the same public hash before and after mounted ISO inspection.
Read-only `xorriso` reports ISO9660/El Torito; `unsquashfs -cat` reads
small literal fields from the live filesystem, using a duplicate-key
rejecting SafeLoader for Calamares YAML.

The ISO mount uses `ro,nosuid,nodev,noexec` on a private runner.
No QEMU, Windows, Calamares, guest input, physical disk or partition
operation is executed. The external ISO reader reopens the private
pathname after hashing; this is **not** a future QEMU FD binding.
Only a later independent authenticated FD/guest test can prove that.

Negative tests import the actual Python module. They reject
wrong release/OS identity, missing kernel/initramfs/Calamares sequence,
invalid and duplicate YAML, unauthorized SquashFS member paths,
false signing signals and altered media. Existing readiness tests
also cover hash/size mismatch, symbolic/hard links, replaced path,
in-place mutation, invalid and writable file descriptors.

## Experimental catalogue-compatible candidate

[`auto_tests/fixtures/q4os_6_10_r2_unsigned_catalog_candidate.json`](../auto_tests/fixtures/q4os_6_10_r2_unsigned_catalog_candidate.json)
pins `isoInstallerSizeBytes=1851392000` and the exact public SHA-256
with the same media field names as Gaslux `release-config.json`.
It is deliberately marked `UNSIGNED_EXPERIMENTAL_CATALOG_CANDIDATE`,
`candidateOnly=true`, `signed=false`, `stable=false` and
`productionEligible=false`. Unknown publisher key, signing chain,
signature and still-unverified boot/firmware combinations are
explicitly absent or denied. No stable-catalog change was made.

The actual CI readback emits
`candidateCatalogFieldsUnsigned`, validated by
[`schemas/gaslux-q4os-iso-provenance-evidence.schema.json`](../schemas/gaslux-q4os-iso-provenance-evidence.schema.json).
A schema is **not** an authenticating signature, and matching hashes
are **not** publisher signing proof.

## Blockers to live boot and release

1. Independently trusted publisher release signature/key, or a
   maintainer-approved and audited alternative origin policy.
2. Independently verified Safety reviews for #318, #338, #345
   and the exact differential of this task.
3. Authenticated same-VM bind of ISO → inherited QEMU FD → owned
   QCOW2 and firmware → kernel/userspace → Guest-origin witness.
   Reuse HOST/FD and Guest Peer from `dev`; never clone or bypass.
4. Before **any** installer action, review Calamares
   `installEFIFallback: true` and Windows ESP ownership.
5. Windows dual-boot, kernel/bootloader update and rollback remain
   entirely unverified.

**Gates unchanged:** `QEMU_FD_BACKING_VERIFIED=false`,
`productionStorageWritesAuthorized=false`,
`q4osNativeInstallationVerified=false`,
`sameDiskDualBootVerified=false`,
`windowsInPlaceRollbackProven=false`,
`releaseEligible=false`, `stable=false`.

**No merge or installation authorization.**
Generated-by: GPT-6; GPL-3.0; independent Safety review required.
