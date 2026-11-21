# GASLUX-ZORIN: descriptor / pathname TOCTOU audit (synthetic only)

## Reproduced defect BEFORE the mitigation

Dependent stack: Zorin PR #277 (HEAD 7ea97f2c2d4a7f9546ad00ad40719ebc3c498470),
based on #264. Unmodified Safety #265 reader:
8ed912c6934c33354b0a814201c7217043bd0197.

In auto_tests/tools/zorin_synthetic_writeset.py, verify_private_synthetic()
opened and authenticated baseline.raw, trial.raw and checkpoint.raw by
owned_fd(), then called read_gpt(root, name, policy). That function used
inspect_gpt_image(root / name), which OPENED THE PATH A SECOND TIME. Byte
comparison, hash and final fstat checks used the original FDs. Therefore
GPT data and compared bytes could refer to distinct inodes.

The BEFORE-fix reproduction in GitHub Actions #44907293085, on commit
ce52f44a48d0397dc3caeffae0f311c5babbba28, passed 11 deterministic
tests, including deliberately asserting unsafe synthetic classifications.
It demonstrated successful SYNTHETIC_NO_CHANGE returns when a same-size,
valid-GPT, same-GUID regular file replaced baseline.raw or trial.raw
before the Safety GPT path open, including exactly at os.open. Swapping
checkpoint.raw AFTER owned_fd and swapping trial.raw between GPT and byte
comparison were also accepted, because original pinned FDs still held the
old content. A same-GPT hardlink was accepted on the reopened path.
A synthetic ESP directory replacement between scandir and open could
also produce a matching digest despite a changed directory inode.

Correct refusals BEFORE fixing were observed for a changed GPT PARTUUID,
a final symlink substitution rejected by Safety O_NOFOLLOW, and a changed
EFI leaf between entry.stat and os.open. This matters: not all races were
exploitable or equally classified.

These are real demonstrations of source-identity mismatch in a disposable
16 MiB synthetic RAW fixture, NOT evidence of exploitation on a guest,
Windows disk or actual ESP.

## Mitigation in the stacked audit branch

1. Preserve the UNMODIFIED Safety parser and all primary/backup GPT CRC,
   GUID, PARTUUID, offset and partition checks. No second GPT parser.
2. Keep hash/byte comparison on already-owned FDs and preserve existing
   negative failure codes. Before publishing a positive result, unconditionally
   refuse E_GPT_FD_BINDING_REQUIRED, even if every diagnostic check passes.
   The current Safety API cannot prove that its reopened path names identify
   the same objects as those authenticated FDs. A final pathname recheck
   would not solve rename-and-restore (ABA). Therefore NO success
   classification is emitted until a reviewed Safety FD interface exists.
3. Anchor the synthetic ESP directory traversal to opened directory FDs:
   os.scandir(fd), os.stat(name, dir_fd=fd, follow_symlinks=False),
   os.open(name, ..., dir_fd=fd), cross-check inode/device and inspect
   via the retained descriptor. Check parent and child directory identity
   after traversing. This addresses the tested directory/entry reopen
   race, but does not independently attest any ESP/FAT32.
4. Retain synthetic-only, no-writer, no external attestation,
   no Windows-rollback and no native-installer flags. Modify no
   signed catalogs, production backend, Safety or Observer module.

The positive no-swap and Linux-partition-only cases remain demonstrable
at the primitive compare_raw() level, but top-level
verify_private_synthetic() REFUSES E_GPT_FD_BINDING_REQUIRED. A temporary
refusal is safer than an invalid claim that GPT measurement and raw
comparison are bound to one file.

## Next Safety interface required (PROPOSAL, NOT implemented)

Safety #265 would need a reviewed read-only interface such as:

    inspect_gpt_fd(fd: int, *, logical_sector_size: int) -> dict

It must operate solely on a validated, duplicated already-open regular
file descriptor via os.pread, never reopen caller-controlled pathnames.
No /proc/self/fd symlink trick, monkey-patched os.open, local GPT parser
copy or pathname before/after checks as an authentication substitute.
Keep the canonical CRC/PMBR, primary/backup, GUID/PARTUUID and exact
geometrical validation. Verify FD identity/size before and after.
Even this API does not prove against arbitrary concurrent in-place writes
or a malicious data source; immutable backing, external provenance,
transaction authority, host/guest binding and restored checkpoint remain
separate Safety requirements.

The synthetic ESP directory remains a path inventory surrogate. Actual
FAT32/EFI, BootOrder, Windows Boot Manager, BCD, WinRE and hardware recovery
must be tested separately after Safety and Observer approval.

## Before/after validation

- BEFORE: Actions #44907293085, SUCCESS 11/11 pre-fix reproduction tests
  at SHA ce52f44a48d0397dc3caeffae0f311c5babbba28. An unsafe
  SYNTHETIC_NO_CHANGE was reproduced; green here means the diagnostic
  reproduced the defect, NOT safety.
- AFTER: Actions #44907672555, SUCCESS 12/12 adversarial swap refusals
  at SHA 89d38038128e2c205625f2c73aeb581877b3ffb8.
- Full post-mitigation CI runs 12 TOCTOU + 32 synthetic + 140
  Zorin/Mint/Windows regression tests = 184, Python compileall,
  Ruff check and Ruff format and JSON Schema Draft 2020-12.
- Original PR #277, Safety #265/#267, Observer #259/#272 remain untouched.
- All mutations are in disposable temporary private RAW/EFI test files;
  no QEMU, Ubiquity, GRUB, Windows Setup, physical disk or OS installation.

## Review and status

GASLUX-SAFETY should review the actual reproduced races,
unconditional admission refusal, dirfd implementation and requested
descriptor API. This audit cannot close the underlying GPT binding gap
until Safety publishes that API and independent review passes.

authorization=DENY_NO_WRITER
syntheticOnly=true
transactionOwned=false
externalAttestationVerified=false
windowsRollbackVerified=false
nativeInstallerInvoked=false

No rollback Windows, native dual boot, P3/P4/P5 or stable status claimed.
