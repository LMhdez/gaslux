# GASLUX-ZORIN — RAW/GPT FD binding audit and integration

**Scope:** disposable *synthetic-only* Zorin RAW/GPT write-set observer. This
document is not evidence of Zorin installation, disk-write authorization,
Windows dual boot, BCD/WinRE recovery or in-place rollback.

## Identity and dependency history

- Zorin [PR #264](https://github.com/LMhdez/gaslux/pull/264):
  previous synthetic Windows COW/rootfs laboratory, NOT native installation.
- Zorin [PR #277](https://github.com/LMhdez/gaslux/pull/277):
  typed no-writer write-set and byte-diff/checkpoint fixtures.
- Zorin [PR #281](https://github.com/LMhdez/gaslux/pull/281):
  read-only descriptor TOCTOU diagnosis and FD-binding integration.
- Previous Safety #265 reader was pinned at
  SHA 8ed912c6934c33354b0a814201c7217043bd0197.
  Related #286 was closed without merge.
- Canonical Safety [PR #307](https://github.com/LMhdez/gaslux/pull/307)
  merged into dev at SHA d5eb20114df34a778ada1af1f6f4f6bff0c49845.
  File assets/live/libertix_disk_identity_gate.py has Git blob
  SHA e599e532fe3cc1139c1833f27035c668c73e6926 at that merge.

The Zorin audit branch has NO separate copy of the Safety parser. Its
workflow checks out only the canonical module and canonical test file
from the pinned #307 merge commit into safety307/ and imports it through
PYTHONPATH=safety307/assets/live. The workflow checks the exact checkout
HEAD, the presence of inspect_gpt_fd and the absence of Zorin's former
path-reopen operation. This avoids integrating unrelated dev commits.

## RED — confirmed source identity mismatch

The original #277 verifier used owned_fd() to pin baseline.raw and trial.raw,
but read_gpt(root, name, policy) delegated to the old Safety
inspect_gpt_image(root / name), causing a second pathname opening. Hashes
and full byte-diff remained tied to the first FDs. GPT metadata could
therefore be measured from a different inode to the one compared.

- [Actions #44907293085](https://github.com/LMhdez/gaslux/actions/runs/44907293085),
  commit ce52f44a48d0397dc3caeffae0f311c5babbba28, reproduced
  unsafe SYNTHETIC_NO_CHANGE on swapped, same-size, valid-GPT regular
  source pathnames and hardlinks; 11/11 RED diagnostic tests passed.
- Correct refusals were observed for changed PARTUUID, final symlink
  and mutated EFI leaf. Not all swaps caused the same failure.
- [Actions #44908036329](https://github.com/LMhdez/gaslux/actions/runs/44908036329)
  made the earlier branch deny-only with E_GPT_FD_BINDING_REQUIRED;
  184/184 tests passed. That refusal was correct before Safety #307.

RED proves an error in the synthetic tool, NOT exploitation of any
Windows, physical disk or real ESP.

## GREEN — canonical Safety FD integration in PR #281

The Zorin code now imports
inspect_gpt_fd(fd: int, *, logical_sector_size: int) -> dict
from the exact pinned Safety #307 source and applies it to the already
authenticated baseline.raw and trial.raw FDs. Those SAME FDs also support
baseline/checkpoint SHA-256 verification, assert_snapshot_matches(),
full compare_raw() byte-diff, subsequent integrity hashes and final
fstat() identity checks. Checkpoint and OVMF paths are separately
opened and pinned; the synthetic EFI tree uses dir_fd traversal.

The canonical reader duplicates the original FD, uses only pread(),
enforces read-only regular-file access, validates protective MBR,
both GPT headers, CRCs, entry arrays, GUID/PARTUUID/geometry, re-reads
GPT regions and revalidates file identity and timestamps. No Zorin
GPT parser copy or monkeypatched Safety open is used.

Zorin also checks baseline, trial and checkpoint identity (including
ctime, inode and hardlink count) at the end of verification; a final
lstat basename check is a supplemental persistent-rename detector,
NOT proof of the bytes read. Every GPT/RAW measurement uses pinned FDs.

Valid synthetic results are restored:

- SYNTHETIC_NO_CHANGE: no observed byte differences, all checks pass.
- SYNTHETIC_ONLY_WITHIN_ROOT: changes confined to the owned synthetic
  Linux-root byte range, all protected areas unchanged.
- REFUSED: disk/checkpoint/ESP/OVMF corruption, foreign source identity,
  PARTUUID changes, GPT CRC errors, symlink/hardlink and tested TOCTOU.

Both positive results are DIAGNOSTIC ONLY, NEVER a write authorization.

Authorization and schema constraints remain unchanged:
authorization=DENY_NO_WRITER
syntheticOnly=true
transactionOwned=false
externalAttestationVerified=false
windowsRollbackVerified=false
nativeInstallerInvoked=false
writeOperations=[]

## Adversarial proof and post-integration CI

New deterministic tests swap baseline, trial and checkpoint filenames
after opening, test a same-GUID valid GPT on another inode, rename
during real Safety os.dup(), swap between GPT inspection and raw-diff,
replace sources with symlinks/hardlinks, pass a closed descriptor,
perform an in-place GPT mutation during the real FD read, and reject a
valid foreign PARTUUID. Existing fixtures exercise primary/backup CRC
corruption, protected sectors, canaries, EFI and OVMF modifications,
and synthetic recovery.

The test that forbids a second RAW pathname open spies on actual
os.open() while allowing the initial owned_fd opens. Race tests change
actual temporary bytes/inodes, never fake GPT return values.

[Actions #45020448074](https://github.com/LMhdez/gaslux/actions/runs/45020448074)
completed SUCCESS with:
- 17/17 Zorin TOCTOU tests;
- 32/32 Zorin synthetic write-set/checkpoint tests;
- 140/140 Zorin/Mint/Windows regression tests;
- 25/25 canonical Safety #307 FD/identity pytest tests;
- 214/214 total, Python compileall, Ruff lint and format, plus JSON
  Schema Draft 2020-12 assertions.

CI uses a GitHub-hosted runner, private temporary synthetic RAW files,
source hashes and a bounded JSON artifact. No QEMU, installer, Windows
Setup, GRUB, physical disk or production write operations were run.

## Remaining trust limits

FD binding CLOSES the demonstrated pathname/second-open GPT versus RAW
identity mismatch. It does NOT make arbitrary concurrent in-place
mutations impossible. Repeated hashes, GPT rereads and ctime checks
detect tested races but do not provide immutable backing, a global
filesystem lock, or protection from adversarial rename-and-restore ABA.
A basename lstat cannot make a source inherently trustworthy.

The ESP tree is synthetic; it does not validate FAT32, Windows Boot
Manager, NVRAM, BCD or WinRE. A digest and copy restore are not an
independently authenticated checkpoint or Windows rollback. Host/guest
disk mapping, external provenance, signed transaction authority,
write fencing and independent recovery still require Safety/Observer
review before ANY native installer write.

Do not promote P3/P4/P5 or claim Windows dual boot or stability.

## Handoff

Request a narrow independent GASLUX-SAFETY DIFFERENTIAL review of the
Zorin integration to the already-reviewed #307 FD reader and the
adversarial tests. Do NOT repeat an undirected audit of the canonical
parser without a new finding. After review, the Integrator may
reconcile #277 + #281, respecting the current dependency graph and
branch protections. This PR remains draft; no merge here.
