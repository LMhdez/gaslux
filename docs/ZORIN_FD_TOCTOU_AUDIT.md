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


## Integration: eight-file clean-dev composition (2026-11-22)

The eight-file subset is the five-file #277 synthetic write-set plus the
three new #281 FD/TOCTOU files (two of #281's five are modifications of
existing #277 paths). This is a diagnostic proposal, **not a merge into dev**.

At the time of the composition, clean `dev` was pinned to
`6439377a6a7f9b336ac9d4894b65745b5a0dc5ff`.
The canonical parser in that dev checkout has Git blob
`e82a401d5a160bfb5ca232b9a820417347dfc22a`, **not**
the older pinned #307 parser blob `e599e532fe3cc1139c1833f27035c668c73e6926`.
The current reader retains `inspect_gpt_fd()`, and this integration test
exercises its actual code without replacing it. We do not assert bitwise
equivalence of the two parser versions.

The [clean-dev Action #45021347116](https://github.com/LMhdez/gaslux/actions/runs/45021347116)
on Zorin HEAD `3079c736b20d35da158784f4bb9267ccdf97e2f5`
completed **SUCCESS** in both jobs:
- Existing pinned-#307 replay: 17 TOCTOU, 32 synthetic, 140 shared
  Zorin/Mint/Windows and 25 Safety regressions (214 total).
- New `clean-dev-zorin-subset` job: checks out exact clean dev;
  asserts every selected path is absent from the dev tree before copying
  precisely eight files from the Zorin PR HEAD; imports the canonical
  `inspect_gpt_fd` on that dev tree; runs 32 synthetic + 17 TOCTOU +
  25 canonical Safety pytest tests, plus Ruff lint/format and compileall.
  All passed. No code, installer, writer or tests from #264 are copied.

The separate checkout is a **synthetic composition test**; it does not
automatically prove that the stacked Git history of #281 can be merged to
`dev` without including #264. Do not retarget this stacked PR to dev
blindly. A minimal dev-based integration path with exact-file selection,
independent Safety review and current-head CI is required for merge.
`DENY_NO_WRITER`, `syntheticOnly=true`,
`nativeInstallerInvoked=false`, `windowsRollbackVerified=false`,
`sameDiskDualBootVerified=false`, `stable=false` remain in force.


## Targeted negative coverage and latest clean-dev replay (2026-11-22)

Current PR #281 is still draft and based on the historical #277 feature
branch. PR #277 is now CLOSED WITHOUT MERGE. PR #264 remains draft; its
original Windows COW/rootfs ancestry MUST NOT be included in a dev merge.

A minimal eight-file clean-dev composition was repeated against exact
dev commit 8e68a475d6397ba8fef2e0f9f83758545e202a5f. The
current canonical dev GPT reader's Git blob was verified as
e82a401d5a160bfb5ca232b9a820417347dfc22a.
This is a different exact blob from the original #307 merge blob
e599e532fe3cc1139c1833f27035c668c73e6926, but both expose
inspect_gpt_fd and are independently executed by the respective CI jobs.
No parser is copied into the Zorin branch.

Eight further tests use actual synthetic bytes or metadata to reject:
- primary-GPT short reads through canonical inspect_gpt_fd;
- incomplete raw comparison reads after the GPT inspection;
- declared 4096-byte sector geometry applied to 512-byte GPT bytes;
- conflicting disk size in the typed plan;
- a matching-hash receipt with foreign provenance;
- foreign backend ownership GASLUX-CACHYOS-ROOT;
- primary GPT mutation after initial inspection and before full raw diff;
- a late protected-sector mutation detected by final FD metadata checks.

The authenticated RAW descriptor remains the source for GPT,
SHA-256, byte comparison and final fstat. No code authorizes a
transition from a diagnostic result to a writer.

[Actions #45029817921](https://github.com/LMhdez/gaslux/actions/runs/45029817921)
SUCCESS at SHA 5dccccc6cebf9b5a57b4ac8db2807954454b745d:
- Main pinned-#307 replay: 25 TOCTOU, 32 synthetic write-set and
  140 Mint/Zorin/Windows tests, plus 25 canonical Safety tests;
  222/222 with Python compileall, Ruff lint/format, JSON Schema checks.
- Clean dev eight-file subset: 25 TOCTOU + 32 write-set checks,
  and canonical Safety pytest, compileall and Ruff. No installation.
- All file changes remained inside the existing Zorin experimental
  branch. No edits to production Debian/Ubuntu, Safety, Observer,
  signed catalog, physical disks or real Windows artifacts.

### Production integration boundary (explicitly NOT closed)

A review of CURRENT dev's assets/live/libertix-install-main.sh,
Git blob f176249b0744905c2cc431869555837813b2ce2c,
shows production uses resolve_target_disk_from_manifest() before
operations such as blockdev --getss "$DISK", parted -s "$DISK"
resizepart, wipefs on "$NEW_PART", and firmware-specific GRUB/EFI
operations. It has its own target identity, geometry and recovery
validators. Those checks MUST NOT be treated as equivalent to
this synthetic FD-bound proof. No production installation code was
changed here, and no new production defect is asserted solely from
these path references.

The authoritative plan validator
assets/live/libertix-installation-plan.py (current dev)
records disk unique ID, GPT table ID, total bytes, logical sector
bytes, partition offsets and transaction context. Plan validation
and runtime destination stability, however, are separate
trust boundaries. Host/guest identity, post-prepare geometry,
independent ownership and checkpoint recovery require coordinated
Integrator-2 and Safety audit before any real writer.

In particular, a real device pathname or a later geometry probe
must NOT be taken as a proof that a writer operates on the exact
device object previously authenticated by the synthetic RAW reader.
That scope remains DENY_NO_WRITER and is outside this PR's authority.

### Reconciliation advice

Integrator should create a clean dev-based branch and select ONLY
the eight inventoried no-writer Zorin files, then confirm the current
canonical GPT reader identity, CI, independent Safety review and
dependency statuses. Do not retarget/merge the current stacked
#281 ancestry blindly; do not merge #264 to acquire these tests.


## Rebase seletivo da evidência, 2026-11-22 UTC

O HEAD `79264bd147f5d3e71de59b0f126e5906cfafa52e` da PR #281 confirmou dois jobs verdes na [Actions #45021477864](https://github.com/LMhdez/gaslux/actions/runs/45021477864), incluindo `clean-dev-zorin-subset` sobre `dev` no commit `8e68a475d6397ba8fef2e0f9f83758545e202a5f`. A extração em `integration/zorin-277-281-fd-nowriter-dev-20261122` preserva só a análise de bytes sintéticos e recusa escrita. Não se deve integrar diretamente #281, pois a sua ancestralidade inclui #277 e #264. Não existe ainda revisão Safety independente desta composição nem prova de rollback Windows. Validações verdes da branch histórica não substituem os checks do HEAD da nova integração.

**Nota de HEAD (22-11-2026 13:55 UTC):** a branch #281 avançou para `a26c0cda741323f0d4457aa662daa85279e726e5` após a execução `45021477864` no commit `79264bd147f5d3e71de59b0f126e5906cfafa52e`. Os quatro ficheiros operacionais (verificador, dois testes e schema) mantiveram exatamente os mesmos Git blob SHAs nesta mudança; a documentação evoluiu. A CI `45021477864` não deve ser atribuída a `a26c0cda` sem check próprio.
