# Bazzite legacy storage gate reconciliation (experimental)

This is an **inert, no-QEMU, read-only contract transplant** stacked on PR #222
from the four divergent follow-up commits in PR #214.

## Exact historical origins

- PR #214, HEAD \`a601557a415bbd1f597df48ce00ab52513712138\`:
  \`auto_tests/bazzite_legacy_readonly_storage_gate.py\` (blob
  \`d7d0c09281e94d794f293f5e2e397437c6a56caf\`) and its original
  \`auto_tests/tests/test_bazzite_legacy_readonly_storage_gate.py\` (blob
  \`5d7272f11367ff7346f90719c5e077696c46ba2f\`).
- PR #222, starting HEAD \`006b37298d940aa56162ef13d510bf95913ef4ef\`:
  more restrictive GPT-context OCR navigator and a distinct disposable COW
  laboratory workflow.
- This integration adds only the historical **observer** and unit tests, plus
  cross-gate tests. It does **not** bring back either of PR #214's experimental
  QEMU workflows, because these overlap with #222's independently developed
  GPT/COW workflow and require a separate comparison of guest identity,
  immutability checks, signed artifact provenance and cleanup semantics.
  Thus PR #214 MUST stay open until those workflow-level differences are
  reconciled and the applicable real OVMF evidence is reviewed.

## Permission boundary

Recognizing an "Advanced Custom (Blivet-GUI)" label proves only that OCR
observed some text. It does not verify a runnable Blivet binary, a signed
legacy ISO, a safe partitioning mode, disk identity, or rollback capability.
No workflow in this transplant runs QEMU, connects to any disk, invokes
Calamares/Anaconda/Blivet, or modifies EFI/Windows.

Only UEFI/GPT can be considered for eventual Bazzite support; BIOS/MBR and
unapproved Secure Boot key changes remain forbidden. No production catalogue
or firmware/partition writer changes are included. The PR is draft and
requires human review before any merge (AI_POLICY.md and GPL-3.0).

Generated-by: GPT-6.
