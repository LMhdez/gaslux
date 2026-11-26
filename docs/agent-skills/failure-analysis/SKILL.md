---
name: gaslux-failure-analysis
description: Turn reproducible failures and Safety findings into bounded corrective tasks.
---

# Gaslux failure-analysis

Portable repository procedure. AGENTS.md, AI_POLICY.md and existing Safety gates remain authoritative. No new permissions.

1. Inspect job logs, exit codes, exact checkout SHA, artifacts, and skipped stages. Distinguish model/AST, lint, test regression, runner capacity, media, trust root, guest boot, and recovery failure.
2. Find earlier RED/GREEN and similar findings before changing code. Reproduce the precise defect with a minimal negative test; preserve the original evidence.
3. Repair only the demonstrated cause; verify regression and adversarial tests, then exact-head CI. A corrected failure does not close unrelated findings.
4. Record cause, scope, RED and GREEN URLs, residual limits and owner. Stop on repeated failure or missing prerequisites; never weaken a gate.

Examples: #383 F-383-01 report confinement and F-383-02 OVMF copy TOCTOU remain open at the audited HEAD; #414 fixed Ruff and role dedup; #269 denial is a correct fail-closed result, not a defect to bypass.
