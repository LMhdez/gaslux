---
name: gaslux-safety-review
description: Perform reproducible independent exact-head technical review without manufacturing approval.
---

# Gaslux safety-review

Portable repository procedure. AGENTS.md, AI_POLICY.md and existing Safety gates remain authoritative. No new permissions.

1. Confirm exact candidate HEAD, live base, paths, CI, provenance, previous findings and scope. Review code and tests independently from the author; shared credentials or an agent label alone prove no independence.
2. Adversarially test identity, ownership, path/FD confinement, TOCTOU, replay, stale evidence, guest/host distinction, write-set and rollback when applicable. Preserve existing DENY_NO_WRITER and protected flags.
3. Record explicit findings, evidence and verdict at the exact SHA, including residual risk. Do not present a technical comment as a formal GitHub APPROVE. No fabricated reviewer identity.
4. For automated authority require authenticated operational independence and all existing repository gates; for delegated manual integration follow AGENTS.md risk-based rules. No merger or writer authority from a skill.
5. Reopen only on changed SHA, new evidence or reproducible regression; do not recycle approval across edits without review.
