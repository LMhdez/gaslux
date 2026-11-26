---
name: gaslux-evidence-verification
description: Verify evidence provenance, artifact expiry and scope without promoting historical claims.
---

# Gaslux evidence-verification

Portable repository procedure. AGENTS.md, AI_POLICY.md and existing Safety gates remain authoritative. No new permissions.

1. Match authenticated run ID, event, head SHA, job conclusion and actual checkout; account for synthetic PR merge SHA. Inspect actual execution rather than workflow title.
2. Verify artifact metadata, exact digest, bounded archive members, sizes, paths and original source as in #119/#125. A hash proves integrity, not origin or license. Missing/expired artifacts remain missing, not fabricated.
3. Keep history separate from formal gate registry. Record producer claims and independently verified facts separately, with precise proof level and false authorization flags.
4. Prioritize preservation of permitted non-sensitive JSON/log/hash evidence before expiry; no ISO, disk images, TPM, keys or secrets. Verify archived bytes before reporting preservation.
5. Only update formal evidence through the applicable independent review process. A green CI, old result or valid-looking JSON alone never closes a gate.
