---
name: gaslux-dependency-resolution
description: Resolve stacked and diverged PRs before reusing code.
---

# Gaslux dependency-resolution

Portable repository procedure. AGENTS.md, AI_POLICY.md and existing Safety gates remain authoritative. No new permissions.

1. Load the full PR inventory and the exact-SHA comparison index. Branch-name edges are leads only.
2. Verify current PR HEAD and base using authenticated GitHub metadata. Compare parent SHA to child SHA using GitHub compare or `git merge-base --is-ancestor` with complete objects. Missing objects or shallow history are unknown, not negative proof.
3. For ahead/behind/diverged, inspect merge base and unique commits, exact file blobs and changes already in dev. Squash merges require tree/blob comparison, not just ancestry.
4. Preserve unique changes, findings and tests; reconcile existing branches in dependency order. Never force-push or close a PR simply because its title is similar. Revalidate final composition CI and Safety.
5. Record exact pair of SHAs, compare result, unresolved divergence and decision. Do not treat historical ancestry as merge authority.

Example: #189 → #231 and #267 → #269 have diverged final heads. #113 → #119 → #125 have confirmed historical ancestry. See `docs/GASLUX_HISTORICAL_DEPENDENCY_AUDIT.json`.
