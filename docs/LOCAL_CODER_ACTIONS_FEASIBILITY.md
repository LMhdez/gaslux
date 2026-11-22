# GitHub Actions local-coder feasibility experiment (2026-11-22 UTC)

Scope: **isolated CPU feasibility smoke only**. This does not create an autonomous coding agent or alter Gaslux installer code.

- Source baseline: `dev` at `8e68a475d6397ba8fef2e0f9f83758545e202a5f`.
- Workflow: `.github/workflows/research-local-coder-smoke.yml`.
- Two separate, bounded Ubuntu hosted jobs test Ollama `qwen2.5-coder:1.5b` and `qwen2.5-coder:3b` on an intentionally tiny deterministic code expression.
- No checkout, repository write permission, GitHub secrets, pushes, autonomous PR creation, physical disk operations or installer changes.
- Each job is capped at 30 minutes, and model download at 10 minutes; inference requests have an 8-minute timeout. Results are uploaded as short-lived JSON evidence.
- AST allowlisting precedes running a generated expression with builtins disabled. This is a restricted smoke test, **not** a general-purpose secure sandbox for model-generated source.
- Current pilot installer uses the upstream Ollama install script without a verified version pin. Before any unattended or write-capable agent, pin hashes, dependencies and model digests, isolate inference, validate provenance, and set network egress boundaries.
- **Success here does not prove capability to repair CI, autonomy, useful code quality, recovery correctness, or free guaranteed 24/7 compute.** Capture actual exact-SHA runs and timings before enlarging scope.
- Public-repository standard GitHub-hosted runner execution is generally free under GitHub's current usage rules; service availability, fair use and job limits still apply.

Next gate: if both model jobs produce reliable evidence, benchmark actual *noncritical* Gaslux Python regression cases in a dedicated, no-write test harness. Only after objective comparison should a separate workflow be considered for drafting patches, with limited iterations, independent review and explicit exclusion of disk/boot/recovery paths.

This experiment is independent from Draft PR #361 and must not be interpreted as integration/recovery evidence.
