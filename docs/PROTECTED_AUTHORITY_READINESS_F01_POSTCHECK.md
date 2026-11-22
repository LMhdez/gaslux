# F-01 — readiness gate JSON backend type safety and post-test pin checks

**Scope:** corrective Draft PR stacked on [#295](https://github.com/LMhdez/gaslux/pull/295), never merged, no operating authority. The original test baseline is [#295 at `fa8658edac391fa764c8786c6b8a030a06b04f5f`](https://github.com/LMhdez/gaslux/commit/fa8658edac391fa764c8786c6b8a030a06b04f5f). The original imported module Git blob is **`cfb53039670255b96a3029f9f2c696b8e057ba6d`**, as verified by GitHub before editing. Schema `schemas/protected-authority-readiness-v1.schema.json` is **unchanged**.

## RED — original module, not an approximation

[GitHub Actions #44972210330](https://github.com/LMhdez/gaslux/actions/runs/44972210330), branch commit `86c89d0e745af4ec6ca757612844f8dd1c648d9b`, ran the new regression test `auto_tests/tests/test_protected_authority_readiness_f01.py` **against the original, unmodified source and original Draft 2020-12 JSON Schema**. It returned `TypeError: unhashable type: 'list'` or `'dict'` in the original `_reason()` at the set-membership check, for accepted `backend` values across the **five ledger controls**. Accepted numeric/null/boolean inputs did not raise TypeError but yielded a generic reason instead of explicitly refusing an invalid backend type. These are distinct behaviors: do not imply that all invalid types caused exceptions.

The same RED job passed the original #275 (42), #285 (43), #267 (22) and #295 (38) regressions. The final **post-test pin check ran even though the new F-01 suite failed**. All four checkouts retained their expected SHA, clean tracked files and unchanged recorded module Git blob.

## Minimal implementation

Inside `_reason()` for `control.startswith("ledger.")`, read `backend = payload.get("backend")`, require `type(backend) is str` **before testing its membership in the allowed local-backend set**. Non-string and missing backend values yield `LEDGER_BACKEND_FIELD_INVALID_OR_UNVERIFIABLE`. Historical **string** backends `sqlite`, `local-file`, and `runner-memory` keep `LOCAL_LEDGER_NOT_EXTERNALLY_ROLLBACK_RESISTANT`; all other string backends keep `EXTERNAL_LEDGER_AUTHORITY_UNVERIFIED`, except `snapshotRestored is True` which remains `LEDGER_SNAPSHOT_ROLLBACK_UNFENCED`. None proves an external service.

The existing 23-control response, `NOT_VERIFIABLE`, unconditional `BLOCKED_TRUST_ROOT`, and all seven capability flags `false` are unchanged. There is **no** `AUTHORIZED` result, new administrator verifier, controller, ledger, guest command or writer.

## New regression coverage

For each ledger control test unhashable/complex JSON lists and objects including nested combinations; null, positive/zero integers and booleans; missing backend; known and unknown string backends; snapshot restored; and untrusted `GITHUB_READ_ONLY` with HTTP 200. The tests **validate each input against the original JSON Schema before invoking the real module**, then require a fully structured refusal with all 23 controls and seven false capabilities. Other controls receive nested arrays/maps to challenge unrelated comparisons, and a full 23-control self-declared `status=VERIFIED` report must still block.

## CI post-test checkout invariants

The final workflow step has `if: ${{ always() }}`, runs **after** the original #275/#285/#267/#295 tests and new F-01 suite, and checks each pinned checkout:

1. `git rev-parse HEAD` matches the full approved commit, not a branch label.
2. `git diff --exit-code --quiet` refuses tracked working tree changes.
3. `git diff --cached --exit-code --quiet` refuses staged/index changes.
4. `git status --porcelain --untracked-files=no` and `git ls-files --deleted` refuse changed/missing tracked items.
5. `git rev-parse HEAD:<module>` equals `git hash-object --path=<module> <checked-out-file>` for each relevant executable module; the correct module path is checked in each of the four repositories.

| Pinned checkout | Expected commit | Executable module |
|---|---|---|
| #275 trigger | `1a6446b408c78386e720f8d2b1f2063c1d3f7db1` | `auto_tests/tools/observer_gpt_qemu_one_shot.py` |
| #285 ledger | `fda13b8a2a48d8e5f00c3f9be306499d85e0d336` | `auto_tests/tools/observer_one_shot_ledger_offline.py` |
| #267 Safety | `0be04192acd542646a5b6cd952e01620379edf5d` | `assets/live/libertix_prewrite_no_writer.py` |
| #294 Observer | `e7941ef3eb26c0cae1a2d7fbe1b3009eb050c5c9` | `auto_tests/installer_observer/host_qemu_fd_evidence.py` |

Untracked Python bytecode caches are **not** treated as edits to tracked source. The post-test check does not cryptographically attest GitHub infrastructure, detect arbitrary changes in untracked files, or prove the checked-out code could not have been swapped and restored between checks. The GitHub runner, checkout/action provenance, hardcoded commit pins and stored Git objects are still assumed; this is **not** an independent protected authority.

## Remaining trust boundary

The new tests and CI cover offline type safety and integrity checks. Neither a passing job nor intact checkouts proves branch protection or required human review, independent Authority A/B, immutable controller, durable external ledger, trusted clock/nonce, real QEMU capture, Windows rollback, dual boot or disk recoverability. The seven capability flags remain false.

**No QEMU, no VM guest, no writer, no disk/ESP/BCD/WinRE/NVRAM mutation, no repository administration, no merge.** Revision requires independent GASLUX-SAFETY review and human responsibility according to `AI_POLICY.md`.
