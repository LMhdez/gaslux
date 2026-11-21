# Observer GPT IMMEDIATE — one-shot QEMU preparation (NOT authorization)

**Safety audit:** https://github.com/LMhdez/gaslux/pull/272#pullrequestreview-6004845263

APPROVED_FOR_READONLY_QEMU authorizes technically ONE synthetic 64 MiB,
GitHub-hosted, read-only QEMU/KVM laboratory experiment, **only after separate
explicit human authorization**. This draft PR does not provide that approval.

## Pinned code and immutable experimental scope

- Exact **executed** Observer commit: dd3e7bf26e36499f89701393773df464ce713e4f
  (PR #272). It is checked out under audited/, not inherited from the trigger
  branch. The workflow validates the FULL git SHA and publishes producer
  Python file SHA-256 checksums.
- Safety v1 pinned source: 0be04192acd542646a5b6cd952e01620379edf5d
  (PR #267). Existing guestfs kernel helper: 3f44ae2068fabe875f160ca007393f9e3eb99367.
- Only a 64 MiB GPT synthetic regular file, 512-byte logical sectors,
  read-only guestfs, QCOW2 child on RAW backing under a temporary private
  RUNNER_TEMP directory; NO selected Windows or physical user disk.
- Guest opened readonly=1 using a generated guestfs label. The audited
  experiment captures HOST; runs real libguestfs.pread_device under QEMU/KVM;
  terminates QEMU; then calls capture_fresh_immediate(), exporting the ORIGINAL
  overlay into a NEW immediate.raw, never reusing host.raw.
- GitHub-hosted Ubuntu 24.04, KVM required, least workflow permissions
  (contents: read), persist-credentials: false for every checkout,
  concurrency cancel-in-progress: false, no installation or GUI input.

## Why not workflow_dispatch?

The default branch is main. Its tree does not contain the pre-existing
installer-observer-gpt-readonly.yml workflow, so that workflow cannot reliably
receive workflow_dispatch until present on main. Main is deliberately untouched.

The distinct observer-gpt-qemu-one-shot.yml is triggered only by a push to
qemu-approved/observer-gpt-dd3e7bf2-20261121 which ADDS exactly
.github/gpt-qemu-approvals/observer-gpt-dd3e7bf2-20261121.json.
It has no PR, workflow_dispatch, schedule, repository_dispatch or ordinary
development-branch trigger, and does NOT modify the existing Observer gate.
It does not use a commit-message marker.

The initial guarded preflight requires github.actor=LMhdez, repository
LMhdez/gaslux, GitHub-hosted runner, first run attempt, pre-existing branch
(created=false), non-forced push, EXACTLY one commit containing the EXACTLY
one new file, no other changes, git parent/event identity match, audited
SHA ancestry, exact expected JSON payload, and no write privileges.
The job is guarded against accidental pushes and manual reruns (attempt 2+).
The new authorization branch is deliberately **not created during preparation**.

This is an audit trail within the SAME GitHub administrator domain; JSON and
actor account identity are not a hardware-backed independent human signature.
An administrator may modify CI or branch policy. A new attempt after recreation
of the authorization branch must also be barred by human process; GitHub git
history alone is not a global once-ever ledger.

## Separate authorization procedure (NOT performed)

1. A human reviews this preparation PR, the Safety #272 differential audit,
   the CI results and the code SHA, and separately authorizes ONE QEMU/KVM
   experiment. This preparation request or technical Safety verdict alone is
   NOT permission to run.
2. After authorization, create the distinct authorization branch
   qemu-approved/observer-gpt-dd3e7bf2-20261121 from the preparation
   HEAD, with NO approval file. A branch-creation event is explicitly rejected.
3. In that authorization branch, ADD ONLY the following new file in ONE
   human-authorized commit, without changes elsewhere and without force push:
   .github/gpt-qemu-approvals/observer-gpt-dd3e7bf2-20261121.json

   JSON object fields and values, with no additional fields:
   - authorizationKind: ONE_SYNTHETIC_GPT_READONLY_QEMU
   - repository: LMhdez/gaslux
   - approvedCodeSha: dd3e7bf26e36499f89701393773df464ce713e4f
   - safetySourceSha: 0be04192acd542646a5b6cd952e01620379edf5d
   - authorizationRef: refs/heads/qemu-approved/observer-gpt-dd3e7bf2-20261121
   - reviewUrl: https://github.com/LMhdez/gaslux/pull/272#pullrequestreview-6004845263
   - humanApproved: true
   - singleRun: true
   - inputAuthorized: false
   - diskWritesAuthorized: false
   - productionInstallationAuthorized: false
   - productionWriteAuthorized: false

   The canonical exact fields are also returned by the Python
   expected_approval() function. The JSON file is NOT committed here.
4. Examine the single resulting GitHub Actions run. Do not click Re-run;
   the script rejects attempts >1. No automatic QEMU retries exist.
   On any error, record failure and STOP. Further retries require a new
   independent human review and explicit authorization.
5. Publish the run URL, HEAD, artifact hash and exact remaining limitations
   in PR #272 and request another independent Safety review.

## Evidence (prepared, NOT yet collected)

The workflow first checks the gate and commits, then verifies the exact source
SHA and pinned Safety. Only then can it install the already-qualified lab
dependencies and open KVM. The audited Python producer remains unchanged.

A second local fail-closed validator checks source chronology, distinct
host.raw/guest-reconstructed.raw/immediate.raw, raw GPT samples, sector SHA-256
and primary/secondary GPT header/array CRC32, GUID/PARTUUID, offsets,
three-way GPT equality, backing chain hashes and read-only/writer/input flags.
This validates same-runner trace consistency, NOT independent provenance.

The seven-day artifact contains ONLY JSON/text:
authorization-intent.json, executed-heads.txt,
audited-source-sha256sums.txt, sha256sums.txt,
host-read-trace.json, guest-read-trace.json, immediate-read-trace.json,
safety-gpt-provenance-v1.json, manifest.json, evidence-verification.json,
lab-result-summary.json. It contains NO QCOW2/RAW files, Windows images,
passwords, sensitive user material, or ephemeral private signing keys.

MANDATORY classification remains NOT_INDEPENDENT / DIAGNOSTIC_ONLY.
inputAuthorized=false, diskWritesAuthorized=false,
productionInstallationAuthorized=false, productionWriteAuthorized=false.
No independent QMP VM identity, trusted remote guest provenance, Windows
installation, dual boot, recovery, rollback or production write authorization
is proved or claimed. Historical QEMU runs on other source HEADs cannot
validate this new audited function operationally.
