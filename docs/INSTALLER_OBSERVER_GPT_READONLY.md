# Installer Observer — experimental real-sector GPT producer

**Scope:** disposable synthetic QCOW2/RAW disk only; QEMU/libguestfs
read-only; zero guest input and no Windows/installer writes. No independent
attestation is implemented. Classification **NOT_INDEPENDENT**.

## Existing code reused

The producer is deliberately kept in Observer PR #259:

- `auto_tests/installer_observer/gpt_readonly_producer.py`: bounded
  `pread` collection of actual full-sector GPT headers and complete
  primary/secondary partition arrays; SHA-256 over bytes returned by
  `pread`, header CRC-32 and array CRC-32 rechecked, per-piece offset,
  length and exact base64 evidence recorded. Rejects block devices,
  symlinks, hardlinks, foreign paths, wrong geometry, invalid GPT, lost
  file identity and path/inode/mtime replacement during read.
- `auto_tests/installer_observer/gpt_lab_provenance.py`: the lab-only
  orchestrator. Reuses (by exact SHA checkout, **not copied/modified**)
  Safety #267 `libertix_disk_identity_gate.inspect_gpt_image`,
  `read_header`, `exact_read`, `safety_qemu_gpt_host_guest`
  create/reconstruct/chain checks, its `SafetyObserverPins`, and
  `assess_gpt_provenance_v1` directly.
- `auto_tests/installer_observer/lab_identity.py`: QEMU Linux
  `/proc` PID/start ticks/command/executable inode. A hash is
  additionally computed over the actually opened QEMU executable
  while the process exists.
- `auto_tests/tests/test_observer_gpt_readonly_producer.py`: synthetic
  adversarial tests of raw capture, parser, CRC/byte hashes and Safety
  schema. These are **not live QEMU observations**.
- `.github/workflows/installer-observer-gpt-readonly.yml`: contracts run
  on normal pushes; its **single** QEMU experiment can run only on a
  deliberately tagged `[gpt-lab]` push, after contracts succeed.

The consumed Safety sources are pinned to
`0be04192acd542646a5b6cd952e01620379edf5d`. The guestfs kernel
helper is pinned to `3f44ae2068fabe875f160ca007393f9e3eb99367`.
A Git SHA identifies checked-out bytes; the same privileged runner can
still modify local files. Pinning alone does not create an independent
trust anchor.

## Exact read paths and reported identities

1. Only a newly created temporary private laboratory directory is used.
   The Safety fixture generator makes a 64 MiB RAW GPT image and a
   child QCOW2 with that file as its raw backing. Only these filenames
   are accepted; no caller-supplied disk path is routed to a writer.
   `qemu-img info --backing-chain` must show exactly the expected
   qcow2/raw pair, formats and virtual sizes. Exact dev/inode identity
   and file SHA-256 are retained before and after.
2. A RAW read-only export of the child QCOW2 is produced before boot.
   The `host` measurement uses `os.pread` on that exact exported
   file, validated against Safety's existing GPT parser. It is an
   indirect export of QCOW2 content, **not** a read of a QEMU file
   descriptor.
3. An actual libguestfs Linux appliance is launched with precisely
   **one** QCOW2 drive opened read-only. The drive is selected by a
   generated guestfs label, *not* by `/dev/sda` ordering. Its virtual
   geometry and 512-byte sector size are checked. A real
   `guestfs.pread_device` reads the first and last 34 sectors; the
   existing Safety helper reconstructs only those slices into an
   ephemeral sparse RAW file for validation. The producer verifies
   the reconstructed content against the **original in-memory guest
   bytes** before marking the record `guest`.
4. The guest QEMU process must terminate before the `immediate` read.
   The pinned Safety helper performs a **new read-only `qemu-img convert`**
   from the original `overlay.qcow2` and its raw backing to a distinct
   `immediate.raw`, which is then measured by `pread`. It never reuses
   the old `host.raw`. Overlay/parent inode, geometry, mtime, backing
   chain and SHA-256 are checked before/after the export. A missing or
   inconsistent export is `OBSERVATION_INCOMPLETE`. This observation
   occurs *after* QEMU termination, not atomically while QEMU is live.
   Same-runner/root tampering remains outside the trust guarantee.
5. For all three observation records, exact offsets, lengths, raw
   samples, SHA-256, calculated CRCs, normalized GUID/PARTUUID,
   partitions, acquisition method and UTC timestamp are retained.
   The trace's SHA-256 is tied to the Safety v1
   `originProof.evidenceSha256`, but is **not a cryptographic witness
   from an independent collector**.

The generated guestfs **label is not an authenticated hardware serial**.
A random VM UUID assigned by the lab is not a QMP-verified VM UUID;
QMP is not exposed by this guestfs experiment. Both limitations are
explicitly recorded; comparisons are lab-consistency checks only.
Procfs PID/start ticks and file identity also cannot exclude an
administrator controlling the runner, root, QEMU and all fixtures.

## Safety GPT provenance v1 and signed Observer state

A diagnostic statement is serialized only with the exact
`schemas/safety-gpt-provenance-v1.schema.json` taken from pinned
Safety #267, validated by JSON Schema Draft 2020-12 and tested against
`assess_gpt_provenance_v1`. Its order is `host`, `guest`,
`immediate`; all carry `LOCALLY_MEASURED` and
`read-only-diagnostic`. The result is always
`classification=NOT_INDEPENDENT`,
`writeAuthorized=false`, `productionWriteAuthorized=false`.

No independent Observer broker or trust store is available. The lab
may construct a **LABORATORY_ONLY**, protocol-v1-shaped
`session.identify`/`state.read` pair, with a new *ephemeral*
runner-owned Ed25519 key and an **explicitly unverified** guest
attestation: `identity_assurance=host-observed`, `status=not-provided`.
The existing `RemoteResponseVerifier` is invoked in a lab-only mode
with `require_guest_attestation=False` to authenticate *message
consistency only*. The private key is not written to disk or included
in evidence. The resulting `observerResultSha256` is a digest of
this *laboratory-signed* state, not an independently authenticated
remote Observer measurement. Safety's provenance evaluator may
therefore return `DIAGNOSTIC_ONLY`, but the production Safety bridge
**must continue to refuse** any attempt to infer a trusted guest or
authorize writes. No existing remote v1 semantics, schema or verifiers
were weakened. The actual Safety adapter was not modified.

A valid v1 diagnostic schema **does not mean** that three independent
collectors were proven or that a Windows disk is writable.

## Acceptance and adversarial boundary

The separate synthetic test suite rejects corrupt primary/backup
headers, partition-array corruption, wrong logical sector, foreign
and linked files, unexpected file replacement, missing original guest
bytes, changed partition identities and mismatching three-way traces.
The lab additionally checks actual QEMU process/attachment and
parent/overlay bytes before and after. It does **not** grant
`ACCEPT_WRITE`, `EXTERNALLY_ATTESTED`, direct keyboard/mouse,
generic QMP, or any physical disk operation.

A successful lab, if achieved, proves read-only GPT sectors were
collected through two locally controlled pathways with a shared
runner; it does **not** prove actual QEMU/guest identity or
administrative independence. Required external mechanisms include a
trusted remote collector, provenance-bound QMP/VM/disk serial,
independent TPM measured boot, immutable artifact and process
identity, protected nonce/transaction issuance and replay, retained
third-party measurement receipts and effective session revocation.

Safety PR #267 and Integrator PR #270 must review the evidence and
any future versioned contract extension before integration. Neither
branch or any writer/boot/install code is modified by this work.


The new synthetic regression changes a valid GPT GUID after the host sample,
then verifies a second source export detects it and the Safety three-way gate
refuses. In-export tampering and a missing export fail as
`OBSERVATION_INCOMPLETE`. This fake converter does **not** prove real QEMU
freshness; new QEMU operational evidence and Safety consumption review are
still required. Observer v1 and all no-writer restrictions are unchanged.
