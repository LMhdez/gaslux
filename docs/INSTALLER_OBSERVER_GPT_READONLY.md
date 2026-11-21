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
4. After the guest read, QEMU PID/start ticks and executable SHA-256
   are checked while the process is still alive. The appliance then closes
   and the QEMU process must terminate. The parent and overlay are checked
   for unchanged inode, backing metadata and SHA-256. Only then does
   `immediate` create and read a **fresh, second QCOW2-to-RAW export** of
   the child disk; the parent/overlay are rechecked again after this export.
   The original `host.raw` copy is never re-labelled as `immediate`.
   This is a post-guest host-side verification, **not** an immediate
   guest read, nor an atomic snapshot of a running VM.
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


## Confirmed genuine QEMU GPT collection — 21 November 2026

The one successful execution is
[workflow #44895034912](https://github.com/LMhdez/gaslux/actions/runs/44895034912),
at commit `690f7a2f30917b32b9a1fa1a890871d9f9f13cac`.
The **producer contracts** and **real QEMU/libguestfs read-only** jobs both
completed SUCCESS. The signed state was produced using a runner-generated
ephemeral Ed25519 key with `host-observed` guest identity and
`attestation.status=not-provided`. It is not production Guest attestation.

The QEMU result explicitly recorded:

```json
{
  "classification": "NOT_INDEPENDENT",
  "diagnostic": "DIAGNOSTIC_ONLY",
  "ephemeralDiskRemoved": true,
  "guestInputCount": 0,
  "guestRealPread": true,
  "status": "LABORATORY_ONLY",
  "writerCalled": false
}
```

The local Safety v1 assessor accepted **read-only diagnostic
consistency**, not independent origin and never writing authorization. The
process and attached QCOW2 were inspected; the isolated backing/overlay
hashes and identities were checked after collection; the guest process
must have exited before the tool succeeds. This supports only the
bounded synthetic-laboratory read evidence described above.

Original per-sector byte samples, trace SHA-256s, computed GPT CRCs,
normalized GUID/PARTUUID inventory, host/guest/immediate acquisition
times, backing-chain metadata, signed-state consistency digest and
manifest are in
[artifact #14702754509](https://github.com/LMhdez/gaslux/actions/runs/44895034912/artifacts/14702754509).
The GitHub Actions artifact ZIP SHA-256 is
`4fd02180627944c3ffb7c56ecb95edd2108e8bdaaefaee734aedb09eaaf3b325`.

The log independently reports these **file SHA-256 values**:

| Evidence file | SHA-256 |
|---|---|
| `host-read-trace.json` | `56b368e01f4051fa1589a4fb969e557556cfbfe06b2b984c0a81013147bbd01d` |
| `guest-read-trace.json` | `1c88b7605aa476cbff5adeb34fc6db77912b48926b6084de617bac6edbd33561` |
| `immediate-read-trace.json` | `5469f5df3c6baea53de44d99d6b20600665045c86c415e9adcfac43d3202ab9a` |
| `safety-gpt-provenance-v1.json` | `5b3c0361ab1b1ea8b7562b42abe4153f3ada2cfe293d5b917ecda2934afd6eb0` |
| `manifest.json` | `f8a0a9374f02a19445c0fe697a735f639bddd46acc8e20993fdd09447a95e036` |

A previous run
[#44894833833](https://github.com/LMhdez/gaslux/actions/runs/44894833833)
failed **before QEMU boot** because the venv lacked `Pillow`, which is an
existing transitive Observer dependency. The next commit added Pillow and
a preboot import test; the successful experiment was then conducted once.
The failed run's 162-byte artifact is **not measurement evidence**.

**Acceptance level: RESULT A — synthetic QEMU laboratory only, NOT_INDEPENDENT.**
No Windows, installation, dual boot, recovery, genuine guest hardware identity
or safe production write was proved. Even a successful signed state constructed
by this runner cannot establish the origin of the actual VM or the
administrative independence of any collector.

**Follow-up correction:** after the initial successful run #44895034912,
the post-guest `immediate` method was strengthened to create a new raw
export of the unchanged QCOW2 rather than reread the existing host export.
The initial run remains genuine evidence for host and guest reads, but
its immediate record used the previous host export. The revised source
requires its own validation run before its stronger immediate claim
can be accepted; never attribute this property retroactively to the
earlier artifact.

## Fresh IMMEDIATE revalidation — confirmed 21 November 2026

A follow-up engineering review identified a nontrivial source limitation:
the original `immediate` read in run #44895034912 read the *same*
`host.raw` export used by HOST. The code was corrected in commit
`418ad582a7ceb8e54c203467b8d35dd12c4f1026` to require a new
`qemu-img convert` read-only export of the **same checked QCOW2** only
after `guestfs.close()` and QEMU process termination. A second SHA-256
and inode/chain validation follows this fresh capture.

This specific changed hypothesis was tested in
[Actions #44895500728](https://github.com/LMhdez/gaslux/actions/runs/44895500728),
commit `8d66312a8a972cdc86b860de03f9410ac85107bf`:
the synthetic producer contracts, pinned Safety regressions and genuine
QEMU/libguestfs laboratory all completed **SUCCESS**. The final QEMU
result recorded `guestRealPread=true`, `ephemeralDiskRemoved=true`,
`diagnostic=DIAGNOSTIC_ONLY`, `guestInputCount=0`,
`writerCalled=false`, and `classification=NOT_INDEPENDENT`.

[Original refreshed artifact #14704100481](https://github.com/LMhdez/gaslux/actions/runs/44895500728/artifacts/14704100481)
contains the three distinct read traces, raw GPT samples, strict Safety
v1 document, hashes and lab manifest. GitHub Actions ZIP SHA-256:
`24be270491e356ee6db9cd83787a6c5d03c26262cf7b3f3bf8f1e0eddc4d5391`.

| Original evidence file | SHA-256 |
|---|---|
| `host-read-trace.json` | `96642f07f13618d1a40f165f4dadd5a78e809767b4d2089f1f1513551a466c55` |
| `guest-read-trace.json` | `48596d9b8c4b9e058639bee3051048787b94fdddce77bc97e96d48bd3855b3dc` |
| `immediate-read-trace.json` | `9055c0c69466d6ff0efde9e1ca5c632d35930cd42d2b940e20373b9e7f7d9a31` |
| `safety-gpt-provenance-v1.json` | `9e58077e22c939e4d52c8e2b54d3dcf5806f73f76aa2530d8012357830c7043d` |
| `manifest.json` | `4c9fc606fc30fa1c9001cb34f798c0c5b6ab986356afb3ff0f56664ba5a01e59` |

**What this adds:** post-guest QCOW2 state revalidation from a
new read path. The appliance is already shut down when IMMEDIATE is
acquired; this is **not an atomic live-VM snapshot** and still does not
prove a QMP-authenticated VM UUID, a genuine hardware serial, or
independent guest measurement provenance. All identity and storage
claims remain local to the GitHub-hosted laboratory.


## Consolidated synthetic IMMEDIATE regressions

The existing post-guest QCOW2 export is reused by experiment() through the
new capture_fresh_immediate() validation boundary. The pinned Safety helper
still exports original overlay.qcow2 to newly owned immediate.raw after QEMU
exits; this is never a reread of host.raw. Overlay/base inode, geometry,
mtime, ctime, backing-chain metadata, SHA-256, and GPT snapshots are checked
before and after capture. Unknown or inconsistent evidence is refused as
OBSERVATION_INCOMPLETE. Synthetic tests invoke this same production function
with an injected converter. They do not prove an independent source or replace
previous genuine QEMU evidence.

Only synthetic contract runs are permitted on the regression branch. The QEMU
job remains available solely through an explicitly marked commit on the
original Observer branch. The manifest explicitly keeps inputAuthorized,
diskWritesAuthorized and productionInstallationAuthorized false. No writer,
Observer protocol v1 change, Windows install, or rollback claim is introduced.
