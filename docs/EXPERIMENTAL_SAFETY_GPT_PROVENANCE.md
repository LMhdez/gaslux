# Safety GPT provenance v1 — producer/consumer contract (experimental)

**Status:** proposal and executable diagnostics only. No writer; not a
certificate, not production authorization, not an Observer v1 protocol change.

Code: `assets/live/libertix_gpt_provenance.py`  
Schema: `schemas/safety-gpt-provenance-v1.schema.json`  
Tests: `auto_tests/tests/test_safety_gpt_provenance.py`  
Producer owner: GASLUX-OBSERVER (#259). Consumer owner: GASLUX-SAFETY (#267).

## 1. What each assurance label actually means

| Label | Meaning in a producer statement | What Safety may conclude |
|---|---|---|
| `DECLARED` | Collector or controller asserted fields | Unverified claim; diagnostics only |
| `SIGNED` | A controller claims an integrity-protected statement | Signature may authenticate a message, **not** the actual disk measurement |
| `LOCALLY_MEASURED` | Producer claims local, read-only sector access with a trace digest | Local trace may be inspected, but privileged same-runner control defeats independent proof |
| `EXTERNALLY_ATTESTED` | Producer claims an external authority independently verified the measurement | **Rejected** by the current validator: no verified, externally administered evidence API exists |

Even when `remote_verifier.verify()` accepts an Ed25519-signed Observer
`state.read` response, its generic `snapshot` is an authenticated *statement*
of the controller. The remote protocol v1 does not assert that the GPT bytes
were actually read from the VM attached to the exact QCOW2 inode. Neither an
Ed25519 signature, guest attestation status declared by that controller,
a TPM quote's mathematical consistency, nor a JSON/Python `verified` marker
establishes independent provenance.

### Dimensions deliberately kept separate

1. **Message integrity:** Ed25519/RFC8785 signature by a pinned public key
   (Observer v1 verified by the original RemoteResponseVerifier).
2. **Key authenticity:** a pinned key ID and bytes matched; independent
   provisioning and administrative control are NOT proven by a signature.
3. **QEMU process identity:** asserted PID/start ticks/executable digest
   checked against caller-supplied pins; no independent live process seal here.
4. **VM identity:** signed VM UUID compared to an externally supplied pin;
   does not prove which real VM was measured.
5. **Disk origin:** device ID/serial/size, raw sector hashes, GPT CRCs and
   backing-chain metadata are *claims* until independent capture verifies
   file descriptors, attachment, sectors and collector process.
6. **Administrative independence:** NOT_INDEPENDENT in this lab. A privileged
   runner controlling host, guest, collector and keys defeats independence.
7. **Plan authenticity:** a SHA-256 equality check is **not** verification
   of a production plan signature or authorization.
8. **Write authority:** always **false**, irrespective of every other claim.

## 2. Strict, separately versioned origin statement

This is a separate **Safety v1** statement, not an automatic extension to
`schemas/observer-readonly-{request,response}.schema.json`. The Observer
remote protocol remains protocol=1. The optional detached TPM binding
`observer-tpm-quote-binding-v2.schema.json` on #259 is also separate and
currently returns `NOT_INDEPENDENT`; its quote calculations do not certify
the virtual disk, collector's execution domain or measured-boot chain.

`contractVersion=1`, `kind=safety-gpt-provenance`, `classification=NOT_INDEPENDENT`,
`purpose=read-only-diagnostic` and `writeAuthorized=false` are immutable.
The schema rejects missing, additional and incorrectly typed properties.

The statement must contain:

- Transaction UUID, VM UUID, request UUID, canonical 256-bit challenge nonce,
  sequence and the digest of a *previously verified* Observer v1 state result.
- Issuer ID, observer ID, collector ID, controller ID, policy ID/digest, signing
  key ID and administrative domain. These are pinned **outside** the response;
  no response-provided identity is an independent trust anchor.
- QEMU PID, start ticks, executable digest, virtual device ID, serial,
  virtual size and logical sector size.
- Exactly two ordered QCOW2-chain entries: a QCOW2 overlay with exact backing
  filename/format and its raw parent, including file IDs/inodes, sizes and
  SHA-256 claims. The externally pinned immutable file identities and current
  process attachments must later be measured independently.
- Exactly three ordered observations: host, guest and immediate. Each
  includes the collector and device identity, timestamp, declared assurance,
  read method and optional local trace claim.
- A complete five-key normalized GPT identity for each observation, with
  disk GUID, PARTUUID, partition offsets/lengths, attributes and logical
  geometry. The primary and secondary GPT header positions, CRC-32 claims,
  partition-array CRC-32 claims and raw byte SHA-256 claims are required.

The Safety diagnostic validator compares the three normalized inventories,
pins, declared sector hashes/CRCs and timestamps, but it **does not read raw
sectors, recompute CRCs or authenticate the emitter's collection**. The
established `inspect_gpt_image()` independently recomputes CRCs only if
given an actual regular read-only image. Raw guest sectors, QEMU process seals,
backing-chain contents and storage identity require an independent producer
and verifier. Equality between three fabricated snapshots remains fabrication.

## 3. Required producer/consumer chain

The GASLUX-OBSERVER producer must supply, before any upgrade:

1. Immutable, independently authenticated trust policy and signer identity
   (not chosen by the runner, signed response or guest).
2. Evidence of the process that opened exact host and guest disk handles,
   the QEMU PID/start ticks/executable, the VM UUID and device serial.
3. Atomic mapping from host inode and exact immutable backing chain to the
   QEMU attachment/serial and guest block device (not merely /dev/vda).
4. Bounded raw read-only GPT sector observations and bytes. Consumers must
   recompute both GPT headers/array CRCs and compare GUID, PARTUUID, offsets.
5. An external nonce issuance/single-use replay mechanism and explicit
   transaction/request/session binding, provided by the existing Observer
   verifier (no second replay implementation in Safety).
6. Evidence that the controller/host runner cannot rewrite raw measurements,
   alter attachments or forge the collector's output before authorization.
7. A cryptographically validated independent origin assertion with
   issuer/key provenance outside the controller, linked to those exact bytes,
   with a separately reviewed **new** contract before any acceptance.
8. On any missing proof, return `NOT_INDEPENDENT` and diagnostic-only status.

`assess_gpt_provenance_v1()` accepts complete, matching declarations for
**read-only diagnostics**, returns `ProvenanceAssessment(result=DIAGNOSTIC_ONLY,
classification=NOT_INDEPENDENT, origin_independently_attested=False,
production_write_authorized=False)`. A local trace (also produced by the
runner) cannot change those fields. Any `EXTERNALLY_ATTESTED` claim is
refused until a separately reviewed external verifier is implemented.
`require_externally_attested_measurement()` always fails closed.

## 4. Existing evidence versus missing evidence

- #267 previously obtained genuine **QEMU/KVM execution against a synthetic
  GPT image**, with matching host/guest snapshots and preserved backing.
  See Actions #44818212291, #44818212307 and #44818212316.
- #267's Safety/Observer integration validates **synthetic, signed** v1
  responses via the original verifier; the live QEMU lab did not produce
  these signed Observer envelopes.
- The new Safety origin schema and tests do not relabel previous QEMU outputs
  or claim to have captured a real Observer producer.
- Test SHA-256 values and GPT CRC numbers are conspicuously **synthetic
  fixture fields**, not hashes observed in a real Windows or QEMU disk.

## 5. Windows 10 QCOW2 acceptance gate — blocked

Before a read-only Windows experiment, require externally authenticated ISO
origin, exact parent and overlay identity/inode/hash, confirmed QEMU VM/serial
and read-only attachment, full GPT/ESP/Recovery inventory, Windows BCD/WinRE
and BitLocker/Device Encryption state, OVMF/TPM metadata, authenticated plan
and transaction, immutable checkpoint with recovery proof, and independently
pinned collector/controller trust policy.

Do not initiate a Windows install, Windows partition write, EFI/BCD/WinRE
change, `parted`, `mkfs`, installer, bootloader or production writer.
No Windows recovery or P3/P4/P5/P6 stability is demonstrated by this contract.
