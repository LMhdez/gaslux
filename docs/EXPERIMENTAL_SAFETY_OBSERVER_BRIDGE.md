# Safety × Observer: signed read-only state (experimental)

## Dependency and interface

Safety PR #267 is based on #265. This bridge consumes the **existing**
`RemoteResponseVerifier.verify(request, response, *, deadline, now)` and
`TrustStore` from Observer PR #259, at reviewed commit
`31d6e014aff9d5c073841907191d2b1afb8bfe9a`. The CI checks out that
revision separately. No Observer code is copied into the Safety branch.

Adapter:
`assets/live/libertix_safety_observer_adapter.py`:
`consume_observer_state_no_writer(verifier, request, response, pins,
plan_bytes, host_gpt, guest_gpt, immediate_gpt, gate_evidence, now, deadline)`.
`gate_evidence` contains three separately HMAC-authenticated Safety GPT
snapshots, ephemeral host/guest keys and an explicitly limited synthetic
owned free-space write-set. The adapter invokes the existing
`decide_no_writer()` before returning `ACCEPT_NO_WRITER`, then verifies
that its authenticated snapshots equal the independently supplied GPT
inventories. Observer's UUID transaction is converted to the same 128-bit
32-character hexadecimal Safety plan identifier; no unrelated transaction
may be generated. Neither HMAC nor a caller-supplied ownership declaration
is proof of provenance or production authority.

Only immutable raw request/response bytes are accepted. The actual Observer
verifier must check RFC 8785, Ed25519, schemas, externally pinned controller,
collector, distribution and QEMU executable, response integrity, response
freshness and transaction/session replay before Safety inspects the signed
`state.read` result. The verifier owns replay state. Safety reuses the GPT
snapshot comparator from #265 and refuses mismatches or incomplete fields.

The externally provisioned `SafetyObserverPins` must originate from an
independently authenticated coordinator. They include transaction UUID,
session and request UUID, nonce, sequence, VM UUID, controller and collector,
public key ID, QEMU PID/start ticks, plan digest, backing filename and digest,
overlay digest, virtual disk serial, GPT disk GUID and virtual size. Safety
checks agreement, but **does not verify the physical collection** of those
values. Input values supplied by a privileged, compromised runner are not
independent trust anchors.

The signed Observer `state.read` `result.snapshot` does not natively
specify GPT. This experimental bridge accepts only the additional nested
`snapshot.safety` object with EXACT keys `trust_boundary`, `mode`,
`gpt`, `qcow2`, as exercised by synthetic fixtures. Its QCOW2 object must
match all external pins. The signed GPT assertion is compared against
separately supplied Safety host, guest and immediate complete GPT snapshots.
The bridge does not interpret UI pixels, screenshots, HMACs or guest claims
as independent GPT evidence. No production Observer producer currently
emits this reviewed Safety GPT envelope. These tests therefore prove the
**consumer contract**, not a deployed remote collector.

## Trust and capabilities

- `controller_signature_verified = true` means an Ed25519 signature matched
  the externally pinned public key. It does not prove the holder's isolation.
- `guest_attestation_verified_locally = false` remains false: Observer's
  signed guest attestation status is a **controller assertion**, not a
  locally verified TPM quote or independent process identity.
- `trust_boundary = NOT_INDEPENDENT` is mandatory; any claim of
  administrative independence is refused.
- The plan digest proves byte equality only. The adapter has NOT
  authenticated a production Gaslux plan signature.
- The backing/overlay digests prove equality to declared external pins, not
  that an immutable file descriptor or running QEMU process was inspected
  independently or fenced against substitution.
- Only `ACCEPT_NO_WRITER` can be returned after the *existing Safety gate*
  succeeds, and only with
  `production_write_authorized = false`, `writer_called = false`.
  **It MUST NOT be connected to parted, mkfs, an installer or bootloader.**
- No physical disks, real Windows partitions or VMs are modified by the
  adapter or its synthetic tests. No private keys are stored in artifacts.
  The test helper generates transient Ed25519 keys solely for fixtures.

## Testing and CI

Workflow: `.github/workflows/safety-observer-readonly-adapter.yml`.
It pins the #259 commit, executes actual cryptographic Observer verifier
fixtures, the Safety GPT/no-writer regressions, bytecode compilation and
Ruff, then refuses signed or unsigned tampering with VM, transaction,
nonce, request, sequence, controller, collector, QEMU process, backing,
PARTUUID, plan, disk identity, mode and trust boundary. Observer's replay
guard is exercised with a repeated signed request.

No QEMU boot is needed for these contract tests: reuse the independently
documented synthetic KVM GPT evidence from runs #44818212291,
#44818212307 and #44818212316. Those runs do NOT contain a signed Observer
remote state envelope and cannot be relabeled as an integrated live proof.

## Blocking prerequisites for genuine Windows 10 QCOW2

1. Authenticate the exact Windows origin and ISO signature/digest, QCOW2
   backing chain and immutable backing-file identity outside the runner.
2. Bind QEMU PID, start time, VM UUID, device serial, virtual geometry,
   attached file descriptors and external collector process to one transaction.
3. Provide complete host, guest and immediate GPT inventories from
   controlled read-only observation; attest their actual measurement origin
   and ensure external capture/nonce replay protection.
4. Capture and preserve ESP/Recovery partitions, EFI files, BCD, WinRE,
   BitLocker/Device Encryption status and OVMF state independently.
5. Prepare a proven restorable checkpoint (including OVMF/TPM where used).
6. Authorize the plan and media pins via an independent signature policy;
   prohibit concurrent mutation or path replacement before validation.
7. Keep the observer read-only and the Safety writer nonexistent. Production
   installation, real Windows boot, rollback, P3–P6 and stability are
   **not** demonstrated by this bridge.
