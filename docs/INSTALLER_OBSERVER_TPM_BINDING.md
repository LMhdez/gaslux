# Installer Observer — durable TPM replay and detached v2 binding (draft)

**Status:** experimental cryptographic consistency only; `NOT_INDEPENDENT`. This
specification extends the [read-only Observer](INSTALLER_OBSERVER.md) *without*
modifying `schemas/observer-readonly-request.schema.json`,
`schemas/observer-readonly-response.schema.json` or the remote v1 verifier.
It does not create a remote broker, sign a trust receipt, authorize input,
validate boot provenance or allow disk/installer writes.

## Durable, explicitly provisioned replay

The new `auto_tests/installer_observer/durable_quote_replay.py` reuses the
existing `remote_verifier.SQLiteReplayGuard` SQLite connection, isolation and
transaction settings (`BEGIN IMMEDIATE`, `PRAGMA synchronous=FULL`) instead
of creating another generic SQLite library. TPM replay uses **separate tables**
(`tpm_quote_meta`, `tpm_quote_consumed`), leaving the remote v1
nonce/request/session state and public signatures unchanged.

Provision once, in a pre-existing private **POSIX** directory owned by the
service account with mode `0700`, by deliberately calling
`DurableQuoteReplayGuard.provision(path)`. Provisioning uses `O_EXCL`,
`O_NOFOLLOW` where available, mode `0600`, an unpredictable ledger marker,
SQLite FULL synchronous commits and a parent-directory `fsync`. Existing
files are never overwritten. **Do not call provision as a fallback when
reopening fails.** All normal consumers call
`DurableQuoteReplayGuard(path)`, which requires the database to exist, checks
ownership, mode, file identity, single link, schema, metadata and SQLite
integrity, and refuses any missing, malformed or substituted ledger.

An accepted native TPM quote consumes all three globally unique identifiers
in one transaction: (a) 32-byte challenge, (b) 32-byte nonce and (c) request ID,
and records transaction/session IDs, UTC consumption time and policy expiry.
A second process must wait for the exclusive SQLite writer transaction and
refuse a duplicate. The replay ledger never garbage-collects or reuses
identifiers, **even after session/policy expiry**. Expiry controls quote
acceptance, not retention. Storage exhaustion or corruption fails closed.
There is no automatic cleanup, reset or recovery from a corrupted store;
human forensic recovery and an externally anchored ledger migration are
required. This implementation has no independent monotonic storage/witness:
an administrator who can delete, restore or replace the ledger can roll back
replay history. Durable storage **does not establish administrative
independence**. Same-UID/root attacks, journal sidecar manipulation and a
hostile privileged runner remain outside its trust guarantees.

`LaboratoryReplayGuard` remains explicitly single-process and non-durable.
`quote_binding.verify_quote_binding` requires a
`DurableQuoteReplayGuard`; a lab replay guard is refused.

## Exact detached quote/response binding proposal — v2

Contract schema: `schemas/observer-tpm-quote-binding-v2.schema.json`.
This is a **separate local proposal**, not an extension to remote protocol v1.
No `verified:true` bit can grant any additional permission. All properties
are allowlisted; the schema requires `classification=NOT_INDEPENDENT`,
`guest_input_authorized=false`, and `independent_attestation_verified=false`.

Inputs to `quote_binding.verify_quote_binding`:

1. The exact v1 request and *complete* signed v1 response (including signature).
2. The native `TPMS_ATTEST`, `TPMT_SIGNATURE`, candidate AK public key,
   PCR values and externally **expected** `QuoteContext`.
3. An independently supplied offline quote policy with pinned PCR/AK expectations.
4. Separate remote-v1 verifier/trust store/replay guard and **durable** TPM ledger.
5. A detached proposal constructed for this exact request, response, quote and
   policy. The proposal is **not** cryptographically authenticated by itself.
6. A trusted clock `now` and request deadline for remote response verification.

The typed procedure checks that the quote challenge includes the expected
fresh 32-byte nonce and exact transaction/session/request IDs, VM UUID,
distribution, ISO digest, policy ID/version/digest and trust-anchor ID.
It binds the quote to the v1 request's canonical nonce, transaction and session;
to the v1 response's VM, distribution, ISO and attestation trust-anchor claim;
and to the complete signed v1 response and request using their SHA-256 digests
under RFC 8785. The *native* TPM attestation/signature bytes and the derived
challenge are independently hashed in the proposed receipt. Issue/expiry
timestamps come from the signed v1 response and are verified against the caller's
trusted clock by `RemoteResponseVerifier`. The remote response's Ed25519
signature is verified using the existing externally pinned controller key.
The TPM quote's signature, challenge, AK pin, selection, PCR digest, policy
and replay are checked by the existing `OfflineQuoteVerifier`.

No TPM quote contains a trusted wall-clock timestamp by default; observing
the v1 timestamp alone cannot establish the time the TPM signed the quote.
Freshness relies on independently issued unpredictable nonces and the durable
ledger. The v1 trust-anchor claim is *not* EK/AK certification. The two replay
ledgers commit independently, **not** as one distributed transaction; a partial
verification failure must be treated as terminal and is not retried.

The returned `LocalBindingAssessment` separates:

- `controller_signature_valid`, `quote_signature_valid`,
  `challenge_valid`, `pcr_digest_valid`,
  `replay_consumed_durably`, `binding_consistency_valid`.
- `AK_TRUST_UNVERIFIED`, `MEASURED_BOOT_POLICY_UNVERIFIED`,
  `VM_BINDING_UNVERIFIED`, `EXECUTION_DOMAIN_UNVERIFIED`.
- `independent_attestation_verified=false`,
  `guest_input_authorized=false`, `classification=NOT_INDEPENDENT`.

A fake or unsigned proposal, a local controller signature produced by the
runner, or a valid swtpm quote cannot be upgraded to independent attestation.
The remote v1 field `guest_attestation_verified_locally` remains **false**.
No input API, direct QMP, RFB client, Windows disk writer, ESP/BCD modification
or backend change is part of this contract.

## Adversarial verification and remaining requirements

The two new suites
`auto_tests/tests/test_observer_durable_quote_replay.py` and
`auto_tests/tests/test_observer_quote_binding.py` exercise duplicate
challenge/nonce/request IDs after restart, cross-process races, corruption,
missing/replaced files, symlinks/hardlinks, policy expiry and mixed
transactions, sessions, VMs, ISOs, policies and untrusted assertions.
The existing historical Q4OS and Observer tests are regression gates.
Test fixtures are **synthetic**, not new hardware/TPM/QEMU attestations.

The already approved genuine `swtpm` laboratory
[run #44891001738](https://github.com/LMhdez/gaslux/actions/runs/44891001738)
and [public artifact #14702161199](https://github.com/LMhdez/gaslux/actions/runs/44891001738/artifacts/14702161199)
remain the operational TPM evidence. This change does **not** require re-running
them or booting another QEMU VM.

Independent trust remains blocked pending: externally administered trust store,
validated EK and AK certification/activation, authenticated PCR reference policy
and measured-boot event-log replay, real VM/TPM/media association, independent
broker and evidence storage, replay-ledger anti-rollback witness, effective
session revocation, and human-reviewed separation from the GitHub runner.
Safety PR #267 owns the GPT/transaction consumer; Integrator PR #270 owns
architectural reconciliation. Neither branch is changed here.
