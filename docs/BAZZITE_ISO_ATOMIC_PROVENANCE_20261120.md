# Bazzite official ISO and Atomic payload provenance — 2026-11-20

## Decision

**Result B — keep installation denied.** The official Bazzite build pipeline has
a real detached Cosign ISO signature and GitHub/Sigstore build-provenance
attestation. A current stable Bazzite 45 ISO candidate and its corresponding
OCI payload can be correlated to the same image configuration in the official
workflow logs. This is materially stronger than the previously investigated
legacy Bazzite 42 ISO.

However, this intervention did not read back the published ISO bytes or its
`.sig`/`.json` sidecars from the public R2 download endpoint, did not obtain
the exact ISO byte length, did not run `cosign verify-blob` or
`gh attestation verify` against the actual ISO file, and did not extract the
embedded OCI image from the ISO. The signed provenance statement itself was
not downloaded for independent predicate inspection. Therefore the public
artifact identity and the ISO-to-payload relationship have not been
end-to-end verified by Gaslux. **Do not promote this candidate or authorize
installation.**

This is an evidence/read-back limitation, not a failed implementation of
Cosign or GitHub provenance.

## Official source and trust key

Repository: [ublue-os/bazzite](https://github.com/ublue-os/bazzite).

The ISO build workflow at source commit
`5d71c4376169910c25bc06a3537f4780521e7435` is
[.github/workflows/build_iso.yml](https://github.com/ublue-os/bazzite/blob/5d71c4376169910c25bc06a3537f4780521e7435/.github/workflows/build_iso.yml).
Its signing step uses `SIGNING_KEY: secrets.SIGNING_SECRET` and runs
`cosign sign-blob` to create `<iso>.sig`. It then invokes
`actions/attest-build-provenance` and uploads the ISO, checksum, signature
and attestation metadata to `R2:bazzite`.

The OCI build workflow at the same source commit sets
`COSIGN_PRIVATE_KEY: secrets.SIGNING_SECRET`. The ISO and OCI workflows
therefore use the same upstream signing secret.

The corresponding public key is
[cosign.pub](https://github.com/ublue-os/bazzite/blob/main/cosign.pub):

| Identity | Value |
| --- | --- |
| Repository file blob SHA | `bd5b1927189e8af5566a8ff399c46cbf7085d3b1` |
| SHA-256 of PEM file bytes | `af78ecfda6eb21c35195af3739341715e9cfc3f2f5911dd9c10b0670547bf6e8` |
| SHA-256 of DER SubjectPublicKeyInfo | `efaae036a5afefcfe2c64686db0311ab64e57ae794be634d80c25286695336a6` |
| Algorithm | ECDSA P-256 |
| Key-introduction commit | `f8580007fb1fb4241378fd99b33800aefe62c3b5` |
| Commit verification | GitHub reports `verified=true`, `reason=valid` |
| Commit author | Benjamin Sherman, 2024-07-02 |

The fingerprint above is computed from the public key in the official
repository; it is not represented as a separately published out-of-band
fingerprint. Trust bootstrap is the GitHub-verified key-introduction commit
and the official release-signing workflow, not the ISO download directory.

As a separate confirmation of key use, release
[45.20261117.1](https://github.com/ublue-os/bazzite/releases/tag/45.20261117.1)
contains `packages.json`, `packages.json.sig` and
`packages.json.sigstore.json`. The release workflow ran
`cosign sign-blob` and `cosign verify-blob --key cosign.pub`; the verification
reported `Verified OK`, and all three assets were uploaded. These are
release-manifest assets, **not** the ISO signature.

## ISO candidate: stable Bazzite 45, x86_64

Official ISO build:
[Actions #44121421800](https://github.com/ublue-os/bazzite/actions/runs/44121421800).

- Source commit: `5d71c4376169910c25bc06a3537f4780521e7435`
- Workflow: `.github/workflows/build_iso.yml`
- Job: `build-iso (bazzite)`, job ID `134173618964`
- ISO name: `bazzite-stable-live-amd64.iso`
- Build SHA-256: `6120b6edc2d87e7bdccf8dfddc8b156552cd50b152cb0a9e9dedb37fb947cbe5`
- Exact byte length: **not available in the accessible run evidence**
- Build result: SUCCESS
- `Sign ISO`: SUCCESS; log says the detached `.sig` was written
- `Attest Build Provenance`: SUCCESS
- GitHub attestation: [#68711578](https://github.com/ublue-os/bazzite/attestations/68711578)
- Sigstore Rekor log index: `3949128808`
- Attestation subject: the ISO SHA-256 above
- Certificate identity: `https://github.com/ublue-os/bazzite/.github/workflows/build_iso.yml@refs/heads/main`
- Certificate binds workflow run `44121421800` and source commit `5d71c437...`
- R2 upload step: SUCCESS. First attempt logged HTTP 501 for the ISO, checksum,
  `.sig` and `.json`; the rclone retry reported `Attempt 2/3 succeeded`.
- GitHub job-artifact upload: SKIPPED on `main`; no ISO artifact is attached
  to the Actions run.

The R2 step's successful conclusion establishes that the official workflow
completed its retry. It is not an independent read-back of the four public
objects. This session could not fetch the public download objects through the
available network/browser transport, so it cannot claim that the current
website URL returns this exact SHA or that the sidecars can be retrieved.

The previous report's legacy Bazzite 42 ISO
`9c8d06cd8e57f2274678edeb14b4b13a79b8117c70571a65199919a66305b5c7`
remains a separate, unauthenticated artifact. Do not transfer the new ISO's
signature or attestation to that old file.

## Payload candidate: exact official OCI digest

Official image build:
[Actions #44115557508](https://github.com/ublue-os/bazzite/actions/runs/44115557508).

- Release: `45.20261117.1`
- Job: `Make (bazzite, 45, ... x86_64)`, job ID `134153219650`
- Tag published: `ghcr.io/ublue-os/bazzite:stable-45.20261117.1`
- Stable alias published by the same job: `ghcr.io/ublue-os/bazzite:stable`
- Immutable OCI image digest: `sha256:492f83c738838861464685aed341783c2ea2266c82a9f19f0c867fd301783fd4`
- OCI config digest: `sha256:938000b71e57a251c3720e90ad7422b6636b1cbcbecc928479c0a8f32350badb`
- Cosign image signing: SUCCESS, using `COSIGN_PRIVATE_KEY` from
  `secrets.SIGNING_SECRET`
- GitHub build-provenance attestation:
  [#68695561](https://github.com/ublue-os/bazzite/attestations/68695561)
- Sigstore Rekor log index: `3948558954`
- Attestation subject digest: the OCI digest above
- Certificate identity:
  `https://github.com/ublue-os/bazzite/.github/workflows/build.yml@refs/heads/main`
- Certificate binds workflow run `44115557508` and source commit
  `5d71c437...`

## Build-time ISO → payload correlation

The exact ISO build run sets both
`BASE_IMAGE` and `INSTALL_IMAGE_PAYLOAD` to
`ghcr.io/ublue-os/bazzite:stable`.

At source commit `5d71c437...`:

1. `installer/Containerfile` accepts `INSTALL_IMAGE_PAYLOAD` and passes it
   to `installer/build.sh`.
2. `installer/build.sh` either saves that image from the container store or
   executes `podman pull "$INSTALL_IMAGE_PAYLOAD"`.
3. The Bazzite 45 image build run published the immutable digest
   `sha256:492f83...` under the `stable` tag.
4. The image build log records config digest
   `sha256:938000...` while pushing that immutable digest.
5. The ISO build log records `podman pull ghcr.io/ublue-os/bazzite:stable`
   and the same config digest `sha256:938000...`.

This is a strong build-log correlation to the signed OCI payload, and it
confirms that the ISO build consumed the same OCI image configuration/rootfs
identity as the image build. It is not yet a complete independently
verifiable binding of the final ISO bytes to the OCI manifest digest:
the ISO was not read back, its embedded container storage was not extracted,
and the GitHub provenance predicate was not independently inspected to
confirm that it lists the OCI digest as a resolved material. Do not promote
the config digest as if it were the OCI manifest digest.

## Candidate evidence manifest

| Field | Value |
| --- | --- |
| Artifact | `bazzite-stable-live-amd64.iso` |
| Version/channel | `45.20261117.1 / stable` |
| Architecture | `x86_64` |
| Firmware/table supported by Gaslux | UEFI/GPT only; not BIOS/MBR |
| ISO SHA-256 from official build | `6120b6edc2d87e7bdccf8dfddc8b156552cd50b152cb0a9e9dedb37fb947cbe5` |
| ISO size in bytes | **Unknown — local/public read-back required** |
| Signing key fingerprint (SPKI SHA-256) | `efaae036a5afefcfe2c64686db0311ab64e57ae794be634d80c25286695336a6` |
| ISO authentication method | Cosign detached `.sig` plus GitHub/Sigstore build provenance |
| ISO attestation | `68711578`, Rekor `3949128808` |
| Payload image | `ghcr.io/ublue-os/bazzite` |
| Payload version | `45.20261117.1` |
| Payload OCI digest | `sha256:492f83c738838861464685aed341783c2ea2266c82a9f19f0c867fd301783fd4` |
| Payload config digest | `sha256:938000b71e57a251c3720e90ad7422b6636b1cbcbecc928479c0a8f32350badb` |
| Payload authentication | Cosign image signature plus GitHub/Sigstore provenance |
| Payload attestation | `68695561`, Rekor `3948558954` |
| ISO/payload link | Build-time config-digest cross-match; final ISO content not read back |
| Public ISO/sidecar read-back | Not verified in this session |
| Support state | Official stable build candidate; Gaslux compatibility unverified |
| Result | **B — refuse promotion and installation** |
| `installationAuthorized` | **false** |

## Public readback update — Actions #44751586997

A first execution of the dedicated readback workflow downloaded the official
public ISO and all three sidecars. The runner measured the ISO at exactly
**8,377,878,528 bytes** and recalculated SHA-256
`6120b6edc2d87e7bdccf8dfddc8b156552cd50b152cb0a9e9dedb37fb947cbe5`,
matching the pinned upstream build subject. The downloaded
`-CHECKSUM` sidecar matched. Cosign `v2.6.5` verified the detached
signature with the key pinned above. The downloaded metadata JSON identified
attestation #68711578.

Evidence artifact:
[Actions #44751586997 / artifact #14635702681](https://github.com/LMhdez/gaslux/actions/runs/44751586997/artifacts/14635702681).

The run stopped at GitHub attestation verification because the workflow
initially supplied the mutually exclusive GitHub CLI flags `--signer-repo`
and `--signer-workflow` together. This is a command-line policy configuration
error, not a reported invalid signature or missing attestation. The workflow
was corrected to enforce the exact signer workflow without the conflicting
flag. Consequently, this run proves public byte readback, checksum and
detached Cosign signature only; it does **not** yet prove the GitHub
attestation or the embedded OCI manifest/config relationship. Result remains
B and installation remains denied.

## Required closure evidence

Before changing Result B to A:

1. Read back the official current ISO, `.sig`, `.json` attestation metadata
   and checksum from the public download endpoint. Record exact byte length
   and recompute SHA-256; it must equal the attested ISO subject digest.
2. Verify the detached signature with the pinned official `cosign.pub`
   using `cosign verify-blob`; independently verify the ISO's GitHub
   attestation with `gh attestation verify` against repository
   `ublue-os/bazzite`. Record verified workflow identity, source commit,
   subject digest and transparency proof.
3. Inspect the ISO read-only and extract the embedded payload container
   identity. Verify its immutable OCI manifest digest and config digest.
   The expected payload is exactly
   `ghcr.io/ublue-os/bazzite@sha256:492f83...`, with config digest
   `sha256:938000...`.
4. Verify the payload's Cosign signature and GitHub attestation independently.
5. Reject if the current public ISO differs from the attested build SHA, if
   any sidecar is absent/invalid, if payload identity differs, or if any
   provenance statement does not bind the expected repository/workflow.
6. Keep `installationAuthorized=false` regardless of provenance success;
   the Anaconda live collector, write-set, EFI/NVRAM and installation gates
   remain separate blockers.

No installation, guest boot, partition write, EFI/NVRAM write, Safety or
Observer change was made during this investigation.
