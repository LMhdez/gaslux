# Bazzite official ISO public readback

This workflow performs a bounded, read-only verification of the pinned Bazzite
45.20261117.1 live ISO and the Atomic OCI payload embedded in its live
SquashFS. It is deliberately separate from installation and write-set
authorization.

## Workflow

- Workflow: `.github/workflows/bazzite-iso-public-readback.yml`
- Triggers: manual dispatch, or push to the dedicated Bazzite PR branch when
  the workflow, pinned key, or readback validator changes.
- Public objects: the ISO, detached `.sig`, metadata `.json`, and
  `-CHECKSUM` sidecar from `https://download.bazzite.gg/`.
- Cosign for ISO detached signature: upstream-compatible `v2.6.5`,
  installed through the upstream pinned cosign-installer action commit.
- Cosign for OCI payload signature: upstream-compatible `v3.1.3`, installed
  into a separate directory through the same pinned installer action. The
  payload build workflow uses this version and
  `build.py sign` explicitly selects the legacy bundle format; payload
  verification uses `--new-bundle-format=false`.
- Key: `assets/live/bazzite_cosign_20261120.pub`, byte-compared with the
  key at the upstream key-introduction commit. Both PEM and SPKI SHA-256
  fingerprints are checked; the introducing Git commit must be GitHub-verified.
- GitHub provenance: `gh attestation verify` enforces repository,
  SLSA provenance predicate, signer workflow, source ref, source commit,
  and GitHub-hosted runner identity for both ISO and OCI payload.
- Build metadata: the exact upstream ISO and OCI build run IDs, workflow paths,
  source commit, and version release tag are independently checked through
  the GitHub API.
- Embedded payload: the ISO is loop-mounted with `ro,nosuid,nodev,noexec`.
  `unsquashfs` reads `LiveOS/squashfs.img` without booting the ISO or
  extracting/writing the ISO itself. The embedded containers/storage image
  entry, raw manifest, and config blob must match the pinned manifest and
  config digests.

## Evidence and failure policy

The workflow uploads text-only evidence: measured ISO size and SHA-256,
downloaded text sidecars, verification output, build metadata, and the
embedded OCI manifest/config identity. The ISO and payload binaries are never
uploaded as workflow artifacts.

Any unavailable endpoint, digest mismatch, missing attestation, untrusted
signer, wrong workflow/source commit, missing embedded metadata, or unsupported
SquashFS/container-store layout leaves Result B and fails the final gate.
The report always states `installationAuthorized=false`.

A successful Result A proves only this ISO/payload provenance chain. It does
not prove the Anaconda write-set, GPT/ESP ownership, EFI/NVRAM behavior,
Windows preservation, first boot, updates, or rollback. Those independent
Safety and Observer gates remain mandatory.

Bazzite remains UEFI/GPT-only. BIOS/MBR, ISO boot, Anaconda execution,
partition writes, EFI writes, NVRAM writes, Secure Boot key changes, and
installation are outside this workflow and are not authorized by it.

## Verified readback — 20 November 2026

- [Actions #44759529218](https://github.com/LMhdez/gaslux/actions/runs/44759529218)
  completed **SUCCESS** on HEAD `0ae92174a3acbc305aa3bbcc50986cfbcdcf34b6`.
  Its final step refuses anything other than Result A and checks all earlier
  attestation, signature, raw OCI config and embedded-manifest gates.
- Evidence artifact [#14641606769](https://github.com/LMhdez/gaslux/actions/runs/44759529218/artifacts/14641606769)
  contains text reports; no ISO or OCI binary is published.
- The pinned signed ISO is linked to the signed OCI manifest/config by exact
  readback of the containers/storage manifest inside the ISO. The ISO SLSA
  statement itself does **not** independently declare the payload digest;
  this is why `isoAttestationResolvedPayloadDigestIndependentlyVerified`
  remains false in the evidence ledger. The upstream key has no independently
  verified out-of-band fingerprint.
- The ledger's Result A is **provenance-only**. The ISO has not been booted in
  this workflow; the Anaconda/Blivet action graph, GPT metadata writes, Windows
  ESP protection, NVRAM writes, deployment, kernel updates, dual boot and
  recovery remain unverified. Installation and stable catalog are denied.
- The synthetic Anaconda action-comparison gate now checks ESP ownership flags,
  boot/ESP roles and exact sizes, alignment, the trailing root extent and
  the prerequisite recovery/metadata gates. It does not equate a synthetic
  match with a live, authenticated Anaconda action capture.
