# Bazzite live ISO detached-signature gate (experimental)

**Status:** read-only lab contract. This does **not** install or boot Bazzite.

## Independent trust domains

1. **Atomic OCI:** existing `gaslux-bazzite-atomic-origin.yml` proves Cosign/attestation for a resolved GHCR image digest. That digest is **not** a bootable ISO digest.
2. **Live ISO:** `assets/live/gaslux_bazzite_iso_signature.py` checks a local regular ISO's exact caller-pinned **byte size and SHA-256**, ISO9660 volume header, local matching `.iso.sig` detached signature, and Cosign public key. The expected public-key SHA-256 must be independently pinned. Both pins must ultimately come from authenticated, signed Gaslux release metadata; the CLI does not verify that metadata.
3. **Installer identity:** still unverified. A signed ISO may contain a changed installer. An explicit version-pinned, read-only inspection of the exact ISO and booted guest is required.
4. **Installed system:** still unverified. OSTree/bootc deployment identity, original OCI image digest, Btrfs layout, EFI boot chain and first boot must be independently checked.

The official upstream `ublue-os/bazzite/.github/workflows/build_iso.yml` produces `*-live-amd64.iso`, a checksum, a detached Cosign signature, and a build attestation. This does **not** prove that signatures for a particular downloadable release are publicly obtainable. If the matching signature cannot be retrieved from an authenticated upstream source, refuse the ISO: do not substitute the plain checksum or copy an OCI signature. Check the upstream public-key provenance separately.

Cosign `verify-blob` here authenticates a *key-signed detached blob*; the flag `--insecure-ignore-tlog=true` only means no transparency-log attestation was asserted and must never be presented as one. The output permanently sets `transparencyAttestationVerified=false`, `installerIdentityVerified=false`, `nativeInstallationVerified=false`, and `installationAuthorized=false`.

The CI workflow creates an isolated synthetic 80 KiB ISO9660 fixture, generates a new ephemeral keypair, actually signs the fixture with Cosign, requires successful signature verification, tampers with the signature and checks rejection. The key is generated inside the GitHub runner, is **not** an official upstream signing key, is never committed, and never authorizes production.

## Boot and disk constraints

- Only UEFI/GPT is eligible even for this diagnostic. BIOS/MBR, BIOS/GPT, UEFI/MBR and unmeasured/on Secure Boot all fail before image I/O.
- Current official live installer provides automatic partitioning, not manual partitioning. The legacy Anaconda ISO has a different storage interface. Neither may be enabled for Gaslux until its exact version is safely automated and tested against real Windows QCOW2 disks.
- Do not invoke a native installer, `bootc install`, `rpm-ostree`, a disk writer, BCD, WinRE, EFI, NVRAM or a Linux deployment from this verifier.
- Never use the `stable` filename/tag as a release pin: filename and OCI tag are mutable. Require exact signature, trusted upstream key and immutable SHA-256/size.
- Keep `release-config.json` and the production installer untouched.

## Remaining minimum acceptance

1. Independently verify the specific official ISO's detached signature, externally pinned size and digest; inspect its installer source, volume labels, EFI boot chain and declared payload (without guessing).
2. Boot that exact ISO in an OVMF disposable guest without disks; verify actual installer and supported unattended operation.
3. Provision a separate *owned* QCOW2 test target and complete native Atomic deployment; prove independent disk-only first boot, update and deployment rollback.
4. Use a genuine Windows 10/11 UEFI/GPT guest on the same disposable QCOW2 with independently checked EFI/BCD/WinRE, Windows boot before/after, installation failure recovery, reinstall and removal.
5. Obtain human review and release evidence before changing the stable distribution catalogue.

References:

- https://github.com/ublue-os/bazzite/blob/main/.github/workflows/build_iso.yml
- https://github.com/ublue-os/bazzite/blob/main/cosign.pub
- https://docs.bazzite.gg/General/Installation_Guide/install-guide/
- https://docs.bazzite.gg/General/Installation_Guide/legacy-install/
- https://github.com/ublue-os/bazzite/issues/4918
