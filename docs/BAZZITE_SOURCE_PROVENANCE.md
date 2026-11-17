# Bazzite 2026: Atomic OCI trust vs installable ISO trust

This branch adds a read-only check for official Bazzite Atomic OCI metadata.
It is **not** an ISO download, install, boot, or a valid proof that the new
live installer supports unattended native partitioned Windows coexistence.

The upstream public key copied into `assets/keys/bazzite-upstream-cosign.pub`
is from:
https://github.com/ublue-os/bazzite/blob/main/cosign.pub

It verifies the official `ghcr.io/ublue-os/bazzite:stable` signature using
Cosign, then independently checks its GitHub provenance attestation via
`gh attestation verify --repo ublue-os/bazzite`. Both must succeed.
The `stable` tag is intentionally mutable, so CI must report the **resolved
digest** for any candidate; no release metadata may pin the tag alone.

The upstream Bazzite installer documentation says its new installer lacks
manual partitioning; dedicated Windows dual-boot has additional restrictions.
The older ISO is a **separate source format** and must not be conflated with
new-installer bootc media or its OCI image digest.

The Linux target must eventually verify independent EFI ownership, Btrfs and
Atomic deployment identity, rollback and kernel updates. No Windows/BCD/ESP/
WinRE disk writes are performed by the OCI provenance verification.

Upstream references:
- https://github.com/ublue-os/bazzite/blob/main/cosign.pub
- https://docs.bazzite.gg/General/Installation_Guide/install-guide/
- https://docs.bazzite.gg/General/Installation_Guide/legacy-install/
- https://universal-blue.discourse.group/t/bazzites-biggest-update-deck-44-has-launched-happy-birthday-to-universal-blue/12373
