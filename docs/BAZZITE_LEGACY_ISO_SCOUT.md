# Bazzite legacy ISO investigation — 18 November 2026

Status: **experimental, laboratory-only**. A complete ISO byte hash has been
checked against the earlier CDN discovery value, but no independent immutable
upstream signature or GitHub attestation has been verified. Bazzite installation
is **not authorized**.

## Checked official-domain legacy ISO bytes (18 November 2026)

- [Actions #44358709061](https://github.com/LMhdez/gaslux/actions/runs/44358709061):
  both `contracts` and `pinned-media-bytes` **SUCCESS** on
  [commit 928634d2](https://github.com/LMhdez/gaslux/commit/928634d2ba392ddb2fbee91f2ac2065fc2d20b19).
- The exact downloaded `bazzite-stable-amd64.iso` had **7,907,770,368 bytes**
  and SHA-256 `9c8d06cd8e57f2274678edeb14b4b13a79b8117c70571a65199919a66305b5c7`.
  Its EFI El Torito boot metadata was independently inspected by `xorriso`.
- The job returned `officialGithubAttestationVerified=false` and
  `detachedCosignSignatureVerified=false`. The earlier CDN checksum came
  from the same mutable origin and is **not** an independent trust anchor.
- The digest is a **lab observation pin**, not a signed release pin.
  `catalogPinAuthorized`, `installationAuthorized`, and
  `windowsEspWriteAuthorized` remain false.

### Quarantined diskless OVMF research

The experimental workflow
[`gaslux-bazzite-legacy-diskless-ovmf.yml`](../.github/workflows/gaslux-bazzite-legacy-diskless-ovmf.yml)
checks the lab bytes again, then runs the ISO with **only read-only optical
media**, private disposable OVMF variables, 8 GiB guest RAM, no attached
hard disk, no guest network and no automated keyboard/mouse input. It saves
bounded screenshots/OCR for independent inspection. Even an accepted
screenshot must not be conflated with Anaconda/Blivet installation, a
disk-write authorization or Windows ESP preservation. Unsigned/unattested
legacy ISO execution is restricted to this short-lived isolated lab.

## Actual diskless ISO welcome screen (18 November 2026)

- [GitHub Actions #44364282815](https://github.com/LMhdez/gaslux/actions/runs/44364282815):
  **SUCCESS** on commit `44255598`. An 8-GiB KVM/OVMF guest was observed
  without any hard disk, network adapter, scripted input or Windows device.
  Four nonblank screenshots were collected.
- [Independent OCR Actions #44367448297](https://github.com/LMhdez/gaslux/actions/runs/44367448297):
  **SUCCESS**. Screenshot phase 1 contains Linux/systemd startup text;
  phases 2–4 independently show **BAZZITE 42 INSTALLATION** and
  **WELCOME TO BAZZITE 42**, with the installation language picker.
  [Evidence #14456692397](https://github.com/LMhdez/gaslux/actions/runs/44367448297/artifacts/14456692397).
- This establishes visual evidence of a **legacy installer welcome screen**,
  not the Anaconda executable's validated identity, Blivet-GUI availability,
  a disk write, Atomic deployment or Linux first boot after installation.
- **Important version ambiguity:** the installer advertises `42`, while
  [official Bazzite releases](https://github.com/ublue-os/bazzite/releases)
  include `45.20261117.1`. The installed payload/version is **not bound**
  to the banner or a signed catalogue record. Never silently assume that
  the old legacy media installs/updates to the current upstream release.

The next candidate milestone is independent authentication of a currently
supported legacy ISO and a **strictly no-write** exploration of the native
storage/Blivet screen on authenticated runner-owned virtual media. No Windows
disk may be attached or written until signed ownership, exact guest identity
and transaction rollback have been established.

## Why this separate experiment exists

The official Bazzite legacy installer documentation still describes
Anaconda/Blivet advanced custom partitioning and Btrfs root, whereas the
new live installer shown in Gaslux PR #208 defaults to **Use entire disk**.
The current website download picker code observed 18 November 2026 has
links for stable **live** ISOs but does not itself expose a legacy download
button. A historical candidate URL on the official domain is:

- https://download.bazzite.gg/bazzite-stable-amd64.iso

Treat this as a **candidate**, not a verified published release. A successful
HTTP response and a checksum from the same mutable CDN do NOT authenticate
the ISO or authorize a release pin. The upstream ISO may be unavailable.

Official upstream documentation:
- https://docs.bazzite.gg/General/Installation_Guide/legacy-install/
- https://docs.bazzite.gg/General/Installation_Guide/manual_partitioning/
- https://docs.bazzite.gg/General/Installation_Guide/dual_boot_setup_guide/
- https://github.com/ublue-os/bazzite.gg/blob/main/content/themes/betheme-child/script136.js

## Safety contract

The CI scout requests **only HTTP HEAD** for the ISO, checksum and detached
signature candidate, and may retrieve the checksum text capped to 4096 bytes.
It does not fetch the ISO, use QEMU, attach a guest disk, execute Anaconda,
write EFI/NVRAM, create partitions or touch any Windows media.

The Python policy gate rejects BIOS/MBR, BIOS/GPT, UEFI/MBR and enabled or
unknown Secure Boot. It accepts only the exact official-domain candidate URL
and one unambiguous checksum record naming the exact legacy ISO. A positive
result is still explicitly **untrusted CDN metadata**, not cryptographic media
verification.

A separate static **hypothetical** Blivet layout check requires:
- distinct Windows ESP, owned Linux ESP, owned ext4 /boot and owned Btrfs root
  PARTUUIDs, plus a transaction identifier;
- Windows ESP action **preserve / no mount / no format**;
- UEFI/GPT with Secure Boot off.

Static acceptance does NOT authenticate a physical disk, predict the Anaconda
write set or prove Windows EFI preservation. The new Bazzite installer,
legacy Anaconda installer, rpm-ostree/bootc deployment and OCI signatures are
different evidence boundaries, never interchangeable.

## Preconditions before any guest storage write

1. Obtain an official immutable legacy ISO provenance record, an independently
   trusted SHA-256 and exact size. If available, independently verify the
   detached signature against the independently pinned upstream public key.
   Never manufacture a hash, inherit the *live* ISO hash or promote metadata
   from the same mutable URL to an independent trust anchor.
2. Boot the exact verified ISO in isolated UEFI/OVMF with no target disk and
   verify actual legacy Anaconda identity and Blivet availability.
3. Use exclusively a newly created, owned, disposable QCOW2 with a signed plan,
   durable snapshot, exact backing/guest disk identity and pre/post-write audits.
   Never attach the Windows QCOW2 until a constrained write set is proven.
4. Prove installed Atomic system first boot **without ISO**, deployment and
   bootloader updates/rollback, then Windows 10/11 shared-disk coexistence,
   EFI/BCD/WinRE integrity, reinstall and uninstall in snapshot-backed VMs.
5. Do not enroll MOK, change Secure Boot keys, bypass BitLocker or change firmware.
   Bazzite remains unavailable in the stable Gaslux catalogue.

Related experimental work: PR #179 (signed new live ISO), PR #208 (blank
QCOW2 new installer storage discovery), PR #21 (read-only Atomic preflight).
