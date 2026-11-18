# Bazzite legacy ISO investigation — 18 November 2026

Status: **experimental, discovery-only**. No independent immutable SHA-256/size
pin for a genuine legacy ISO has yet been established. Bazzite installation is
**not authorized**, even if a CDN checksum is obtained.

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
