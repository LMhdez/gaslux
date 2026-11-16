# Bazzite — Fedora Atomic backend workstream

**Status: lab-only preflight, not an installer.** Independent of CachyOS.
Requires `feature/multidistro-lab-media-probe` as shared, read-only base.

## Independent restrictions

- **UEFI/GPT only.** Reject BIOS/MBR, BIOS/GPT and UEFI/MBR before reading
  the ISO and well before any storage or boot write.
- **No unattended Secure Boot enrollment.** Bazzite supports MOK
  enrollment upstream, but this Gaslux diagnostic refuses Secure Boot on
  until an explicitly validated, user-consented unattended strategy is
  implemented. Do not change firmware keys or Secure Boot automatically.
- Require at least 8 GiB RAM and 50 GiB selected Linux space as conservative
  preliminary laboratory policy; final resource values must follow the
  exact signed distribution release and complete integration evidence.
- Require Btrfs as the Atomic root target. Reject ext4 and attempts to run
  Debian squashfs extraction or Arch pacstrap.
- Historic Bazzite live `os-release` can report `ID=fedora` rather than
  `ID=bazzite`. Require an additional Bazzite label and exact,
  version-specific ISO verification. An os-release label by itself is
  insufficient evidence of Bazzite identity. Signed catalogue v2's
  `osReleaseId=bazzite` currently needs reconciliation against real
  images before release; do not bypass the mismatch.

## Unimplemented

Native installer and custom partition layout capability (especially the
current new-installer manual-partitioning limitation), authenticated
handoff, Atomic ostree/bootc image deployment, EFI bootloader,
updates/rollback ownership, Windows coexistence, Windows first boot,
uninstall and host-independent Windows recovery evidence.

Only disposable QEMU/OVMF virtual disks may be used for future writing
tests with explicit authorization and verified snapshots. The current
synthetic tests do not install or boot Bazzite.

Upstream references:
- https://docs.bazzite.gg/General/Installation_Guide/legacy-install/
- https://docs.bazzite.gg/General/Installation_Guide/troubleshoot_guide/
- https://docs.bazzite.gg/General/FAQ/
