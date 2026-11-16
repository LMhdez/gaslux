# Gaslux: parallel candidate media probes

These are **read-only diagnostic modules** for three candidate backends, independent
of the existing CachyOS development chain. They are not part of the installed
Windows application, signed catalogue, live installer dispatch or disk writer.

## Strict scope

- Reject unsupported firmware/layout combinations before reading an image.
- Reject missing, symlinked, replaced, incorrectly sized or incorrectly hashed
  local ISO files. Check an ISO9660 primary volume descriptor as a minimal
  format sanity check. This does **not** establish complete ISO identity.
- Parse an independently supplied os-release evidence file and compare its
  exact `ID` to a backend policy. **The file is not proven to have originated
  from the ISO**. A complete backend must extract and authenticate the actual
  live image and capture that relationship independently.
- Return `installationAuthorized: false` and `signedCatalogVerified: false`
  even after a passing diagnostic, because only the existing signed catalogue
  path may authorize any release installation.

No API here mounts a volume, executes an installer, invokes an OS package
manager, modifies partitions, touches NVRAM or runs a bootloader command.
Only synthetic temporary ISO files are used by CI.

## Independent workstreams

- Pop!_OS: System76-specific ISO identity and systemd-boot/GRUB policy,
  explicitly refuse Secure Boot enabled.
- Q4OS: distinguish native live/installer media from the Windows-folder
  setup program and require a verified Calamares/native installer environment
  before any plan can be wired to a backend.
- Bazzite: Fedora Atomic/bootc/OSTree-specific provisioning still to be
  implemented; BIOS/MBR must fail before even reading the ISO, and the
  policy must not promise unattended MOK enrollment or unsupported installer
  partitioning.

These probes are independent of CachyOS, but ultimately depend on
a reviewed signed-capabilities contract and backend-specific transaction
integration before any installation is possible.

References:
- https://support.system76.com/support/install-pop
- https://support.system76.com/support/bootloader
- https://q4os.org/blog.html
- https://docs.bazzite.gg/General/Installation_Guide/legacy-install/
- https://docs.bazzite.gg/General/Installation_Guide/troubleshoot_guide/
