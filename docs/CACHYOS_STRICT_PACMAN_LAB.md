# Strict Pacman VM-lab candidate for pinned CachyOS 260809

**This change is experimental and restricted to disposable QEMU/KVM guests.**
It does not authorize partitioning Windows, production installation or release.

The independently measured SHA-pinned 260809 official ISO has a weak
`[cachyos]` repository signature policy (see
[Actions #43934974693](https://github.com/LMhdez/gaslux/actions/runs/43934974693)).
The isolated CachyOS stage must **never copy** its live
`/etc/pacman.conf` into the installed target.

`assets/live/cachyos-strict-pacman.py` builds a deterministic alternative:

- Allows exactly `core`, `extra` and `cachyos`; each requires
  `SigLevel = Required DatabaseOptional TrustedOnly`.
- Requires signed local and remote packages; no `Optional`, `TrustAll`
  or signature-skip options.
- Derives mirror URLs only from the verified CachyOS live filesystem;
  filters out HTTP/FTP and rejects unsafe or ambiguous active directives.
- Generates a separate installer configuration and a stable target
  configuration with the same repository/signature policy.
- In `--prepare-vm` mode, refuses non-QEMU systems, requires explicit
  lab consent, and writes exclusively into a freshly created directory
  on an actual `/run` tmpfs. It never writes to a disk itself.
- The experimental stage calls `pacman-conf` via the shared trust guard
  on the alternate config, then invokes `pacstrap -K -C`, and retains
  the exact signed-only repository policy on the installed system.
  Package-signature verification cannot be disabled to make a test pass.

The real ISO's package signatures and repository trust chains have NOT been
successfully exercised through this alternate policy, and no installed
CachyOS guest has yet booted. An unsigned package should make pacstrap
fail, not be accepted. The installer still has no production-authenticated
Windows plan, full EFI/BCD/WinRE rollback or tested first boot.

Source references:
- https://man.archlinux.org/man/pacstrap.8.en.html
- https://man.archlinux.org/man/pacman.conf.5
- https://github.com/LMhdez/gaslux/issues/3
