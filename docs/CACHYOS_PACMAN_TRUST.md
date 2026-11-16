# CachyOS pacman signature policy gate (experimental)

**Not released. No real-disk installation is authorized.**

The CachyOS target stage calls `pacstrap -K`, and later retains
`/etc/pacman.conf` for installed-system package updates. This cannot be
considered safe merely because the live ISO has a verified SHA-256: a
verified live image can still contain a repository configuration that
accepts unsigned packages.

The current upstream CachyOS Live-ISO `archiso/airootfs/etc/pacman.conf`
contains a repository-level `SigLevel = Optional TrustAll` for `[cachyos]`.
This is a **source-level risk to investigate for each pinned ISO**, not
yet a measured finding about the exact 260809 archive. It cannot be
accepted unchanged by the production Gaslux installation backend.

Sources:
- https://github.com/CachyOS/CachyOS-Live-ISO/blob/master/archiso/airootfs/etc/pacman.conf
- https://man.archlinux.org/man/pacman.conf.5.en
- https://man.archlinux.org/man/pacman-conf.8

## Implementation

`assets/live/cachyos-pacman-trust.py` is a read-only, fail-closed guard:

- Runs `pacman-conf --config FILE` to resolve Pacman's own effective
  configuration, including inherited `SigLevel` values and includes,
  instead of approximating Pacman's parser.
- Rejects all optional, disabled, weak-trust or unknown signature flags,
  including `Optional`, `PackageOptional`, `Never`, `TrustAll`,
  `PackageTrustAll` and `DatabaseNever`.
- Requires mandatory trusted **package** signatures on every active
  repository and the presence of `core`, `extra` and `cachyos`.
  `DatabaseOptional` alone remains permitted when package signatures
  are mandatory, matching Arch's normal policy.
- Rejects ambiguous repository names, duplicates, missing configuration,
  symlinks and failures of the actual `pacman-conf` subprocess.
- Reports an audit digest of the inspected configuration and does
  not claim Windows or hardware installation stability.

`assets/live/cachyos-stage-target.sh` now calls the guard before
`pacstrap` and repeats the check on the installed target's
`pacman.conf` before account and boot configuration. The policy script
must be provisioned from trusted, versioned backend assets and owned by
root; it is deliberately not downloaded dynamically.

`--check` remains **read-only** and does not perform a package
installation. The installer remains restricted to explicitly authorized
QEMU/KVM guests. This branch is not connected to the Windows UI or
production distribution catalogue.

## Evidence and limits

The Python regression suite uses mocked `pacman-conf` output, including
adversarial Optional/TrustAll/missing/duplicate/malicious repo cases.
It is **not** proof that any CachyOS pacstrap transaction successfully
downloaded, installed or verified the final package inventory. The
effective signature policy and keyring state of the exact official
260809 live ISO still need independent audit. Weak configurations
must be rejected before any guest disk writes, not silently overridden
or accepted. The next target installation experiment must use a
separately mounted **disposable VM-owned Linux root disk**, independent
Windows guest snapshots and a signed authenticated handoff.

No hashes, signatures or trusted repository configurations have been
invented or installed by this change. PR #10's authenticated handoff
and issue #3's Windows 10/11 recovery requirements remain mandatory.
