# CachyOS 260809 pinned-ISO package signature audit

**Status: read-only experimental repository-policy evidence. Not an installer.**

The actual SHA-256-pinned CachyOS Archiso image is mounted read-only.
Its `airootfs.sfs` is mounted separately read-only and checked to originate
from the correct ISO file. The ISO's **own** `pacman-conf` is executed through
a read-only chroot. The exact effective package-signature policy is evaluated
by `assets/live/cachyos-pacman-trust.py` (PR #24). No INI-parser guesswork.

If an active CachyOS repository allows unsigned packages or uses `TrustAll`,
the step fails closed before running any `pacstrap`. The JSON failure report
is uploaded as a workflow artifact for review. There is no automatic
weak-signature override, key import, package download or disk formatting.

The current upstream Live-ISO source has `SigLevel = Optional TrustAll`
in its CachyOS repository, but that **does not establish** what the separately
hash-pinned 260809 ISO actually contains. This CI run measures those bytes.

A successful audit would establish only the ISO's package-policy *settings*,
not verification of packages/keyring trust, installed-root boot, Windows
boot or Windows recovery. Passing the audit would NOT authorize a production
install: real target ownership, authenticated Windows handoff and VM snapshot
recovery must still be tested independently.

References:
- https://github.com/CachyOS/CachyOS-Live-ISO/blob/master/archiso/airootfs/etc/pacman.conf
- https://man.archlinux.org/man/pacman.conf.5
- https://github.com/LMhdez/gaslux/issues/3
