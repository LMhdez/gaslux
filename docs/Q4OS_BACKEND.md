# Q4OS — native partitioned installation workstream

**Status: experimental. Pinned ISO and two installed-root QEMU boots are proven; full Calamares and Windows dual boot are not.**
Independent of CachyOS. Stacked only on shared lab-media preflight.

Q4OS 6.10 Andromeda was announced as the updated stable release on
8 October 2026. It is based on Debian 13 Trixie. The native Q4OS live
media uses Calamares. The distinct **Q4OS for Windows** program installs
into a Windows filesystem folder: that is *not* the Gaslux native
partitioned installation model.

## Important identity mismatch

Unlike the existing `osReleaseId=q4os` assumption in the draft signed
catalogue v2 policy, Q4OS 6.9 evidence shows `ID=debian` in
`/etc/os-release`. Q4OS identity requires independently checked
Q4OS-specific version evidence (e.g. `/etc/q4os_version`) **from the
same verified native ISO**, plus a real Calamares installation payload.
This early module refuses missing/malformed version evidence, and
reports that ISO-to-live identity binding is **not yet proven**.

The current probe conservatively rejects Secure Boot enabled until
the exact native image signing chain is independently verified; this
does not claim Q4OS itself lacks Secure Boot support.

## Support boundaries

- BIOS/MBR and UEFI/GPT are candidate modes only; the existing MBR
  4-entry/extended/logical and UEFI ESP preservation requirements apply.
- UEFI/MBR and BIOS/GPT are refused.
- The user must not be sent to Calamares' interactive partitioning; an
  authenticated unattended native backend and transaction-owned target
  provisioning are not implemented.
- No ISO URL, exact bytes or SHA-256 is invented or included in the
  stable distribution catalogue.

## Still blocked

Native Calamares partition intent handoff;
Windows storage transaction; disk ownership evidence; bootloader
and update durability; first Linux and Windows boot; uninstall; power
loss; and WinRE/BCD/MBR/ESP rollback in disposable Windows 10/11 VMs.

## Verified official image and QEMU lab boundary (16 November 2026)

- The official SourceForge `q4os-6.10-x64.r2.iso` SHA-256 is
  `1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d`.
  This is an upstream-published checksum, **not** a Gaslux maintainer-signed
  release catalogue or a verified upstream detached signature.
- The real ISO's complete bytes and Debian 13 live SquashFS passed the
  independent Q4OS Actions inspection:
  https://github.com/LMhdez/gaslux/actions/runs/43936058057
- The later disposable QEMU boot experiment failed because the guest GRUB
  could not see `/live/vmlinuz-6.12.111+deb13-amd64` on the emulated
  optical device:
  https://github.com/LMhdez/gaslux/actions/runs/43940542320
- A stacked branch now reuses the verified, read-only VirtIO ISO transport
  from the Pop!_OS workstream. The guest has only ephemeral NVRAM and ESP
  images, no network or physical disk. A pass requires observed guest
  kernel/userspace login, not merely an EFI/GRUB menu.
- This is a **live-media experiment**, not the requested native Calamares
  install. No unattended target partitioning, disk ownership, Windows boot,
  bootloader update or rollback has been demonstrated.

Reuse policy: the original Libertix partition/transaction/Windows recovery
machinery remains the shared base. Q4OS's native installer settings, module
ordering and installed-root behavior must be checked against the *same pinned
ISO* before attempting an unattended, transaction-owned installation.
The upstream public Calamares GitHub mirror points development to Codeberg.
Do not copy Calamares configuration from unrelated distributions or treat
Q4OS Windows WinSetup folder mode as a native disk installation.

Official Q4OS sources:
- https://q4os.org/blog.html
- https://q4os.org/dqa007.html
- https://www.q4os.org/forum/viewtopic.php?pid=35537

## Exact native Calamares inspection and disposable installed-root experiment

The official pinned Q4OS 6.10 r2 ISO actually contains the full native
`/etc/calamares/settings.conf` and module configuration. The guest root
reported `/etc/q4os_version = 6.10-deb13u1`. From the verified ISO:

- `unpackfs.conf` selects
  `/run/live/medium/live/filesystem.squashfs`, sourcefs `squashfs`,
  destination `""`. This is the only install payload source used by
  the disposable materialization experiment.
- `settings.conf` sequences partition, mount, unpackfs, Q4OS hooks,
  users, GRUB, package cleanup, initramfs and unmount. Those hooks must
  be individually reviewed before real unattended installation.
- `bootloader.conf` selects UEFI GRUB and sets
  `installEFIFallback: true`: blindly reusing this would risk replacing
  `EFI/BOOT/BOOTX64.EFI` on a Windows ESP. The Gaslux policy rejects
  such unowned fallback writes.
- `partition.conf` defaults to ext4 and has
  `initialPartitioningChoice: none`; this is not automatic,
  transaction-owned partitioning.

[Calamares config verification run 43964771409](https://github.com/LMhdez/gaslux/actions/runs/43964771409)
completed successfully, with hashes and native files retained as an artifact.
The policy auditor parses the extracted YAML using a duplicate-key-rejecting
loader; a pass **never** authorizes a production disk write.

The separate `gaslux_q4os_installed_root_lab.sh` experiment is explicitly
opted in **only on disposable GitHub Actions runners**. It creates a fresh
12-GiB sparse GPT image under its private temporary directory and validates
loop backing-file ownership before formatting its own EFI and ext4 partitions.
It stages the native Calamares `unpackfs` SquashFS payload, writes a
guest-only boot-proof systemd unit, and tries to boot with OVMF using a temporary
runner-built GRUB EFI binary. The ISO is **not attached** during the target boot,
and neither Windows disks nor a host physical disk are passed into QEMU.

**Important limitation:** this tests a staged *installed root*, not Calamares'
full installation: Q4OS-specific Calamares hooks, account provisioning,
native package-owned GRUB, package removal/updates, Windows coexistence,
transactional handoff and recovery are not run. A positive boot proof requires
the new guest's own systemd unit to emit a serial marker; success must only
be claimed after reviewing the exact-head GitHub Actions result.

The production catalogue, WPF wizard and Windows/BCD/ESP writers remain
untouched. Q4OS remains experimental; no stable dual-boot support is claimed.

## Native package-owned EFI GRUB and two-boot disposable OVMF proof

The follow-on experimental [PR #45](https://github.com/LMhdez/gaslux/pull/45)
tests a second boot using a **package-installed EFI GRUB loader** instead
of the earlier runner-built temporary EFI loader. This is not full Calamares
execution or a production Windows coexistence test.

The exact Q4OS 6.10 r2 live SquashFS initially lacked `x86_64-efi` GRUB
modules. The lab downloads `grub-efi-amd64-unsigned` and
`grub-efi-amd64-bin` with **Debian 13 signed APT repository metadata**,
requires matching package versions and verifies their SHA-256 before
offline guest `dpkg -i`. The observed packages had version
`2.12-9+deb13u2`. The guest verifies package status and module ownership
with `dpkg-query` and `dpkg -S` before invoking its own
`grub-install --target=x86_64-efi --no-nvram --recheck` and
`grub-mkconfig`.

All native bootloader writes stay on the guest-created GPT ESP. Guest code
rejects Windows EFI files, incorrect root/ESP filesystem/UUID/partition
labels, additional disks, non-QEMU firmware, and unexpected changes to the
original lab-created fallback EFI file. No NVRAM creation or host device
passthrough is permitted. The controlled guest-only fallback copy happens
after all these checks, and is prohibited for any Windows/shared ESP.

In the second QEMU invocation, only the same disposable GPT image and
temporary OVMF variables are presented, with **no ISO**. A pass requires
the real guest's second-boot systemd service to attest the pinned
`uname -r`, `BOOT_IMAGE` kernel command line, Q4OS version,
guest-owned ext4 root UUID and both EFI loader file hashes, as well as
the Q4OS native GRUB menu output. A mere GRUB menu is never accepted as
proof of a successful Linux boot.

[GitHub Actions #43978320653](https://github.com/LMhdez/gaslux/actions/runs/43978320653)
reached a **passing native GRUB installed-guest two-boot step** on commit
`00fca87de6ffc5cd2744a78a4a347aeeb0f52dac`.
Its separate ISO live-boot stage must be checked independently for a
complete workflow pass.

**Still not demonstrated:** full Q4OS Calamares view modules, Q4OS
`q4oshook*` execution, real account/localization provisioning, final
signed installation transaction, Windows 10/11 dual boot, loader updates,
boot durability, removal or WinRE/BCD/ESP/MBR rollback. Native package
boot alone cannot authorize an end-user Q4OS installation or stable release.


## Native Q4OS Calamares process-hook provenance and safety gate

Follow-up draft [PR #49](https://github.com/LMhdez/gaslux/pull/49)
extends inspection of the same pinned official Q4OS 6.10 r2 SquashFS.
The genuine Calamares process descriptors do not call the apparent
`q4os-hook*.sh` scripts directly: `q4oshook2` invokes
`/usr/sbin/debian_adjust2.sh` (3,600 s), `q4oshook3` invokes
`/usr/sbin/debian_adjust3.sh` (18,000 s), and `q4oshook5` invokes
`/usr/sbin/debian_adjust5.sh` (600 s). All fields `type: job`,
`interface: process`, command and timeout are validated against
descriptors extracted from the *same verified ISO*.

The source inventory includes nine shell scripts and three module
descriptors. All 12 are extracted as inert evidence, checked against an
individual SHA-256 manifest, and audited **without invoking them**.
Missing sources, unexpected process commands, hash changes, symlinks,
unsafe manifest paths or changed Calamares job ordering are refusals.
The extraction is ISO-hash-bound by the workflow, not an independent
upstream digital signature.

The genuine upstream files expose production blockers:

- `debian_adjust2.sh` derives `CHROOT` by grepping the current mount
  table for `calamares` and performs bind mounts, target mutations and
  unquoted cleanup. Gaslux cannot accept this path without independent
  transaction-owned disk/partition identity proof.
- `debian_adjust3.sh` creates a legacy `EFI/debian` directory in the
  target ESP, runs target `apt-get --purge autoremove` operations,
  removes installation files and conditionally invokes
  `dpkg --purge --force-remove-essential q4os-loopin`. Each action needs
  explicit scope and recovery.
- The auxiliary `q4os-hook3a.sh` includes writes to
  `EFI/debian/grub.cfg` and `grub-install --force`. Its invocation in
  the Q4OS 6.10 script is conditional on older Debian `bullseye`, but
  the dangerous logic still exists in the ISO.
- `debian_adjust5.sh` runs `chroot $CHROOT update-grub` based on
  that discovered mount path, without Gaslux transaction ownership.

These are observations about inert upstream sources, **not** completed
Calamares jobs or approval to run them. The auditor always returns
`hookExecutionAuthorized: false`, `windowsEspWriteAuthorized: false`,
`nativeInstallationProven: false` and `diskWrites: 0`.

[The successful pinned-ISO source extraction and boot run](https://github.com/LMhdez/gaslux/actions/runs/43981235254)
retained the original hook descriptors and scripts in an Actions artifact.
The next gate is a transaction-bound, VM-only implementation or
replacement of unsafe Q4OS hook effects, verified before touching any
Windows or shared EFI resources.

## Transaction-owned guest-only replacements for unsafe process hooks

The experimental [PR #52](https://github.com/LMhdez/gaslux/pull/52)
replaces *selected effects* of the upstream `debian_adjust2.sh`,
`debian_adjust3.sh`, and `debian_adjust5.sh` in a **disposable installed
QEMU guest only**. It never executes those upstream scripts, and it does
**not** claim a complete native Calamares installation.

Before each guest action, the hook replacement verifies the real QEMU
identity, exactly one `/dev/vda` disk, `/dev/vda2` ext4 root and
`/dev/vda1` VFAT ESP mounts, exact `GASLUX-Q4OS-ROOT` and
`GASLUX-Q4OS-ESP` GPT partition labels, measured filesystem UUIDs,
the pinned official ISO SHA-256, Q4OS version and a randomly generated
transaction UUID persisted on the installed root. Windows EFI files
and any unexpected ESP symlinks cause a refusal **before a hook writes**.

The replacement sequence is checked during the guest-native GRUB
installation and after reboot:
- Hook 2 creates a *locked synthetic QEMU test account* in the already
  mounted guest root, recording a transaction-owned checkpoint. It does
  not use a production user's credentials or claim Calamares users/locale.
- Hook 3 records that unreviewed Q4OS profile installation, APT package
  purges, forced removal of the essential `q4os-loopin` package and
  legacy `EFI/debian` writes remain **blocked**, not performed.
- Hook 5 uses the installed system's `update-grub`, validating that
  the native and guest-owned fallback EFI binary SHA-256 remain unchanged.
- The second boot independently checks the checkpoints, the locked
  account and the unchanged guest root/ESP identities.

The runner requires the positive source inventory and policy audit
from the **same hashed official ISO** before staging the hook adapter.
The only writable target is a newly-created sparse GPT image in the
private Actions temporary directory. No device passthrough or
Windows disk is supplied to QEMU.

**Unproven / prohibited:** executing the actual full Calamares UI/job
sequence, generating an unattended Calamares partition+users plan,
running unreviewed native package/profile removals, modifying shared
Windows ESP/BCD/WinRE/NVRAM, Linux upgrades, uninstall and recovery.
The guest-only checkpoints are not a production rollback mechanism.
Full Calamares validation requires a separate, transaction-authenticated,
disposable Windows/UEFI lab with automated graphical input and post-boot
recovery checks. Q4OS stays experimental and is not enabled for users.

### Verified disposable owned-hook execution (17 November 2026)

[GitHub Actions run #43987473391](https://github.com/LMhdez/gaslux/actions/runs/43987473391)
completed **success** on code commit
`3f1baca1420d79cc17362613031f21093194e8d8`, including the
verified-source audit, first guest boot, package-owned GRUB installation,
second installed-root boot and independent official ISO live smoke.
[The run artifact #14286248031](https://github.com/LMhdez/gaslux/actions/runs/43987473391/artifacts/14286248031)
was inspected independently. The guest logs contain:

- First boot: `GASLUX_Q4OS_OWNED_HOOK2`, `GASLUX_Q4OS_OWNED_HOOK3`,
  `GASLUX_Q4OS_OWNED_HOOK5` with the **same transaction UUID**,
  followed by `GASLUX_Q4OS_NATIVE_GRUB_INSTALLED=6.10-deb13u1`.
- Second boot: `GASLUX_Q4OS_OWNED_HOOKS_VERIFIED` with the same UUID,
  `GASLUX_Q4OS_NATIVE_GRUB_SECOND_KERNEL=6.12.111+deb13-amd64`,
  `GASLUX_Q4OS_NATIVE_GRUB_SECOND_BOOT=6.10-deb13u1` and installed-root
  identity proof.
- `installed-result.txt` explicitly confirms that original Calamares
  hook execution, unsafe APT cleanup, shared EFI mutation and **full
  Calamares installation were NOT performed**.

This is **a guest-owned hook replacement milestone only**. It does not
establish a Calamares GUI/job execution, account password provisioning,
Windows dual boot, upgrade survival or rollback. No stable release gate
was satisfied.

## Exact 29-job native Calamares graph and inert safety profile

The [draft PR #55](https://github.com/LMhdez/gaslux/pull/55)
is a prerequisite to running the *actual* native Calamares job engine
safely. The same official Q4OS 6.10 r2 ISO exposes 7 preparatory
`show` views, **29 `exec` jobs** and the `finished` view. The
profile builder compares the entire execution order with the
ISO-verified, allowlisted sequence and rechecks all 12 extracted
Q4OS process-hook/script SHA-256 records.

The source **29-job graph is preserved only in the audit JSON**, never
as an effective executable list. The generated `settings.conf` has
`exec: []`, with only inert `welcome` and `finished` views: it
cannot run even its first `partition` job if accidentally activated.
Defence in depth also replaces the three upstream Q4OS process hooks
with `command: /bin/false`, blocks GRUB installation/configuration
and `efibootmgr` (`/bin/false`), disables the upstream
`installEFIFallback: true` and removes the native unattended APT
removal list. This is an **abort-by-default diagnostic profile**, not
a deployable installer. A
missing source, changed module command, changed execution sequence,
tampered per-file SHA, symlink or existing output directory causes
a refusal before generating the profile. The output is written only
within the isolated GitHub Actions evidence directory, not to
`/etc/calamares` on the host or an installed system.


[Full pinned-ISO and two-boot QEMU run #43989978204](https://github.com/LMhdez/gaslux/actions/runs/43989978204)
passed at `123d0c5`, with independent artifact inspection showing
the native 29-job source sequence and previous owned-GRUB boot.
**That run preceded the zero-effective-job safety change**. The
latest version has been checked by Python/Ruff regressions, and
its own full ISO/QEMU run must be checked independently before
claiming exact-head end-to-end coverage.

The profile audit sets
`calamaresJobEngineExecuted=false`,
`profileActivationAuthorized=false`,
`installationAuthorized=false`,
`windowsEspWriteAuthorized=false` and
`diskWrites=0`. These values do not certify a fully installed Q4OS
or recovery support.

**Not completed:** an authenticated automatic Calamares view
controller and preflight identity proof on its *live guest*, a
transaction-limited partition/mount worker, safe native locale/
keyboard/users/bootloader/package modules, full GUI/exec sequencing,
and a Windows 10/11 dual-boot recovery simulation. Do not declare
a full Calamares installation by observing the previous
`unsquashfs` + `systemd` guest tests.


## Q4OS read-only run_lab supervision boundary — 22 November 2026

An independent QEMU 8.2.2 CI experiment on the stacked [PR #318](https://github.com/LMhdez/gaslux/pull/318) already demonstrated genuine OVMF/QCOW2/FD and existing operational `_qemu_args()` under `-S` with no guest OS. The incremental [Q4OS-RUNLAB-BOUNDARY-01](Q4OS_RUNLAB_READONLY_BOUNDARY.md) work intentionally **does not set `QEMU_FD_BACKING_VERIFIED=true`**, or invoke the operational `run_lab()` to spawn QEMU.

The new private read-only diagnostic reuses the actual Q4OS `_birth_identity`, `_pidfd_target`, `_witness`, `_peer`, `_socket_identity` and `_cleanup` with the connect-only QMP transport and an independent allowlist of read-only queries. It reuses the same stopped-guest launcher and synthesizes only media belonging to the disposable CI runner. It denies public `run_lab()` with injected factories before any side effect, unknown QCOW2 geometry/backing, unauthorized pidfd, and false QMP peer. A kernel pidfd check on each QMP query does not authorize the QMP command path intended to send DVD keyboard input.

The shared HOST/FD `ProcessSeal` from current `dev` is not a dependency of historical stacked #318; importing or copying it as an independent authority would require an Integrator-composed and reaudited contract. No ProcessSeal clone or replacement Observer controller is added. See the separate document for exact CI SHA, resource hashes, four-way contrast and remaining trust boundary.

**Next genuine live boot only after Safety approval:** authenticate the exact native Q4OS 6.10 x64 r2 ISO bytes and release/catalogue trust (historical upstream SHA-256 already recorded above), bind firmware/boot device and process provenance to a disposable QCOW2, prove live guest kernel and userspace on the *same authenticated VM*, then separately review Calamares. Historical upstream checksum alone does not authorize an installation or count as a signed Gaslux catalogue. All production/storage/release/stability gates remain false.


## Q4OS-NATIVE-LIVE-BOOT-01 — preparation-only source-to-guest graph (22 Nov 2026)

After [Q4OS-RUNLAB-BOUNDARY-01](Q4OS_RUNLAB_READONLY_BOUNDARY.md),
the new [native live readiness evidence](Q4OS_NATIVE_LIVE_BOOT_READINESS.md)
records the official Q4OS 6.10 x64 r2 native desktop ISO source and
upstream-published SHA-256 `1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d`.
The historical official ISO and Calamares inspection from 16 Nov 2026 is
explicitly distinguished from a **new** full-byte ISO verification: none
was made in this stage. Exact size and independent signed catalogue provenance
are not available in the currently examined `dev` stable release metadata.

The diagnostic module `auto_tests/tools/q4os_native_live_boot_readiness.py`
supports read-only, pinned-descriptor SHA-256 inspection of a locally
already-provided ISO. It never starts a guest or authorizes writers; a
matching hash is `MEDIA_HASH_ONLY`, not proof of future QEMU descriptor
inheritance, authenticated publisher signature or Q4OS live boot. The
JSON Schema requires `decision=DENY` and all runtime/Guest/install
authorizations false. Offline synthetic tests include symlinks, hardlinks,
FD mode/identity, rename and in-place mutation, invalid hash and
schema privilege forgery. The new GitHub Actions workflow installs no
QEMU, downloads no ISO and runs no Windows, Calamares or installation.

**Blocking gate**: the independent Safety review on #338 has not been
published; the existing review on #318 was `CHANGES_REQUIRED` before
a subsequent corrective CI run. The `dev` HOST/FD and Guest Peer contracts
must later be composed without duplication, only after a review of the
exact graph ISO → QEMU FD → QCOW2/firmware → observed Guest origin.
The stable catalogue, `QEMU_FD_BACKING_VERIFIED`, native installation
and Windows rollback authorizations remain unchanged and false.
