# Pop!_OS / System76 backend — independent experimental workstream

**Status: lab-only diagnostic, not an installer.** This branch is based on
`feature/multidistro-lab-media-probe`, not any CachyOS implementation.

## Grounded policy

System76's published installation guidance requires disabling Secure Boot.
Pop!_OS uses **systemd-boot for UEFI** and **GRUB for legacy BIOS**. Its
installer offers advanced/custom partitioning, while full-disk encryption
on a Windows-shared drive is not a supported assumption.

The probe:
- Distinguishes generic and NVIDIA x86-64 media policy (actual ISO exact
  variant binding awaits verified signed metadata).
- Refuses UEFI/MBR and BIOS/GPT, wrong bootloader, enabled Secure Boot,
  mismatched `os-release ID=pop`, bad ISO hash, or Windows-shared full-disk
  encryption.
- Accepts BIOS/MBR and UEFI/GPT **as upstream candidates**, never claiming
  those combinations are installed or certified in Gaslux.
- Returns `installationAuthorized: false`, regardless of test outcome.

## Remaining implementation

1. Pin exact official ISO variant/bytes/SHA in a maintainer-signed v2
   catalogue. Do not reuse an unrelated Mint/Zorin squashfs even if both
   images contain `casper`.
2. Verify real Pop live root and System76 distinst/pop-installer identity
   from the **same** pinned ISO and authenticate Windows-to-live handoff.
3. Implement native target installation, account/locale, firmware-specific
   boot chain (including kernelstub / systemd-boot UEFI), update resilience
   and Windows boot entry recovery.
4. Exercise install, dual-boot, updates, uninstall and rollback with disposable
   Windows 10 BIOS/MBR, Windows 10 UEFI/GPT, Windows 11 UEFI/GPT guests.
   Never test on physical disks without independent recovery evidence.

Sources:
- https://support.system76.com/support/install-pop
- https://support.system76.com/support/bootloader
- https://support.system76.com/support/windows
- https://github.com/pop-os/iso/blob/master/config/pop-os/24.04.mk

## Ubuntu-family target configuration reuse (experimental bridge)

The inherited `assets/live/configure-target-main.sh` is split into two
explicitly ordered phases without changing the Mint/Zorin operations:

- `configure_common_ubuntu_target`: account, Windows sharing and preferences,
  locale, keyboard, timezone and development-access configuration.
- `configure_legacy_grub_target`: Casper cleanup, initramfs rebuild, GRUB,
  boot-update guards and first-boot resize setup.

`validate_legacy_target_backend_or_die` executes **before target configuration**
and requires exactly `mint/linuxmint` or `zorin/zorin`. This check runs
inside the installed target, **after live disk staging and extraction**;
it is not a substitute for an earlier Windows/live pre-disk authorization gate. The only accepted
backend remains `debian-squashfs` (the legacy default); `system76`, `popos/pop`
and unknown identities all fail closed. The selection function is deliberately
not wired to a Pop!_OS writer. This does not override Windows preflight or
authorize disk/EFI changes.

The next integration must separately prove that each shared operation works on
the verified System76 installed target. Pop!_OS still requires native
`distinst`/installer integration, its own boot/update/verification policy
(systemd-boot UEFI, GRUB BIOS), authenticated Windows-to-live handoff,
and disposable Windows VM installation/dual-boot/rollback evidence.

`auto_tests/tests/test_ubuntu_target_backend_preflight.py` executes only the
Bash validation function with synthetic environment inputs, confirms negative
and positive policy cases and guards the historical operation order. It does
not execute installer or disk commands.

## OVMF live-boot block-device diagnostic (experimental)

GitHub Actions can verify the official Pop!_OS ISO but older QEMU runs failed
because GRUB could not find the live kernel on emulated CD-ROM or USB optical devices.
The serial evidence listed only the lab EFI disk, so the test now uses a
second explicitly read-only virtio-blk disk for the verified ISO.
The Pop-specific disposable-VM experiment now attaches the signed/digest-checked
ISO as a **read-only virtio block device** (separate from the fresh temporary GPT
ESP disk) and requires a matching live kernel/initramfs and **serial login**.
The shared Q4OS smoke harness retains its previous optical-media path.
A missing GRUB device remains a failure, not a boot success. This is a live
smoke test only; the Windows target disk, System76 distinst, and bootloader
writers are never attached or invoked.

## Verified native installer agent provenance (read-only)

A separate experimental CI job verifies that `usr/bin/distinst` is extracted
from the same SquashFS root that passed `ID=pop` and Pop 24.04 checks **inside
the GPG-verified and SHA-256-pinned official ISO**. It checks the x86-64 ELF
header and records the native agent's observed SHA-256 and byte length.
This is static inspection only; `distinst` is never invoked.

The upstream `pop-os/distinst` CLI supports options such as `--new-table`,
`--delete`, `--move`, `--new`, `--use` and `--modify-boot`. None can be
considered safe on a Windows-shared disk merely because its ISO is genuine.
Production integration must first prove exact disk/partition ownership, prevent
foreign ESP and Windows writes, authenticate the handoff, implement the
System76 EFI/BIOS boot strategy, and test recovery in disposable Windows VMs.

Source: https://github.com/pop-os/distinst/blob/master/cli/src/main.rs

## Executed native CLI in disposable live guest (not an install)

The next experimental stage uses a QEMU/OVMF serial socket to access only the
verified Pop!_OS live guest's lab debug shell, mounts the temporary **VM-created** Gaslux FAT
ESP read-only, hash-checks a tracked probe script, and runs only
`/usr/bin/distinst --help`. A `systemd.debug_shell=ttyS0` root console is
explicitly enabled **only for this disposable no-network QEMU guest** because
Pop's live console requires credentials unavailable to the test harness. This
kernel argument must never enter a production plan or bootloader. The guest
independently verifies the real
`ID=pop`, QEMU/KVM environment and installed `distinst` SHA-256 against
the digest taken from the GPG-verified signed official ISO. No target disk is
attached, no disk-writer flag is used and no Windows/EFI bootloader operation
is performed. The QEMU serial transcript is retained on success and failure.

The separate first-boot, native installation, systemd-boot/GRUB update
persistence and Windows recovery tests remain mandatory for production.

## Native distinst partition-stage validation (synthetic Windows GPT)

A separate VM-only experiment invokes the authenticated real Pop!_OS
`distinst --test` against an **ephemeral** 32-GiB virtio disk with a
mock FAT Windows ESP, mock NTFS partition and distinct Gaslux-owned root.
The official ISO remains read-only; the VM has no network and no host disks.
Because upstream `--test` can reach partition operations, the host hashes
both mock Windows partitions and compares the GPT before and after execution.
A mismatch is a test failure. A mock Windows loader is **not** a working
Windows Boot Manager; BCD, WinRE and actual dual boot are not proved.
This is not a production plan or installation authorization.

### GPT mutation observed in the disposable System76 test

Real `distinst --test` invokes `disk.commit()`: it changed the *owned Linux
root* GPT entry (PARTUUID, name and a one-sector reduction of its last LBA)
while the synthetic Windows ESP and NTFS data remained byte-identical. The
laboratory verifier now validates both GPT header and entry-table CRCs,
requires identical disk GUID, MBR, every non-owned GPT entry and both mock
Windows partition payloads, and permits **only** the measured root change.
It outputs the root's final PARTUUID/LBA for future plan reconciliation.
These allowances are lab-only; the production transaction writer remains
blocked pending durable root identity, recovery and genuine Windows tests.

## Native System76 install + installed-system first boot (experimental VM only)

This stage uses the exact signed Pop!_OS ISO and the SHA-256-identified native
`distinst` executable. The experiment runs without physical disks or a NIC in
a disposable QEMU/KVM UEFI VM with a **separate, newly generated Linux-only**
GPT target (owned 1-GiB ESP and 28-GiB root). The temporary GRUB used to start
the ISO is on a *different* disposable disk. After a full native `distinst`
invocation (not `--test`), the guest verifies the installed `ID=pop`, dpkg,
root filesystem, systemd-boot binary, UEFI fallback file and boot entries.

For first-boot verification only, the test then installs a hash-checked systemd
service into the newly installed virtual root. A second QEMU starts with fresh
OVMF NVRAM and **only the installed Linux disk attached**: no ISO, temporary
GRUB disk or extra volumes. The service reports its real root partition,
actual kernel, EFI mount and installed Pop identity over the virtual serial
port. Missing/failed proof is a CI failure. The service is laboratory-only and
is never delivered to production machines.

Even a successful test does NOT prove the actual Windows-to-Linux transaction,
full account provisioning, Secure Boot variants, upgrades, uninstallation,
Windows 10/11 boot (BCD, WinRE, BitLocker) or rollback. These need later
snapshotted Windows VMs and explicit disk ownership proof. The production
backend remains unimplemented and blocked in the stable catalogue.

## Native full-install diagnostic collection

A real System76 installation can take substantially longer than the ISO
boot smoke tests. In disposable QEMU only, the guest now forwards bounded
periodic tails of the authenticated native `distinst` log to the serial
transcript. These are diagnostic messages, not boot or recovery proofs.
A separate explicit native exit code and independent installed-system
boot markers remain mandatory; timeouts fail closed.

## Full-install serial input corruption (verified root cause)

A failed guest trace from [Actions #43983951909](https://github.com/LMhdez/gaslux/actions/runs/43983951909)
showed the installer controller starting as soon as systemd's early root debug
shell appeared. Kernel and service messages were still being emitted and the
long shell command acquired duplicated characters in its mount path and hash.
The controller now waits for `Startup finished in`, completes short
individually acknowledged mount/hash stages and invokes just `bash install.sh`.
The independently verified native-agent digest is instead stored as an exact
65-byte SHA-256 line in the temporary QEMU FAT control disk and is included in
the hash manifest checked by the guest before the native writer runs. This is
strictly lab-only; it does not establish a production handoff or Windows proof.

## Native install shutdown/second-boot transition

Actions [#43988375734](https://github.com/LMhdez/gaslux/actions/runs/43988375734)
completed the real `distinst` installation and logged native `kernelstub`
bootloader configuration, but failed the host's clean-poweroff gate before
starting the second VM. The guest controller previously closed its serial
connection immediately after sending the shutdown command, even though the
interactive shell might not yet have regained its prompt. The revised
controller proves the returned shell with a post-install command challenge,
confirms a separate completed `sync`, then sends normal `systemctl poweroff -i` and keeps the socket open until
guest disconnection. Disconnection is NOT trusted as success: the QEMU process
must still exit with code 0 and installed first boot remains a separate check.

## Debug-shell prompt interleaving in real OVMF guest

The retained serial transcript from [Actions #43989333364](https://github.com/LMhdez/gaslux/actions/runs/43989333364)
showed the live root debug-shell prompt sharing a line with a late `systemd`
mount message, so a strict end-of-line prompt regex failed even though
`Startup finished in` was observed. The installer controller now uses the
already required nonce-like shell challenge as the sole proof of active shell
execution before any mount or installer command is sent. After completed native installation, a fresh post-install shell challenge
and a separate sync-confirmation marker prevent premature shutdown without
relying on potentially interleaved prompt text. No disk mutation is authorized on missing nonce proof.

## Linux-only first-boot GPT reconciliation (experimental)

A follow-on lab step captures and validates *both* GPT copies (CRC, disk GUID,
protective MBR, partition arrays) before and after the native install. It
rejects any change outside the uniquely owned root partition, checks that the
owned ESP GPT entry is byte-identical, and records the root PARTUUID observed
**on the host after installation**. The independently booted Pop guest must
report that same PARTUUID over serial. An installation success marker or a
plausible-looking guest UUID is not sufficient without this cross-check.

The experiment uses a new Linux-only QEMU disk, not Windows partitions. It is
not a production authorization, shared-ESP integrity guarantee, Windows dual
boot, Windows recovery, update, or uninstall proof. Those tests remain blocked
pending a signed production transaction and disposable Windows VMs.

## Independent native full-install mock-Windows isolation (experimental)

A disposable GitHub Actions QEMU/OVMF test can install the verified native
Pop!_OS 24.04 system onto a virtual disk containing **mock** Windows ESP
(FAT) and Windows data (NTFS), and a **separate** owned Pop ESP/root.
The System76 native CLI receives only the Pop ESP as `reuse` and Pop root
as `ext4`. It must not select the mock Windows partitions.

An independent host-side, read-only auditor validates primary/backup GPT
checksums, byte-identical non-root GPT entries, protective MBR, and the
SHA-256 of **every byte** of the mock Windows ESP and NTFS both after native
installation and after a separate OVMF first boot without the live ISO.
Installed boot must report the reconciled root PARTUUID. Failure blocks
the lab CI job; test evidence does not authorize production disk writes.

The mock EFI file is deliberately *not* a Windows executable. No installed
Windows, WinRE, BCD, BitLocker, Windows boot, dual boot, update, uninstall,
or rollback is tested by this lab. It is separate from the Linux-only
first-boot test, which remains unchanged.
