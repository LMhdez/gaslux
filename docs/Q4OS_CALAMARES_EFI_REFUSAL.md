# Q4OS Calamares — pinned EFI configuration and non-authorizing Safety contract

**Status: EXPLICIT REFUSAL.** This is an analysis of real pinned-ISO source
files already extracted and hashed in prior Actions, plus disposable
adversarial Python tests. It does **not** execute Calamares or prove a
Windows 10/Q4OS installation, Windows boot or EFI rollback.

## Primary source provenance

The verified upstream Q4OS 6.10 x64 r2 ISO reference is
`1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d`.
The exact ISO and SquashFS extraction method are defined in
`auto_tests/tools/gaslux_q4os_calamares_probe.sh`. The archived read-only
[Actions #43964771409](https://github.com/LMhdez/gaslux/actions/runs/43964771409)
logs print **actual** `/etc/calamares/modules/bootloader.conf`, rather than
an inferred distribution default:

| Actual extracted setting | Observed value | Consequence |
| --- | --- | --- |
| `efiBootLoader` | `grub` | EFI GRUB installation path |
| `grubInstall` | `grub-install` | Invoked by Calamares bootloader job if executed |
| `grubMkconfig` | `grub-mkconfig` | Generates GRUB configuration |
| `grubCfg` | `/boot/grub/grub.cfg` | GRUB configuration destination in target |
| `grubProbe` | `grub-probe` | Filesystem and device probing |
| `efiBootMgr` | `efibootmgr` | Potential EFI variable/NVRAM changes |
| `installEFIFallback` | **`true`** | Potential shared `EFI/BOOT/BOOTX64.EFI` overwrite |

The same source's comments describe `grub-install --bootloader-id` and
the EFI directory `/boot/efi/EFI/<dirname>/`, with the default name
derived from `branding.desc:bootloaderEntryName` when `efiBootloaderId`
is not explicitly set. The **actual runtime directory name and exact
fallback operation have not been established by an executed installer**.

In the ISO-derived `partition.conf`, `efi.mountPoint=/boot/efi`,
`defaultFileSystemType=ext4` and
`initialPartitioningChoice=none`. Neither a protected Windows ESP
allowlist nor an authenticated dedicated Q4OS ESP mapping is proven.
The 29-job source order has `partition`, `mount`, `unpackfs`, process
hooks, `grubcfg`, `bootloader` and later cleanup; the existing inert
profile makes the **effective** `exec` sequence empty. Changing only
`installEFIFallback` to `false` does not prove the rest safe.

The ISO's authentic Q4OS process descriptors, as printed in
[Actions #43981235254](https://github.com/LMhdez/gaslux/actions/runs/43981235254),
refer to `/usr/sbin/debian_adjust2.sh` (3,600s),
`/usr/sbin/debian_adjust3.sh` (18,000s) and
`/usr/sbin/debian_adjust5.sh` (600s), respectively. Previously
SHA-256-audited source analysis identifies creation of legacy
`EFI/debian` in `debian_adjust3.sh`; auxiliary
`q4os-hook3a.sh` contains `EFI/debian/grub.cfg` and
`grub-install --force`, **conditional on an older bullseye path** in
the 6.10 hook script. These operations are risks requiring exclusion;
their actual execution on Debian 13 has not been shown.
`debian_adjust5.sh` invokes `update-grub` with an inferred chroot
mount, not with demonstrated Gaslux ownership.

## Effects and refusal decisions

| Anticipated write or side effect | Ownable solely by source config? | Decision |
| --- | --- | --- |
| GPT primary/backup partition entry and CRC changes | No signed transaction/write-set | Refuse |
| Root ext4 formatting/mount and SquashFS unpack | No proven exhaustive write-set | Refuse |
| Windows ESP `EFI/BOOT/BOOTX64.EFI` fallback | No verified suppression | Refuse |
| `EFI/debian` or `EFI/debian/grub.cfg` | No proven Q4OS ownership | Refuse |
| `grub-install` or `grub-install --force` | Target and hooks unverified | Refuse |
| `efibootmgr`, BootOrder/BootNext or other NVRAM writes | No owned NVRAM model | Refuse |
| Windows Boot Manager, BCD, WinRE, OEM partition | Never included in owned write-set | Refuse |

Independent ESP ownership would require a validated second ESP on
the selected disk and firmware support, explicit Calamares mount
binding, all hook/GRUB/NVRAM effects enumerated, Windows Boot Manager
preservation and recovery tests. **None is demonstrated**.
The read-only Q4OS adapter only allows synthetic descriptors for
root create/format to be *checked*, and always returns `refuse`.
The hazardous operations above are adversarially represented as
unallowlisted operation strings; tests do **not** execute those binaries.

## Safety #265/#267 integration

`libertix_disk_identity_gate.py` (#265) owns GPT parsing, CRCs,
geometry and identity comparison; no duplicate GPT parser was added.
`libertix_prewrite_no_writer.py` (#267) checks canonical plan bytes,
HMAC-authenticated host/guest/immediate snapshots, challenge, transaction,
VM, disk identity, exclusively owned free-space extents and matching
write-set. Its success output is **`ACCEPT_NO_WRITER`**, not installation
authorization. HMAC possession does not prove authentic guest hardware,
Windows BCD/WinRE/BitLocker or a trusted host-to-QEMU mapping.

The Q4OS diagnostics require the exact Safety response fields
`decision`, `transactionId`, `planSha256`, `vmId` and `writeCount`,
bind them to the Q4OS diagnostic transaction and refuse if absent,
changed or unsupported. Even a passing response is never a writer
grant. A caller-provided result dict alone cannot authenticate its
origin: the CI uses the **actual pinned #267 code** on synthetic lab
records to exercise the contract, not a production attestation.

## Genuine Windows 10 QEMU boundary

The existing documented lab
`gaslux-q4os-windows10-qcow2.yml` constructs a 48-GiB Windows 10
Evaluation UEFI/GPT image and checks Windows first logon/EFI files.
Its unattended partition script explicitly requests ESP 100 MiB,
MSR 16 MiB and a Windows NTFS primary extending through the remaining
disk; it does not explicitly create a WinRE partition or pre-reserve
Gaslux-owned Linux free space. Whether any Windows-generated recovery
partition exists requires inspection of an actual image. This layout
**must be refused** for Q4OS placement unless independently proven
sufficient, and no shrink or partition creation is permitted here.

No existing Windows 10 QCOW2 artifact was mounted, used in QEMU or
independently compared to the Safety contract during this intervention.
The synthetic GPT test image is not genuine Windows.

No physical or QEMU disks, Windows ESP, BCD, NTFS, WinRE or NVRAM were
written. No Calamares job, graphical input or GRUB command was executed.
No live boot, dual boot, rollback or durable recovery is proven.
Q4OS remains an experimental draft with the stable catalogue unchanged.
