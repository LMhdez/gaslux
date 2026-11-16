# Windows client x64 — real WinRE partition baseline for disposable QEMU/TCG

**Experimental; not yet a boot or recovery result.**

This branch extends the [Windows 10/11 x64 real-ISO TCG laboratory
PR #48](https://github.com/LMhdez/gaslux/pull/48). No change to the
stable Windows preparation, partition-writing or rollback pathways.

## Verified Windows layout contract

Microsoft [documents the supported UEFI/GPT layout](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/configure-uefigpt-based-hard-drive-partitions?view=windows-11)
with an EFI System Partition (ESP), Microsoft Reserved (MSR), Windows
OS volume and **separate dedicated Windows RE tools** partition.

The **only** target visible to Windows Setup is the newly created
file-backed QEMU virtual disk of exactly 128 GiB; there are **no real
host disks, pre-existing Windows volumes, or production firmware
devices** attached. The lab-only unattend plan creates, in order:

| Partition | Size | Filesystem | Windows GPT identity |
| --- | --- | --- | --- |
| 1. ESP | 260 MiB | FAT32 | EFI System partition |
| 2. MSR | 16 MiB | — | Microsoft Reserved |
| 3. Windows | 72 GiB | NTFS | Basic Data |
| 4. Windows Recovery | 1536 MiB | NTFS | Windows Recovery Tools, `DE94BBA4-06D1-4D40-A16A-BFD50179D6AC` |

This leaves at least 45 GiB unallocated in the **virtual disk**.
It is *not* an authorized shrink of a host Windows partition, nor
evidence that Gaslux can place Linux in that area: an independent
target/EFI/ownership and rollback check is still required.

Microsoft recommends a WinRE partition >=990 MB and separate from the
Windows volume. That partition must be immediately after Windows for
future servicing. The unattend `TypeID` identifies it; it does not
automatically prove the GPT attributes, contents or WinRE WIM have
been configured correctly by Windows Setup.

## Guest-side baseline evidence

Only after the Microsoft SHA-256 pinned ISO is fully verified
and a genuine installed Windows **client** boots under OVMF:

- Windows guest PowerShell must confirm ProductType=1 and expected x64
  build, GPT disk 0, one ESP, one Windows Recovery Tools GUID, the
  expected offset order and native Windows `winload.efi`.
- `bcdedit /enum '{bootmgr}'` must return success; no changes to BCD.
- `reagentc /info` must return success **and the real state must be
  Enabled**, not merely that a command was invoked. Failure means
  the baseline **fails closed** without generating the success serial
  witness. The witness emits separate
  `GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1` and
  `GASLUX_WINDOWS_X64_WINRE_ENABLED=1` markers.
- Host waits for **all** markers from COM1 of installed Windows client
  before claiming guest firstboot; a fake marker in a generated XML
  fixture never establishes success.

This branch adds Linux Python negative/contract tests and Windows
PowerShell AST syntax checks in GitHub Actions; these tests **never**
run Windows Setup or change any disk.

## Still required before stability

A successful Windows x64 firstboot **does not** prove actual WinRE
`winre.wim` SHA-256, full BCD store integrity, preserved BootOrder,
Windows Boot Manager ESP hash, BitLocker/Device Encryption state,
post-Gaslux dual boot, Linux kernel updates, uninstall or transaction
rollback. The firstboot observer alone is only a *baseline*.

To accept Windows 10/11 + CachyOS as stable:
1. Obtain this baseline from separate, legally downloaded x64
   Windows 10 and Windows 11 evaluation VM guests.
2. Run true Gaslux Windows handoff plus the signed Archiso install
   on independently owned partitions of the **same VM disk**.
3. Verify boot of both operating systems, before and after Linux
   kernel/GRUB updates.
4. Recollect Windows BCD/WinRE/ESP/encryption/geometry evidence and
   prove rollback after injected failures.
5. Obtain human review under AI_POLICY.md and issue #3.

Windows 10 22H2 is a historical compatibility target outside
standard support. All image and runtime resources are disposable;
no Windows evaluation ISO, QCOW2, credentials or TPM state may be
uploaded to Actions artifacts.
