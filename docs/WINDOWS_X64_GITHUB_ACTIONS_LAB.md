# Windows 10/11 client x64 evaluation on GitHub Actions — hardware feasibility gate

**Draft, isolated, read-only infrastructure experiment. No Windows installation yet.**

The existing [PR #36](https://github.com/LMhdez/gaslux/pull/36) proves
real native minimal CachyOS first boot on a **Linux-only** disposable VM.
The Windows evidence collector in
[PR #15](https://github.com/LMhdez/gaslux/pull/15) and its offline
comparison tests do not prove actual Windows boot.

## Why GitHub-hosted Windows cannot substitute

As of November 2026, GitHub-hosted Windows x64 jobs run Windows
**Server 2025/2022**, not Windows 10/11 *client* (the Windows 11
hosted image is Arm64, not x64). The GitHub Actions job verifies
Win32_OperatingSystem.ProductType and refuses to report Server
as Windows 10/11. See:
https://github.com/actions/runner-images/blob/main/README.md

To prove Windows 10/11 **x64** installation and real dual boot,
an isolated QEMU/OVMF guest must boot the actual client ISO. The
host must possess sufficient disk, RAM, OVMF firmware, TPM 2.0
emulator and KVM acceleration. The signed CachyOS installation
cannot run on a Windows Server host and claim client support.

## Official evaluation ISO profile matrix

These values are explicitly pinned **for VM-only lab evaluation**,
NOT a signed production catalogue. Microsoft Evaluation Center
evaluation licences expire; they are not consumer redistribution
or automatic activation rights.

| Profile | Microsoft publication | SHA-256 (lowercase) |
| --- | --- | --- |
| Windows 10 Enterprise 22H2 Eval EN-US x64 | [Microsoft official hash PDF](https://download.microsoft.com/download/c/1/1/c11d2ca5-967c-45c0-bc7d-2d9ca3f1fe07/Windows10Enterprise22H2HashValues.pdf) | ef7312733a9f5d7d51cfa04ac497671995674ca5e1058d5164d6028f0938d668 |
| Windows 11 Enterprise 26H2 Eval EN-US x64 | [Microsoft official hash page](https://support.microsoft.com/en-us/servicing/os/windows/docs/2026/09/verify-the-authenticity-of-a-windows-11-enterprise-evaluation-iso-file) | bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38 |

Sources:
- [Windows 10 Enterprise evaluation ISO](https://www.microsoft.com/en-us/evalcenter/download-windows-10-enterprise)
- [Windows 11 Enterprise evaluation ISO](https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise)
- Microsoft Windows 10 22H2 reached standard end of support in
  October 2025; **this is only a historical compatibility test**.

The JSON contract verifies both exact 64-character official hash values,
two different expected client Windows build prefixes, Windows ProductType=1,
x64, UEFI/GPT, https://go.microsoft.com/fwlink and
a Microsoft hash authority. Unknown/modified hashes, a Windows Server
ProductType, missing Windows version, HTTP/foreign URLs, or production
metadata flags are rejected by negative tests. **A pinned hash is only
a prerequisite: its ISO must actually be downloaded and its
independently computed digest matched before a VM can boot.**

## Running GitHub Actions jobs

1. **Microsoft metadata and guards:** offline Python negative tests
   validate fixed Windows 10/11 x64 authoritative SHA-256 metadata.
2. **Host Windows x64 label validation:** execute only read-only
   Win32_OperatingSystem inquiry on a native hosted Windows Server
   runner; assert its ProductType is Server, and do NOT modify BCD
   or Windows volumes.
3. **Linux QEMU guest hardware gate:** install QEMU/OVMF/swtpm
   tooling, verify isolated GITHUB_ACTIONS/Linux x64, allowed
   consent marker, opened character device /dev/kvm, available RAM,
   free disposable SSD, and OVMF firmware file sizes. Upload a
   small JSON report. No guest disk or ISO is created by the gate.
   Without KVM or sufficient capacity, the gate **fails closed**.

The host report always contains:
- windows10GuestInstalled=false
- windows11GuestInstalled=false
- windowsAndLinuxDualBootVerified=false
- windowsRecoveryVerified=false
- productionStable=false

Readiness must NEVER be represented as a successful guest boot.

## Next mandatory acceptance tests (not yet executed)

- Stage the legally distributed, downloaded, SHA-256-verified
  evaluation ISO in an isolated **non-host-backed** QEMU storage file.
- Real unattended Windows 10/11 x64 UEFI/GPT installation, with a
  dedicated Windows virtual disk, ESP, WinRE and BCD, verified from
  inside **running Windows client**, including disk GUIDs, sector
  offsets, EFI binaries, boot entries and en/decryption status.
- Independently attest a second disposable CachyOS target/ESP; run
  the existing signed Archiso+pacstrap integration without modifying
  Windows partitions or Windows Boot Manager.
- Prove **both boot paths** after Linux installation and after native
  kernel/bootloader updates. Provide recovery/rollback evidence for
  power loss, EFI, BCD, WinRE, Windows BootOrder, disk identity and
  encryption from inside Windows again.
- Maintain evidence artifacts with hashes, separate simulation vs
  boot vs Windows recovery/rollback statuses and owner provenance.
- Human review before any stable release and no automatic merging.

No real Windows disks, production firmware or host block devices
are made accessible here.
