# CachyOS: Windows recovery evidence for disposable UEFI/GPT VMs

**Scope: laboratory instrumentation only. Not a supported CachyOS installer.**

This work is based on the signed-distribution-capabilities branch (PR #12),
which continues to hide experimental distribution backends from the WPF
production installer.

## Read-only Windows evidence

The following files implement an isolated Windows PowerShell 5.1 evidence
contract:

- `Scripts/modules/Gaslux.CachyosWindowsEvidence.psm1`: record and compare
  the selected Windows system disk's unique ID, exact GPT partition offsets,
  sizes and GUIDs; Windows EFI partition identity and SHA-256 of
  `EFI/Microsoft/Boot/bootmgfw.efi`; all BCD and UEFI firmware BCD text
  checksums; WinRE enabled state and `reagentc /info` checksum; and
  BitLocker/Device Encryption volume, protection and lock states.
- `Scripts/libertix-cachyos-windows-evidence.ps1`: `Capture` and `Compare`
  commands. Compare requires the same transaction and host, unchanged
  evidence fields, and a later observed Windows boot timestamp.
- `auto_tests/powershell/test_cachyos_windows_recovery_evidence.ps1`:
  negative fixture tests. GitHub Windows runner CI executes these tests
  using native Windows PowerShell 5.1 without modifying partition/boot state.

The collector refuses an ambiguous Windows system disk/ESP, missing WinRE,
unavailable BitLocker information, unsupported firmware/layout, missing EFI
loader or inaccessible existing ESP. It deliberately **never** creates an ESP
mount, resizes/formats partitions, changes BitLocker, edits BCD or NVRAM,
reboots, or attempts a rollback.

## Lab-only use

**Only in an authorized disposable Windows 10/11 UEFI/GPT VM**, after
creating a snapshot outside the guest and making the existing ESP
accessible through an already-established mount, for example `S:\`:

```powershell
$runId = 'vm-cachyos-test-20261116'
& .\Scripts\libertix-cachyos-windows-evidence.ps1 -Mode Capture -RunId $runId -EspRoot 'S:\' | Set-Content -Encoding UTF8 .\windows-before.json

# After an independently controlled VM installation/rollback and
# successful return to Windows in the same VM:
& .\Scripts\libertix-cachyos-windows-evidence.ps1 -Mode Compare -RunId $runId -EspRoot 'S:\' -BaselineJson .\windows-before.json
```

Preserve the baseline **outside the guest** as an artifact of the
pre-install snapshot, with a separate SHA-256 and reviewer signature. Do
not create the baseline retrospectively after rollback. A script-readable
ESP path does not authorize modifying the ESP, its filesystem or firmware.

Successful `Compare` proves only the stated Windows-side identities and
a later Windows boot timestamp; it does not prove a real boot of installed
CachyOS, Linux updates, integrity of unrelated disks, availability of
WinRE recovery, UEFI BootCurrent/BootOrder restoration at the firmware
binary level, or that the original recovery can be executed after power
loss. BCD/WinRE checksums may differ legitimately between boots and the
verifier intentionally **fails closed** rather than ignoring differences.

## Integration / stability blockers

- Connect this lab collector to the existing authorized Proxmox Windows
  guest harness and external signed-evidence gate, retaining snapshots and
  independently checked `reagentc`, `bcdedit` and UEFI EFI records.
- Add cryptographically authenticated Windows-to-Archiso boot handoff to
  the actual WPF application; do not call the existing Debian mini-ISO
  backend with CachyOS media.
- Implement transaction ownership, BootNext/BootOrder restoration and
  exact ESP/BCD/WinRE compensation before any partition mutation.
- Perform complete dual-boot installs for both Windows 10 and Windows 11
  in disposable VMs, followed by Linux updates, Windows return, rollback
  and injected power/network/EFI/package failures.
- Add independent all-disk topology comparison for second-disk layouts.
  This first collector covers only the selected Windows system disk.
- Independent human review, signed and hash-verified test reports,
  real hardware backup/restore validation, and explicit release approval.

No Windows 10 or Windows 11 CachyOS dual-boot test is claimed. Windows
Server 2022 GitHub CI validates **fixture logic only**. The code is not
connected to the stable user-facing install wizard.

Related:
- https://github.com/LMhdez/gaslux/issues/3
- https://github.com/LMhdez/gaslux/pull/8
- https://github.com/LMhdez/gaslux/pull/10
- https://github.com/LMhdez/gaslux/pull/11
- https://github.com/LMhdez/gaslux/pull/12
