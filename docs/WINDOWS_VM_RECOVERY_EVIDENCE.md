# Windows 10/11 UEFI recovery evidence — read-only

**Experimental collector only. No Windows/CachyOS dual-boot campaign is certified.**

This addition reuses the Proxmox Windows 10/11 UEFI lab and the
reviewer-signed campaign gate in PR #8. It does not provision VMs or
run a new Linux backend. It has no access to production disks.

An authorized operator runs the Windows guest PowerShell collector
as Administrator in a disposable Proxmox VM, BEFORE any installation
and again AFTER a reboot to Windows after installation/rollback.
Run exactly the same per-operation transaction ID on both captures.
Store untouched JSON stdout outside the VM, so it survives snapshot
rollback. Modes: baseline, postinstall, rollback.

    powershell.exe -NoProfile -File auto_tests/app/scripts/windows-guest-recovery-evidence.ps1 -Phase baseline -RunId authorized-lab-run-001

Then run the offline comparison on the Proxmox controller:

    python3 auto_tests/tools/verify_windows_guest_recovery.py --before BEFORE.json --after AFTER.json --mode postinstall

Use mode rollback when comparing a restored Windows state instead.

No boot or disk mutation is performed by these tools. Guest evidence
is read from Windows Get-Disk, Get-Partition, Get-Volume, Get-FileHash,
Get-BitLockerVolume, Confirm-SecureBootUEFI, bcdedit /enum and
reagentc /info. An unreadable unmounted ESP, missing BitLocker module,
ambiguous disk, disabled/unknown WinRE or unsupported Windows locale
causes refusal. The EFI volume is never assigned a letter or mounted.

A successful result checks the exact Windows disk identities, GPT
offsets and lengths, original ESP/OEM/Recovery partitions, unrelated
disks, Windows EFI loader SHA-256, WinRE WIM SHA-256, BCD, WinRE, BitLocker and a
second observed Windows boot. For postinstall, Linux partitions must
fit entirely inside the byte range freed by the intended NTFS shrink.
For rollback, **every** disk partition map must match byte-for-byte.

**Important limitations:** This is a guest observation only. It does
NOT prove a successful Linux boot, kernel update, actual NVRAM variable
restoration, a Proxmox snapshot rollback, a user-data integrity hash,
or the independent reviewer signature required by issue #3.
It does not handle BIOS/MBR yet. The synthetic tests in CI explicitly
return stable=false, linuxBootVerified=false and reviewerSigned=false.

Before release: capture host-side OVMF/Proxmox state, Linux first-boot
and kernel-update evidence, verify Windows/WinRE/BCD/EFI after all
fault injections, bind results to exact source commit and installer
binary SHA-256 and obtain an independent signed review. Maintain the
existing signed distribution catalog without enabling CachyOS.
