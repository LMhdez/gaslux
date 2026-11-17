# Windows 10 Enterprise Evaluation QCOW2 lab

**Experimental disposable VM only.** The workflow downloads Microsoft's Windows 10 Enterprise Evaluation 22H2 EN-US x64 ISO, checks its SHA-256 against Microsoft's published hash, installs it unattended into a new 48-GiB QCOW2 using QEMU/KVM + OVMF, and validates the installed OS offline before uploading the self-contained QCOW2 artifact.

## Acceptance evidence

The workflow requires all of the following:

- Official ISO SHA-256: `EF7312733A9F5D7D51CFA04AC497671995674CA5E1058D5164D6028F0938D668`.
- QEMU/KVM with OVMF UEFI; the unattended Windows setup creates GPT, an EFI System Partition, an MSR and an NTFS Windows partition.
- Windows `winload.efi`, EFI `bootmgfw.efi` and BCD are present.
- A first-logon command runs inside the installed Windows desktop, writes `C:\\GasluxEvidence\\first-logon.txt`, and shuts the guest down. The marker is checked by mounting the QCOW2 read-only via qemu-nbd/NTFS.
- The final QCOW2 is self-contained, 48-GiB virtual size, has no backing file, passes `qemu-img check`, and is uploaded with SHA-256 manifest.

The lab uses a random password for a temporary local Administrator account. The guest has no network adapter. The password is ephemeral and not included in the uploaded artifact.

## Limitations

- This is Windows 10 Enterprise Evaluation (90-day evaluation), not a retail activation or a representation of all Windows 10 editions.
- This workflow creates UEFI/GPT only. It does not prove BIOS/MBR.
- It does not attach any physical disk, Windows user disk, or real ESP. No Q4OS, Calamares, Linux partition, dual boot, Windows updates, recovery, rollback, or uninstall is tested.
- The QCOW2 Actions artifact is retained for seven days only. It is a disposable test fixture, not a durable user backup.
- A first-logon marker plus offline EFI/BCD checks proves a Windows guest reached its first interactive logon in this VM. It is not a complete compatibility or hardware validation.

The next stage is to use this Windows QCOW2 as a disposable guest target, make a controlled, transaction-owned guest mutation, and prove restore/boot from an independent pre-write snapshot before any Linux partitioning or Calamares execution.


## Runner acceleration policy — 17 November 2026

- The lab uses KVM only when `/dev/kvm` is present and accessible to the runner.
- Standard GitHub-hosted runners may not expose nested KVM. In that case the workflow explicitly selects QEMU TCG, uses a five-hour guest-process ceiling and a six-hour job ceiling; it does **not** mark the run successful unless Windows Setup, first interactive logon, clean shutdown, offline GPT/ESP/BCD checks and the self-contained QCOW2 checks all complete.
- A TCG timeout or resource exhaustion is a failed/incomplete fixture, never a synthetic success. No fallback skips the guest boot or weakens the Windows evidence gates.

## UEFI reset handling — 17 November 2026

The QEMU installer phase now uses `-no-reboot` and a bounded host-side boot-cycle loop. The Windows installation ISO is attached only for the initial Windows PE/setup boot. When Setup requests a reset, QEMU exits to the host; subsequent cycles boot the QCOW2 first, with only the unattended answer media retained. After each guest reset or shutdown, the host mounts the NTFS partition read-only through qemu-nbd and checks for the first-logon marker. The loop fails closed after eight cycles or five hours, and does not treat a QEMU exit alone as success.

This change addresses the previous boot-order hazard where the Windows installer ISO remained the highest-priority boot device after Setup had copied Windows to disk. It is not yet evidence that the guest installation succeeds; the new exact-head Actions run must pass all offline checks and upload its artifact.
