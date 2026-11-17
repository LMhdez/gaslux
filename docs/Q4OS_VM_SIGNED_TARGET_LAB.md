# Q4OS signed target plan — disposable VM only

**State: experimental, read-only. No Calamares installation or Windows dual boot.**

This stacked Q4OS workstream follows PR #59, which proved that the official Q4OS 6.10 r2 ISO launches the native Calamares graphical installer, displays the UEFI/GPT Partitions page, and sees an isolated 32-GiB QEMU disk with one 512-MiB FAT32 ESP. The GUI lab did **not** create a Linux root, execute Calamares jobs or touch a Windows disk.

## Signed plan and disk ownership

The module assets/live/gaslux_q4os_vm_target_plan.py only reads the exact file named efi-disk.img inside a new private, owner-controlled workspace. It refuses symlinked paths, hardlinks, non-regular/block-device files, foreign ownership, changed size and unexpected sector geometry.

It independently reads and verifies:
- The protective MBR and absence of hybrid/foreign MBR entries.
- Primary and backup GPT header CRCs, table CRCs, cross-pointers, exact disk GUID, entry count and 512-byte sectors.
- The expected single GPT entry: ESP type, independent ESP partition GUID, exact start/end LBAs, GASLUX-LAB-ESP partition label, zero residual entries, FAT32 boot sector.
- Both GPT metadata SHA-256 windows and the host inode/device identity; after signing it reopens and rechecks the disk.
- A **proposed, unformatted and uncreated** root extent in the still-unallocated sectors; nothing is written to the root.

The independent, domain-separated Ed25519 signature covers canonical JSON. The verifier requires a separately supplied trusted key fingerprint, run ID and 128-bit nonce. Duplicate JSON keys, unknown fields, re-signed unsafe booleans, signature tampering, replay, altered GPT evidence and cloned disk images are refused. Schema schemas/gaslux-q4os-vm-target-plan.schema.json limits the plan to this experimental layout and fixes installationAuthorized=false, calamaresJobsAuthorized=false, windowsEspWritesAuthorized=false, guestOnly=true.

## GitHub Actions

The isolated Actions workflow gaslux-q4os-vm-target-plan.yml runs Python/Ruff/JSON Schema negative tests, then creates **only its own new sparse 32-GiB file** in the ephemeral runner's private temporary directory. The fixture uses sgdisk and mkfs.vfat solely on temporary files, verifies the actual GPT with sgdisk --verify, generates a fresh ephemeral Ed25519 key and re-verifies the signed read-only plan against the same disk. It uploads the manifest, public lab key, signature and refusal/status report; **never** a private signing key or the 32-GiB disk.

The lab's fresh ephemeral key is **not** a Gaslux production release trust anchor. The pinned official ISO hash in this document is metadata only; this specific signed-plan workflow does **not** re-download and verify the complete ISO.

## Explicit hard boundaries

- This experiment is **not** a Windows-containing GPT or a Windows dual-boot installer.
- Host inode/device identification does **not** establish guest-visible virtio disk identity. The guest must independently bind a signed transaction, disk GUID and partition UUIDs to the verified writable target before any subsequent write-phase can be considered.
- The installed root is absent. **No native Calamares job**, partition formatter, installer hook, account, GRUB, update or rollback is run or authorized.
- The upstream Q4OS Calamares installEFIFallback: true and its unreviewed process hooks remain blocked; the Windows ESP, BCD and WinRE are never exposed to this workflow.
- A future separate Windows 10/11 QCOW2 lab must demonstrate recovery snapshots/checkpoints, exact GPT ownership, both Windows/Linux boot, kernel updates, uninstall and rollback independently. These tests do **not** constitute stability evidence.

Preserve the existing Mint/Zorin backends and keep Q4OS out of the stable catalogue. Do not merge this draft before human review under GPL-3.0 and AI_POLICY.md.
