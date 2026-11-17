# Q4OS integrated QEMU identity + snapshot rehearsal

**Experimental, read-only, synthetic UEFI/GPT fixture only.** This workflow composes the existing signed target plan, self-contained snapshot/restore lab and QEMU guest identity/transport lab in one GitHub Actions job, against the same runner-owned target image.

## Execution order

1. Build one new 32-GiB sparse synthetic GPT file with one 512-MiB FAT32 ESP and create its signed read-only plan.
2. Create a self-contained qcow2 snapshot, restore it to a new host file, compare the complete virtual contents, and independently verify GPT/ESP identity and FAT32. The scratch restore is removed after verification.
3. Build the minimal Linux identity initramfs and boot QEMU against a qcow2 overlay over that same signed target.
4. Bind the guest-visible virtio disk by the plan-derived 20-byte serial, check the exact GPT/ESP geometry, and authenticate the report over the private virtio-serial Unix socket. The host checks SO_PEERCRED against the launched QEMU PID/UID and verifies HMAC-SHA256 freshness/integrity.
5. Revalidate the backing image and preserve both sets of evidence as one seven-day Actions artifact.

## What this proves

It proves that the snapshot/restore and QEMU identity/transport stages can run in one CI job against the same disposable target, and that the guest can boot and report the exact target identity after the snapshot has been restored and revalidated. The base image is unchanged; the guest block device remains kernel- and QEMU-read-only.

## Explicit limits

- The guest is a minimal Ubuntu-runner-kernel/initramfs probe, **not Q4OS**.
- This workflow does not install Windows 10, does not attach a Windows QCOW2, and does not run OVMF or a Windows boot manager.
- No guest disk writes or controlled guest mutations are attempted. Snapshot recovery after guest writes, abrupt power loss or runner destruction is **not** proven; `rollbackVerified=false`.
- The QEMU identity transport is process-bound and HMAC-authenticated, not hardware attestation. The challenge key is visible to the guest, so a compromised guest can forge its own report.
- No Calamares partitioning, formatting, hooks, root install, GRUB installation, first boot, update, uninstall or Windows ESP/BCD/WinRE operation is performed.
- The ephemeral signing key used by the lab is not a production trust anchor. The Actions artifact retention period is seven days and is not a production backup policy.

The next gate remains a separately provisioned Windows 10 QCOW2 created from an official Microsoft installation image, followed by a dedicated write-enabled disposable transaction with exact target identity, independently restorable checkpoints, Windows boot/WinRE/BCD validation and fault injection. Only after those proofs and human review may any bounded Calamares write experiment be considered.
