# Q4OS — bounded guest COW scratch write and recovery experiment

**Status: DRAFT / SYNTHETIC VM ONLY. NOT a Calamares installer, production write authorization or Windows rollback.**

This experiment reuses the signed read-only UEFI/GPT target proposal (PR #182), the guest-observed virtio serial and authenticated report (PRs #183 and #186), and a self-contained signed, independently restored snapshot (PRs #187–#188).

## What is allowed

The GitHub Actions job creates exactly one private 32-GiB raw regular file with protective MBR, valid primary/backup GPT, and one named 512-MiB FAT32 `GASLUX-LAB-ESP`. The QEMU guest sees only a qcow2 overlay of that file, exactly one virtio block device, a private virtio-serial socket and **no network**.

The original production-facing signed plan and Q4OS Calamares settings remain incapable of installation and disk mutation. A **separate Actions-only** write harness requires `GASLUX_Q4OS_SYNTHETIC_WRITE_LAB_ONLY=yes`. Before writing, the guest checks its virtio serial, 32-GiB capacity, logical/physical sector geometry, both GPT CRCs, exact ESP identity and absence of other partitions. It confirms that an exact 4-KiB range located **1 MiB after the beginning of the proposed, still-unallocated Linux root extent** contains only zeros.

The host separately verifies the Ed25519 signed plan and the SHA-256-signed self-contained snapshot, then checks the QEMU Unix-socket peer PID and UID, issues a single fresh challenge, authenticates the guest's prewrite report and sends an HMAC-bound one-use capability for just that offset and 4096-byte marker. The guest re-checks disk identity and zeroed range immediately before exactly one `pwrite` and `fsync`, then returns an authenticated result.

The host must observe the changed 4096 bytes in the COW with `qemu-io`, an actual difference against the base with `qemu-img compare`, and allocated COW blocks confined to the proposed Linux extent. It verifies the unchanged signed base, restores the independent snapshot into a new raw file, compares the entire disk with the base, checks GPT/ESP identity, confirms the marker is absent and discards **only** this transaction's COW overlay.

## What remains explicitly unproven

- This is **not** native Calamares partitioning: no Linux root partition exists and no installer job ran.
- The source Windows 10/11 disk is **not attached**; no EFI/Microsoft loader, Windows Recovery, BCD, BitLocker, NVRAM or dual-boot operation is tested.
- The one-shot HMAC binds the report transport to the QEMU process; it is **not a guest hardware attestation** and cannot withstand arbitrary guest-kernel compromise.
- Snapshot durability is limited to a single ephemeral Actions runner; seven-day artifact retention is not user recovery storage.
- Normal-case COW discard and independent base-image recovery do **not** prove recovery from power loss, a partially installed Linux system, bootloader failure or production Windows rollback.
- BIOS/MBR, Secure Boot, updates, uninstallation, full Calamares installation, Linux first boot and Windows+Q4OS dual boot remain blocked.

An unsafe write, unexpected GPT/ESP/serial, unsigned plan, missing snapshot, foreign file, changed signature, missing explicit opt-in, or unverified readback must fail closed. Do not merge to main/dev or expose Q4OS in the stable catalogue before documented human review, complete VM installation/boot/update/removal/rollback evidence and Windows recovery tests.

GPL-3.0; generated implementation requires human review under AI_POLICY.md.
