# Q4OS QEMU guest identity and read-only recovery checkpoint

This laboratory advances the signed host-file target proposal and guest report parser with an actual QEMU boot. It is deliberately limited to a private, synthetic 32-GiB UEFI/GPT file containing exactly one FAT32 ESP. No Windows disk, physical block device, network adapter or real installation target is attached.

## QEMU identity binding

- The host verifies the Ed25519-signed read-only target plan and re-reads the GPT before launch.
- A per-run virtio-blk serial is derived from the signed plan run ID and nonce. It is exactly 20 ASCII bytes, matching the virtio-blk ID field.
- QEMU attaches only a qcow2 overlay over the owned raw file, with readonly=on; both files are owner-read-only before QEMU starts.
- The guest locates the target by the observed sysfs serial, not by /dev/vda. The device node is diagnostic only.
- The guest requires the kernel block-device read-only flag, opens the block device with O_RDONLY, verifies the protective MBR, both GPT headers and tables/CRCs, exact disk/ESP identity and the FAT32 boot sector.

## Report transport

- QEMU exposes one named virtio-serial port backed by a private Unix-domain socket in a mode-0700 temporary directory.
- The host checks Linux SO_PEERCRED: the socket peer PID and UID must match the exact QEMU process it launched.
- The guest sends a hello; the host returns a fresh 256-bit per-run challenge. The guest returns a bounded report plus HMAC-SHA256 over a domain-separated payload. The host verifies the MAC and then validates the report against the signed plan.
- The challenge secret is ephemeral and is not logged or uploaded.

**Trust boundary:** this is a process-bound local transport with message integrity and freshness, not hardware attestation. The challenge key is delivered to the guest; a compromised guest kernel/root could forge a report. The host therefore independently revalidates the signed backing image after QEMU exits. The result must not be treated as proof against a malicious guest.

## Checkpoint and recovery boundary

The lab creates a qcow2 overlay with an immutable raw backing image, fsyncs the files and a private checkpoint manifest before QEMU starts, reopens and checks the chain after shutdown, compares sparse-content fingerprints before/after, discards the unused overlay and revalidates the backing image.

This proves a **per-GitHub-run read-only checkpoint and overlay-discard path**. It does not prove rollback after a guest write, persistence across runner destruction, Windows VSS/WinRE/BCD recovery, or restoration of a real disk. rollbackVerified remains false.

## Explicitly not tested

- The kernel/initramfs used for this probe is the Ubuntu GitHub runner kernel plus the Gaslux probe, **not the Q4OS live ISO**.
- No Calamares module/job runs; no partition is created or formatted by the guest.
- No installed Q4OS root is booted by this step.
- No Windows 10/11 disk, ESP, BCD or WinRE is attached.
- No updates, uninstall, Windows/Linux dual boot, power-loss recovery or write-enabled rollback is claimed.
- All install, disk-write, Calamares, Windows-ESP-write and rollback authorization flags remain false.

The next safe gate is a separately reviewed, write-enabled disposable-VM transaction with an independently restorable snapshot and fault injection. Only after that can native Calamares job execution be considered.
