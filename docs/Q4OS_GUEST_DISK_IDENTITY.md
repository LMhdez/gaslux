# Q4OS guest-visible disk identity — read-only gate

This contract follows the signed host-file GPT proposal. It derives a per-run virtio serial of exactly 20 ASCII bytes (the virtio-blk serial field limit) from the plan run ID and nonce, then checks the guest-observed serial, exact capacity, logical sector size, GPT disk GUID and the single ESP's GUID, type, label, geometry and filesystem.

The `/dev/vdX` path is diagnostic only and is never used as identity. Reports are bounded to 16 KiB and duplicate/unknown fields, stale run/nonce, extra partitions and mismatches are rejected. The result is an identity observation, not an authorization token.

## Critical limitations

- The guest report is not cryptographically attested. A compromised guest can forge JSON; the host must bind QEMU's device configuration and transport to the expected VM and independently re-read the backing file after guest shutdown.
- This contract does not launch QEMU, collect a virtio-serial report, create a root partition, take a recovery snapshot or run Calamares.
- Installation, disk writes, Calamares jobs, Windows ESP writes and rollback remain unauthorized/unverified.
- The fixture is a disposable 32-GiB UEFI/GPT lab disk with one ESP, not a Windows disk. No Windows ESP, BCD or WinRE is attached.
- GitHub Actions runs parser/contract tests only; it does not claim a QEMU guest boot.

A later step must implement the QEMU device/transport binding and prove the report came from that exact guest before any write-enabled experiment.
