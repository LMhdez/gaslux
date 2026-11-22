# Compact Windows 10 + Linux Mint installation VM: target disk foundation

**State:** Real disposable QCOW2 allocation implemented; **no Windows or Mint guest installation has been performed by this component**.

## Why

The older PR #350 used six large images and an initial physical-space estimate of approximately **808 GiB**, versus approximately **85 GiB** historically available on one standard runner. That estimate belonged to a forensic A/B scenario, not a compact Windows + Linux guest installation. The existing VM-capacity PR #368 separately measures host free capacity but still deliberately tests the older historical budget.

This implementation provisions **one private sparse 60-GiB QEMU target disk**, not six 128-GiB snapshots, and measures physical free space before creating it. It provides a real local virtual-disk artifact for a future dual-boot VM, rather than merely simulating a partition table. It does **not** assert that a 60-GiB Windows + Mint install will succeed: that sizing must be verified empirically in guest.

## Provisional storage budget

| Component | GiB |
| --- | ---: |
| One Windows + Linux shared virtual disk (max addressable) | 60 |
| Verified ISO/media download allowance | 4 |
| Snapshot / rollback workspace planning allowance | 8 |
| Reserved runner workspace | 8 |
| **Physical planning total** | **80** |
| Maximum target budget | **85** |

**Important:** a budget is not a filesystem quota. An external snapshot could exceed the 8-GiB *planning* allowance; the instrument therefore **never admits a writable QEMU guest**. A later job must enforce and measure the real writable capacity of all files and snapshots, verify snapshot restore independently, and reject disk exhaustion safely before installation.

## Implemented software behavior

- `auto_tests/tools/compact_ovmf_target.py` measures real `RUNNER_TEMP` free bytes and fails closed below the 80-GiB planning total. It creates an exclusive, mode-0700 temporary directory, calls real `qemu-img create -f qcow2 -o preallocation=off` and verifies the resulting image's format, size, absence of backing files and unexpectedly large initial allocation using `qemu-img info`.
- Refuses caller-supplied image filenames, existing output image replacement, symlink workspace ancestors, root/device directories and non-directory workspaces. Cleans its own private directory after tool failures.
- `.github/workflows/compact-ovmf-target-disk.yml` executes the actual program on ephemeral GitHub-hosted Ubuntu, tests negative cases, independently re-reads the disk geometry, deletes only the image-owned private directory and uploads **JSON evidence only**, never the virtual disk or ISO.
- **No guest receives read/write access**; no Windows/Mint boot, partitioning, BCD/ESP/WinRE, installation, update, uninstall or rollback operation is executed here. No stable catalog or production runtime changes.

## Next real engineering steps

1. Confirm exact current runner capacity and actual successful sparse image creation from CI evidence. `BLOCKED_STORAGE` is a valid measurement, not proof of installation.
2. Verify legally sourced Windows 10 UEFI/GPT test media/VM with exact provenance and reproducible identity. Verify the official pinned Mint 22.3 ISO already defined in `release-config.json`.
3. Define and enforce disposable guest disk ownership and physical quota for all snapshot backing files; prove snapshots restore and preserve authentic Windows ESP, MSR, NTFS OS and WinRE.
4. Boot Windows, verify Windows Boot Manager and recovery baseline, then invoke Gaslux's actual USB-free staging/installer transaction in the isolated guest, not a synthetic bootstrap substitute.
5. Independently observe installed Mint and return to Windows, update and reboot, uninstall and Windows recovery. Preserve exact artifacts and mark release gates only after real evidence.

**Relation to other work:** PR #368 is read-only host capacity admission. This change is the **next distinct step**, producing a real disposable QCOW2 while refusing all guest writes, and does not supersede #368. PR #350 remains a historical expanded forensic scenario. No Proxmox or Oracle VM is presumed.

Generated-by: GPT-6.