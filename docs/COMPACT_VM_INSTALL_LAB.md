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

## Private hard-quota ENOSPC fixture (separate proposed change)

The same existing compact workflow builds a **384-MiB exclusively owned sparse file**, formats it as ext4 and mounts only its exact loop-device mapping under a private runner workspace. It creates a **real** QCOW2 baseline and overlay on this bounded filesystem. The fixture verifies backing-chain ownership, then fills ext4 to leave a measured 3-MiB reserve. A real `qemu-io` write must fail specifically with **ENOSPC**. Baseline SHA-256 must remain unchanged; the fixture deletes only its owned overlay and filler, recreates the overlay, and verifies the baseline canary after restoration. Foreign loop sources, symlinked workspaces, unrelated write failures, insufficient host reserve, or failed unmount **fail closed**. A failed unmount leaves the workspace intact instead of traversing a mounted directory.

The output is `evidence/compact-qcow2-quota-fixture.json`. It proves physical-limit behavior for a **384-MiB synthetic ext4 loopback fixture only**. `real_60gib_quota_verified=false`, `lab_writer_admitted=false`, and all installed/Windows/dual-boot/rollback assertions remain `false`. No guest receives write permission. A future full-size lab must establish effective capacity, bounded baseline+overlay growth, authentic Windows media, and independent Safety acceptance. If a GitHub-hosted runner cannot mount the private loop device, the test must report blocked, not a false success.

## Full-scale physical reservation evidence (2026-11-22)

Unlike the smaller 384-MiB ENOSPC fixture, the full-scale test **preallocates** a physically backed 60-GiB regular file and verifies real allocated blocks, a private ext4 loopback, an actual 60-GiB QCOW2 baseline and matching overlay, read/write canaries, baseline SHA-256 and overlay reset. It reserves at least **16 GiB of independent HOST storage** before and after preallocation. When the available space is too low, the test emits a blocked preflight report without allocating anything. The full-size container acts as an effective upper bound for its contents, but this test does not fill the full 60-GiB volume, boot a guest, authenticate a Windows installation or exercise a real Windows rollback.

**First positive run:** [GitHub Actions #45067460540](https://github.com/LMhdez/gaslux/actions/runs/45067460540) on PR #388 at HEAD `8acb15596275de55a8e67b5f414e68fd63498513`; real source report `PRIVATE_60GIB_QUOTA_AND_QCOW2_VERIFIED`. Measured physical allocation: **64,424,517,632 bytes**, ext4 usable total **63,090,503,680 bytes**, initial runner free **94,829,649,920 bytes**, backing SHA-256 `a4787af8ab9c5a71734fb59c5cb8ccd66add709d6b54ff64dd2c741e645dfe41`. All guest installer/Windows/dual boot/recovery assertions remain false. It is not release admission and is not independent GASLUX-SAFETY approval.

## Windows ISO identity intake

`auto_tests/tools/windows_media_intake.py` introduces a read-only ISO path/format/SHA/TOCTOU verifier using Microsoft's published [Windows 10 22H2 ISO SHA-256 table](https://www.microsoft.com/en-us/software-download/windows10ISO). The current reviewed entries are Portuguese (Portugal) x64 `83F83B5A9101F5FA21DE4E925ABC7693478D84CD5FBF02CB019393048B5BDBBB` and English x64 `A6F470CA6D331EB353B815C043E327A347F594F37FF525F17764738FE812852E`. These hashes identify exact ISO bytes only; valid product licensing, installed Windows GPT/ESP/BCD/WinRE state and guest provenance require separate evidence. There is no Windows ISO in GitHub artifacts or attached to the VM; workflow output is explicitly `BLOCKED_MEDIA`. Official media must be obtained through the applicable Microsoft download process and delivered privately under its permitted terms before Windows Setup can run. Never store a Windows ISO, license key, user information or installed guest disk as a public artifact.


## Next real engineering steps

1. Confirm exact current runner capacity and actual successful sparse image creation from CI evidence. `BLOCKED_STORAGE` is a valid measurement, not proof of installation.
2. Verify legally sourced Windows 10 UEFI/GPT test media/VM with exact provenance and reproducible identity. Verify the official pinned Mint 22.3 ISO already defined in `release-config.json`.
3. Define and enforce disposable guest disk ownership and physical quota for all snapshot backing files; prove snapshots restore and preserve authentic Windows ESP, MSR, NTFS OS and WinRE.
4. Boot Windows, verify Windows Boot Manager and recovery baseline, then invoke Gaslux's actual USB-free staging/installer transaction in the isolated guest, not a synthetic bootstrap substitute.
5. Independently observe installed Mint and return to Windows, update and reboot, uninstall and Windows recovery. Preserve exact artifacts and mark release gates only after real evidence.

**Relation to other work:** PR #368 is read-only host capacity admission. This change is the **next distinct step**, producing a real disposable QCOW2 while refusing all guest writes, and does not supersede #368. PR #350 remains a historical expanded forensic scenario. No Proxmox or Oracle VM is presumed.

Generated-by: GPT-6.