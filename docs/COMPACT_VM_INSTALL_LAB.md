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

## MINT-LEAN-CAPACITY-RESTORE-01 — no-guest fixture extension (22-11-2026 UTC)

**This is not Safety admission.** The existing compact OVMF workflow measures QEMU's fully-allocated QCOW2 upper bound on the **same runner**, reports a physical upper bound plus reserved space, and explicitly records `quota_verified=false`. Its original nominal 80-GiB plan is not a real enforceable quota, and the true QCOW2 fully allocated bound may exceed that plan.

The existing `compact_ovmf_target.py` now adds a small controlled 16-MiB QCOW2 baseline/overlay fixture, with an explicitly pinned two-entry backing chain, actual `qemu-io` canary write/read, overlay discard and recreation, SHA-256 preservation of its backing image and a separate real installed OVMF_VARS template/copy reset verified by hash. Negative probes reject corrupted QCOW2 metadata, wrong backing target, symlink swaps, incomplete interrupted output, and low-capacity planning. All file operations remain restricted to a fresh isolated 0700 runner workspace; **no QEMU guest is launched**, and the 60-GiB Windows target remains unattached.

**Scope:** a hash-verified baseline with read-only file permissions is not independently immutable Windows recovery. No Windows GPT/ESP/BCD/WinRE guest, Windows ISO/license, Mint installation, installed first boot, uninstall or Windows rollback is demonstrated. No enforceable Windows guest overlay physical quota is proven by this fixture. A real Windows baseline, lawful media, effective quota and independent Safety review are still required for `LEAN_VM_ADMITTED`.

The Core `automation.py` and `automation_preflight.py` still assume a Proxmox-backed Windows VM; the isolated QEMU runner has no authorized Gaslux Windows-manifest handoff yet. A future change must preserve the signed/identified Windows transaction plan and Windows NTFS geometry, not replace Gaslux with an upstream installer or invented manifest.

### Measured RED → GREEN — GitHub Actions, 22-11-2026 UTC

- **RED:** [Actions #45064087180](https://github.com/LMhdez/gaslux/actions/runs/45064087180) on commit `fdc71ecff8a845b4c39025128bada64f30af4917`: 15/15 unit tests passed, but real fixture failed because corrupt QCOW2 was automatically identified as RAW by `qemu-img info` with exit code 0. No success claim.
- **Fix:** Require the actual detected disk format to differ from `qcow2` (or an explicit QEMU error) when asserting rejection of a corrupted image; two regression tests cover RAW autodetection and a falsely valid QCOW2 identification.
- **GREEN:** [Actions #45064275028](https://github.com/LMhdez/gaslux/actions/runs/45064275028), source PR head `c4e38fcb39e6712379e3e2e6ef25a987b71ed450`, same-run checkout at PR synthetic merge `fa92d8a1f0034cab852d0d55dd94b52a5229ec4f`, runner `GitHub Actions 1000013078`, **17/17** unit tests, `RESTORE_FIXTURE_VERIFIED: QCOW2 + OVMF only; no Windows recovery`. [JSON evidence artifact #14770284300](https://github.com/LMhdez/gaslux/actions/runs/45064275028/artifacts/14770284300). Two other applicable contract workflows also passed on the exact PR head.
- **Same-run capacity:** `runner_available_bytes=91233525760`; QEMU fully allocated bound for 60-GiB disk `64434601984`; planned extra reserves `21474836480`; upper bound with reserves `85909438464`; computed shortfall `0` against filesystem availability. Independent effective quota **NOT OBSERVABLE** (`quota_verified=false`). The 85,909,438,464-byte budget counts **one** maximally allocated 60-GiB QCOW2, not the simultaneous frozen Windows backing plus an independently growing overlay. Without an authenticated upper bound for the physically allocated Windows baseline, the conservative two-image maximum at this run is **150,344,040,448 bytes**, 59,110,514,688 bytes above the measured available space. This is a conservative unbounded-case shortfall, **not** proof that a frozen real Windows baseline actually requires 60 GiB. No guest writer admitted. These are resource observations on this single runner, not guaranteed future capacity.
- **Positive bytes:** 16-MiB private baseline SHA-256 before/after `9d7932ff16d14a173a5a92d565e631eed4223b64f4a0ae76580d7da8b29c175a`; installed OVMF_VARS copied baseline and restored work image SHA-256 `a9b2b13aba3d4629593913471af7545bd8eef1d414f33cab4c86fff7d5bc09b9`. Backing chain and read-after-reset verified; corrupt/foreign/symlink/interrupted/insufficient-capacity fixtures denied.
- **Claim boundary:** fixture restore is real QCOW2/OVMF data recovery, NOT installed Windows recovery, effective quota enforcement, Windows ISO authentication, Mint guest install, disk-only first boot or safe production writes. GASLUX-SAFETY has not issued `LEAN_VM_ADMITTED`.

## Next real engineering steps

1. Confirm exact current runner capacity and actual successful sparse image creation from CI evidence. `BLOCKED_STORAGE` is a valid measurement, not proof of installation.
2. Verify legally sourced Windows 10 UEFI/GPT test media/VM with exact provenance and reproducible identity. Verify the official pinned Mint 22.3 ISO already defined in `release-config.json`.
3. Define and enforce disposable guest disk ownership and physical quota for all snapshot backing files; prove snapshots restore and preserve authentic Windows ESP, MSR, NTFS OS and WinRE.
4. Boot Windows, verify Windows Boot Manager and recovery baseline, then invoke Gaslux's actual USB-free staging/installer transaction in the isolated guest, not a synthetic bootstrap substitute.
5. Independently observe installed Mint and return to Windows, update and reboot, uninstall and Windows recovery. Preserve exact artifacts and mark release gates only after real evidence.

**Relation to other work:** PR #368 is read-only host capacity admission. This change is the **next distinct step**, producing a real disposable QCOW2 while refusing all guest writes, and does not supersede #368. PR #350 remains a historical expanded forensic scenario. No Proxmox or Oracle VM is presumed.

Generated-by: GPT-6.