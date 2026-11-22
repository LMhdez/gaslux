# POP-DISTINST-PREWRITE-01 — native System76 write boundary (offline, DENY ONLY)

Status: **PREWRITE_PLAN_UNAVAILABLE / DENY_NO_WRITER**. This is a
read-only source examination plus an inert contract over existing Gaslux
Win10/Pop six-GPT shaped inputs. It is **not** proof that Pop!_OS installs,
preserves a genuine Windows boot chain, or offers a safe native dry run.

## Which installed media, and which source?

The Gaslux *laboratory* fixes Pop!_OS **24.04 Intel build 20**:
`pop-os_24.04_amd64_intel_20.iso`, URL
`https://iso.pop-os.org/24.04/amd64/intel/20/pop-os_24.04_amd64_intel_20.iso`,
size **2,955,067,392** bytes, ISO SHA-256
`a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c`;
the live-guest ELF observation fixes `/usr/bin/distinst` SHA-256
`8bfedbc2d6921c440449ec1fda8c4e4d1c0078d69db5aa5832d9a7bf8b13e1a5`.
System76 GPG fingerprint pinned by the existing laboratory:
`63C46DF0140D738961429F4E204DD8AEC33A7AFF`.
See `windows10_popos_official_iso_signed_lab.py` and
`windows10_popos_distinst_readonly_observer.py`. This PR does **not**
redownload or execute the ISO, verify any new signed manifest, or execute
`distinst`.

The official [24.04 ISO build configuration](https://github.com/pop-os/iso/blob/8a441114a3332f0409d39bc940f4b149fb896870/config/pop-os/24.04.mk)
includes the `distinst`, `pop-installer` and `pop-installer-casper` packages.
The official front end `pop-os/installer` and CLI/libraries in
`pop-os/distinst` are **distinct layers**. An experimental
`pop-os/distinst-v2` repository exists but is not substituted for the
laboratory's pinned ELF without independent package provenance.

Reviewed upstream **source snapshot**:
[`pop-os/distinst@282dfc441ee608e963930d0ce01f04b672ca4f71`](https://github.com/pop-os/distinst/tree/282dfc441ee608e963930d0ce01f04b672ca4f71),
observed 2026-11-22. This is a current source snapshot, **not** an authenticated
reconstruction of the build-20 `distinst` ELF. No SHA-256→Git commit/source
matching evidence is available for that installed binary; the classifier
therefore always sets `sourceToInstalledElfCorrespondenceVerified=false`.

## Precise native control flow visible in the inspected source

| Stage | Exact upstream source | Observation and boundary |
| --- | --- | --- |
| CLI options | [`cli/src/main.rs`](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/cli/src/main.rs) | `--block`, `--use`, `--test`, `--no-efi-vars`, `--modify-boot`; parses disks via `configure_disks`, then calls `installer.install` |
| Partition selection | [`cli/src/configure/reuse.rs`](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/cli/src/configure/reuse.rs) | `:reuse` does not call `format_with`; a specified FS **does**. Neither establishes GPT immutability |
| Initialization | [`src/installer/steps/initialize.rs`](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/src/installer/steps/initialize.rs) | device-map deactivation/unmounts and input checks: state-changing preparation already exists before partitioning |
| Persistent disk write | [`src/installer/mod.rs`](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/src/installer/mod.rs) → [`steps/partition.rs`](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/src/installer/steps/partition.rs) | **`Installer::partition` invokes `disk.commit()`** on selected physical disks, then formats partitions and reloads device layouts |
| Device operations | [`crates/disk-ops/src/ops.rs`](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/crates/disk-ops/src/ops.rs) | `open_device(path)` / `open_disk` / `commit`, plus create/remove/resize, can re-open devices by pathname |
| `--test` exit | [`src/installer/mod.rs`](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/src/installer/mod.rs) | `PARTITIONING_TEST` is checked **after** `Installer::partition` and `mount_all_targets`; **`--test` is NOT a read-only dry run** |
| System install | `Installer::extract` → `configure` | executes only if not returning from test, after potential disk mutations |
| Native boot | [`steps/bootloader.rs`](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/src/installer/steps/bootloader.rs) | BIOS runs `grub-install` targeting the device; Pop!_OS UEFI invokes `bootctl install --path=/boot/efi --no-variables`, and `efibootmgr` only when `MODIFY_BOOT_ORDER` is selected |

The reviewed `--no-efi-vars` switch affects EFI variable mounting.
`bootctl --no-variables` does not by itself prove that Microsoft EFI files,
BootOrder, BootNext, independent ESPs or the Windows Boot Manager are safe.
The boot strategy above belongs to **this upstream revision** and must not
be ascribed to the pinned build-20 binary until source correspondence is
verified.

## Why a native pre-write proposal is unavailable

The inspected API exposes disk configuration and `disk.commit()` as an
effectful execution stage; it does **not** expose an authenticated complete
write-set, including GPT/PMBR/partition metadata, formatters and EFI paths,
that can be evaluated and frozen **before** committing. The CLI `--test`
cannot fill this gap: it reaches partition commit and mounts first.
A successful `--help`, `:reuse`, external static write-set or current
upstream Rust code review is insufficient to confine the pinned ELF.

The pre-existing Gaslux `windows10_popos_native_write_set.py` already
enumerates allowable Pop partition resources and excludes Windows; this is
an **INERT declaration**, not a plan emitted by System76 and not a write
barrier. Its strict six-GPT validation is reused by
`gaslux_popos_distinst_prewrite_gap.py`. The new code checks only
shape, expected build-20 hashes, transaction, disk identity, recovery-shaped
checkpoint, protected Windows partitions, EFI policy and an explicit
non-executable request; it emits **no CLI arguments, writer flag or boot
permission**. A forged JSON hash/boolean cannot make the underlying
source or host evidence authentic.

`schema/popos-distinst-prewrite-deny.schema.json` is deliberately
fail-closed: `decision=DENY_NO_WRITER`, all production/boot/rollback flags
are fixed `false`. This contract may aid audits; it cannot be consumed as
permission to run `distinst`, `--test`, `mkfs`, `sgdisk` or other writes.

## Remaining gates

1. Independently prove the native source revision **corresponds to the pinned
   installed ELF** and inventory the exact Pop 24.04 build-20 CLI effects.
2. Obtain a genuine **complete pre-write proposal** (or create an independently
   attested boundary that intercepts all effects before mutation) for the
   same authenticated physical/guest disk and transaction, including the
   first possible GPT commit and all secondary filesystem/EFI writers.
3. Pin authenticated resource descriptors/geometry from preflight through
   actual commit with no pathname reopens; verify BootOrder, BootNext,
   systemd-boot file destinations, Microsoft EFI hashes and updates.
4. Demonstrate rollback, Windows + Pop boot and update in disposable
   Windows 10/11 VM snapshots; get formal independent Safety review before
   any production writer.

**Persistent guarantees NOT proved:** `allExternalToolsIsolated=false`,
`sameUidInPlaceWriteIsolationProven=false`,
`qcow2BackingResolutionAuthenticated=false`,
`observationComplete=false`, `distinstExecutionAuthorized=false`,
`windowsWriterAuthorized=false`,
`productionInstallationAuthorized=false`,
`sameDiskDualBootVerified=false`,
`windowsInPlaceRollbackProven=false`, `releaseEligible=false`,
`stable=false`.

No `distinst`, QEMU-system, Windows Setup, ESP/GPT/BCD/WinRE/NVRAM writes,
physical disks or real installation were used in this investigation.
