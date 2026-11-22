# CachyOS BCD/FAT32/QEMU offline forensic boundary (experimental)

This document **does not authorize Windows disk writes, ESP repair, BootNext,
kernel updates, or additional QEMU/Windows/ETW runs**. The experimental
CachyOS PR stack is #248 → #263 → #279 → this offline-only PR. Issue #3
remains the release gate. Human Safety review is mandatory.

## Inputs and trust levels

| Input | Meaning | Trust limitation |
|---|---|---|
| Original run #44900941635 ZIP | 42 SHA-checked evidence members; COM1, GPT metadata, BCD hash manifests, two QEMU traces | No raw authenticated FAT32 ESP image, no signed QEMU blk-pointer-to-disk binding |
| FAT32 mapper | Complete byte-exact synthetic or separately authorized read-only ESP capture, **plus** GPT start/end/sector/disk size | A structurally valid map alone does **not** authenticate the source disk or capture time |
| QEMU trace parser | Literal QEMU simple trace text `blk_co_pwritev blk ... offset ... bytes ... flags ...` | The `blk 0x...` values are runtime pointers, not stable disk IDs |
| ETW normalizer | Hypothetical reviewed exporter fields from Windows 10 build 19045 | Neither ETW capture nor verified clock alignment occurred |

**Do not export the original Windows hive, ESP image, QCOW2, OVMF VARS,
swtpm states, passwords, keys or original ETW payload into a public PR.**
Only minimal bounded offsets, counts, digests and synthetic fixtures belong here.

## FAT32 mapping algorithm

- Interpret the ESP as an exact bounded read-only byte sequence; require
  disk sector size 512 and partition geometry matching independent GPT evidence.
- Validate FAT32 BPB, media signature, root cluster, FAT entry capacity, number
  of data clusters (at least 65,525), reserved sectors, mirrored FAT32 tables,
  FSInfo and backup sectors. Ambiguous/divergent metadata is **refused**.
- Traverse `EFI/Microsoft/Boot/BCD` with 8.3/VFAT checksums, case-insensitive
  path component matching and duplicate-name refusal.
- Walk file/directory cluster chains with cycle detection, range checks, bad
  cluster detection, exact allocation, fragmentation support and
  ESP/disk byte bounds.
- Output `bcdDataExtents` as **guest-disk physical-byte** intervals;
  FAT/FSInfo/boot/directory clusters are distinct `fat32MetadataExtents`.
  File-relative byte offsets and QCOW2 host-file offsets are different domains.
- Return `FAT32_STRUCTURAL_MAP_ONLY`, never a signed/proven live disk state.

In run #44900941635, the ESP occupies GPT #1, LBA 2048–534527,
512 bytes/sector, within a 137,438,953,472-byte virtual disk. The ZIP contains
no FAT32 BPB or cluster chain (only hashes/metadata), so the **only defensible
historical result** is `BCD_PHYSICAL_MAPPING_UNAVAILABLE`. Do not infer
clusters from the 28,672-byte BCD file size or the 682 changed bytes.

Reference structure: Microsoft *FAT32 File System Specification* (v1.03),
notably BPB/FSInfo, FAT mirroring and VFAT directory entries.

## Actual QEMU trace format and non-attribution

The original two `.bin` files are **text** traces, with no timestamp field;
the tool recognizes the actual available event names and parses top-level
`blk_co_pwritev` only. Lower-layer `bdrv_co_pwritev_part`/`qcow2_writev_*`
are not added to the count, avoiding duplicate counting.

| Historic arm | Top-level writes | Geometric ESP overlaps | Distinct ESP start offsets |
|---|---:|---:|---:|
| Windows-only A | 7,403 | 38 | 11 |
| Archiso/pacstrap treatment B | 7,423 | 38 | 11 |

The records have **more than one `blk` pointer**. Reusing pointer values across
different QEMU processes is invalid; naming a disk or assuming the first block
device is Windows is not a cryptographic or QMP-proven binding.

`UNMAPPED_ESP_WRITE` is mandatory without independent authenticated
`blk`-pointer → QCOW2 → guest-disk geometry evidence. A restricted
`SYNTHETIC_FIXTURE_ONLY` binding exercises the interval classifier and can
produce `BCD_DATA_SECTOR_OVERLAP`, `FAT32_METADATA_OVERLAP`,
`ESP_OTHER_SECTOR_OVERLAP`; it **never** asserts live provenance,
specific bytes changed or an identified process. `PROCESS_UNATTRIBUTED`
is always retained.

A write overlapping a BCD data sector is not necessarily a BCD write:
filesystem allocation, metadata, sector coalescing and cache writes can
touch the same extents. Final hash inequality does not reveal intermediate
write times. QEMU traces have event order but no monotonic timestamps;
there is no established ETW↔QEMU timebase.

## Future ETW correlation contract (never collected here)

Windows 10 build **19045**. Use only a Safety-approved local Windows guest,
not a remote-control agent. Capture **ProcessStart/ProcessStop**, **FileIoName**,
**FileIoWrite**, **DiskIoWrite** from the documented kernel trace classes.
These are *different* event classes: native fields vary by provider/version.
The proposed exporter must normalize them explicitly; **do not invent a single
event carrying filename, PID, file object, disk LBA and IRP all at once**.

A future signed capture manifest must include:

1. VM/boot/disposable QCOW2 checkpoint identities; ESP GPT GUID/PARTUUID,
   sector size, byte offsets, before/after hashes, OVMF/TPM state identity.
2. ETW session ID, Windows build, provider GUIDs/event IDs/versions, start
   and stop, time base (QPC frequency and independent calibration to QEMU
   clock, or verified system time), overflow/lost-event/buffer counters.
3. Per-process start/end and PID reuse epochs; bounded file-object lifetime
   and FileIo_Name association; FileIo_Write identifiers if emitted.
4. DiskIo transfer offset/length, disk identity, and matching IRP pointer
   **only when both event types actually expose it**; identify caching,
   deferred writes and system-process attribution ambiguity.
5. Startup coverage: events *before* the ETW session starts are not
   observable without a separately reviewed boot-time capture strategy.
6. Witness closure: complete COM1 and real guest shutdown, capture-sidecar
   SHA-256, no partial trace or dropped buffers; independent node/clock
   binding. Do not expose raw ETL/hive/other PII publicly.

`cachyos_bcd_etw_contract_offline.py` is a **strict exported-event fixture
normalizer**, not an ETL parser or recorder. Even a FileIo↔DiskIo IRP
candidate with matching PID lifetime remains
`PROCESS_ATTRIBUTION_UNPROVEN` because a correlation is not sufficient
causal evidence. Missing timestamps, PID, file identity, node binding,
ETW losses or QEMU clock calibration force this outcome.

Authoritative reference: Microsoft Learn *Process*, *FileIo*, *DiskIo*,
*DiskIo_TypeGroup1*, *FileIo_Info*, *Event Tracing Sessions*, and
*EVENT_TRACE_PROPERTIES* ETW reference documentation.

## Future experiment — explicitly disarmed

**Stage A (no pacstrap):** Windows-only A1 and A2 from *independent*
authenticated QCOW2 checkpoint copies, private OVMF VARS and TPM clones.
Same QEMU CPU/machine/firmware/boot count and audited GPT/BCD/WinRE/ESP;
instrument both with authenticated FAT32 snapshots, QEMU node binding and
approved ETW capture. Classify A1/A2 BCD differences and lost events.

**Stage B (conditional):** only after Safety reviews A1/A2 and the Windows
side's repeatability, consider B1/B2 with the existing Archiso/pacstrap
grant. Capture an additional checkpoint **after pacstrap and before Windows**,
plus independent protection hashes. Never conflate pacstrap with the ensuing
Windows boot.

Mandatory preconditions before any new real guest job:

- Specific written human authorization for that disposable VM experiment.
- Safety review and pre-write transaction/write-set agreement.
- Independently recoverable and inspected COW/OVMF/TPM checkpoints.
- Cryptographically verified ISO and baseline, typed plan, geometry and IDs.
- Approved private evidence handling, trusted clock and node bindings,
  tested offline instrumentation, bounded traces and no live disk writers.
- Fail-closed BCD hash and Windows Recovery validation. Preserve original
  Windows Boot Manager/ESP/BCD/WinRE; no automatic repair or new bootloader.

**This PR does not arm Stage A or B.** It does not alter the operational
workflow, signed metadata, Safety, installers, firmware, disks or catalog.

## Gate status

`approvedMutation=false`
`productionStorageWritesAuthorized=false`
`sameDiskDualBootVerified=false`
`rollbackProven=false`
`releaseEligible=false`
`stable=false`

The historical lab demonstrated Windows and experimental CachyOS auxiliary
boots on disposable COWs, but changed protected BCD in both arms. No native
same-disk dual boot through a persistent loader, Windows in-place rollback,
post-update boot or hardware deployment has been established.
