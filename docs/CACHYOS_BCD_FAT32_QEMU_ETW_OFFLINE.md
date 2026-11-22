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

## Experimental ESP source/descriptor provenance — synthetic RAW only

`cachyos_bcd_esp_provenance_offline.py` adds a **deny-only** test oracle
for synthetic, 128-GiB sparse **RAW** regular files, not Windows/QCOW2.

Input is an already-open, `O_RDONLY` file descriptor, its pathname, and an
explicit controller claim containing transaction/checkpoint IDs, disk size,
512-byte sector geometry, GPT disk GUID, ESP PARTUUID and exact LBA range,
SHA-256 of primary+backup GPT windows and the full ESP, plus pinned
`st_dev/st_ino/st_nlink/st_size/st_mtime_ns/st_ctime_ns`. The claim is
**not** cryptographically authenticated by this tool.

The reader rejects symlinks/hardlinks, wrong owner/mode, write-capable
descriptors, file/path replacements, divergent inode/metadata, invalid PMBR,
primary/backup GPT CRCs, mirrored GPT mismatches, unexpected fifth/sixth
partitions, wrong disk GUID/PARTUUID and incorrect ESP offsets or hashes.
It reuses `windows_cachyos_qcow2_gpt_readonly.header_at()` and
`part_array()` from the existing lab, and `map_bcd_fat32()` without
implementing another FAT32 parser. Two ESP byte reads and two GPT-window
reads must agree; the last `fstat/lstat` must still match the pinned
descriptor. SHA-256 is computed over **captured bytes**, not a supplied hash
alone. No path or source byte content appears in the result.

Its result `SYNTHETIC_RAW_FD_MEASURED_DENY_ONLY` supports
`twoPassEspBytesEqual=true` and
`primaryBackupGptConsistent=true` for the supplied synthetic fixture.
It always has `historicalEspProvenanceAuthenticated=false`,
`qemuBlkNodeToDiskAuthenticated=false` and
`productionStorageWritesAuthorized=false`.
A writable file can be modified and restored between reads; **double
readback cannot prove snapshot immutability or absence of intermediate
writes**. Thus this is a structural/readback test, not a signed replay-safe
source attestation.

**QCOW2 must not be passed to a raw descriptor reader.** `pread(fd,
LBA*512)` on a QCOW2 container is *not* a guest-sector read. A future
read-only QCOW2 capture requires an independently frozen and verified QEMU
virtual block graph backed by pinned regular FDs, source/overlay/backing
hashes, a read-only sector extraction API, and a signed transaction/nonce
with external ownership proof. A path or self-declared SHA is insufficient.

The current `dev` branch exposes reusable HOST-only
`auto_tests/installer_observer/host_fd_boundary.py`: `process_seal()`
measures PID generation, command/executable identity; `_execute()`
allowlists `qmp_capabilities` and `query-block`. Both remain host
measurements, not a complete QEMU block-node-to-open-FD binding. This
experimental PR **does not vendor or fork** the HOST/FD module from `dev`.
The branch and commit must be reconciled by the Integrator before reuse.

`evaluate_untrusted_qemu_claim()` separately rejects malformed claim
shape, ambiguous QEMU process count, changed PID generation/executable,
substituted inode, changed backing SHA, missing/mismatched trace digest and
ambiguous QMP node labels. Even a perfect synthetic claim returns
`QEMU_PROCESS_FD_CONSISTENT_BLK_POINTER_UNBOUND` and
`qemuBlkNodeToDiskAuthenticated=false` because runtime `blk 0x...`
pointers are not externally authenticated by QMP node names or /proc PID.
No provenance is established by matching LBA offsets on two disks.

**Trust boundary still open:** independent signed host transaction → pinned
snapshot/overlay/backing FDs → QMP block node identity → QEMU trace
runtime `blk` pointer. A verified /proc-FD inventory plus QMP node name
does not establish the final pointer link by itself. Process tokens may
be reused across QEMU instances and traces can lack timestamps.

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
normalizer**, not an ETL parser or recorder. The ETW-01 Safety review identified
false-positive diagnostics from reversed FileIO/DiskIO timestamps, ambiguous
PID generations, reused FileObject/IRP and missing provenance. **Exporter v1
does not establish PID-generation identity, bounded time proximity, file-object
lifetime, causal event order, QEMU disk identity or trusted ETW/QEMU clocks.**
No arbitrary FileIO→DiskIO time window is claimed as an ETW provider guarantee.

For compatibility, `plausibleIrpLifetimeMatches` is **deprecated and always
zero**, with `plausibleIrpLifetimeMatchesDeprecated=true`. This is intentional:
there are **no** validated plausible matches in the exported synthetic v1
contract, including an otherwise well-formed illustrative fixture.

The positive illustrative example is preserved as
`sharedIrpIdentifierCoincidences=1` and
`sharedIrpIdentifierSemantics=UNORDERED_TOKEN_EQUALITY_ONLY_NOT_CAUSAL`.
This counts only IRP tokens appearing **exactly once** in FileIoWrite events
and **exactly once** in DiskIoWrite events within the provided export.
It is independent of timestamps, ProcessStart/Stop and FileObject names:
coincidence **is not** proof that the operations are related or that a file,
process, PID generation, device, GPT partition or Windows BCD sector was written.
Two FileIoWrite or two DiskIoWrite entries reusing one IRP yield zero
unique-token coincidences. A reversed-time or lost-event fixture may still
contain identifier coincidences, but **never** a plausible/causal match.
Consumers MUST NOT use this diagnostic to authorize changes or infer writer
identity.

The status is always `PROCESS_ATTRIBUTION_UNPROVEN`; all of
`processAttributionProven`, `qemuClockAlignedToEtw`,
`qemuDiskNodeAuthenticated`, `diskNumberBoundToGptIdentity` and
`approvedMutation` remain false. Missing timestamps, PID, file identity,
node binding, event losses, time-base calibration and events before session
start block causal inference. `sessionCompleteWithinDeclaredWindow` reports
only no recorded lost events/buffers and present event timestamps, **not**
complete observation of Windows boot or validated per-process chronology.

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
