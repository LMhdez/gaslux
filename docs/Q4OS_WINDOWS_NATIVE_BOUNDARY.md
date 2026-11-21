# Q4OS — Windows/GPT native target and recovery boundary (experimental)

**NOT installation authority.** This component extends the existing Q4OS #256
laboratory with a deliberately narrow, read-only Windows target and recovery
contract. It neither executes Calamares nor changes the Installer Observer #259.
It does not modify C#/PowerShell production dispatch, boot configuration, the
signed stable catalogue, Windows disks or real user hardware.

## Provenance and firmware boundary

The pinned official Q4OS 6.10 x64 r2 ISO **reference** has SHA-256
`1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d`.
The previous exact ISO/Calamares extraction and checksum evidence is recorded
in [the native Q4OS investigation](Q4OS_BACKEND.md). This contribution **does
not independently redownload or authenticate those ISO bytes**. The published
checksum is not a maintainer-signed Gaslux catalogue entry and does not by
itself authenticate an installation.

Only `uefi/gpt` with a *disposable, private, RAW VM image* is modelled here.
BIOS/MBR, UEFI/MBR, BIOS/GPT, hybrid MBR, complex GPT, ambiguous multiple
ESP or absent Windows Recovery and 4-KiB-sector production systems are not
approved. The code has preliminary 512/4096-byte parsing but no real 4-KiB
Windows boot regression. The proposed root remains **unpartitioned**.

## Read-only trust boundary

`assets/live/gaslux_q4os_windows_boundary.py`:

- Opens only an owned, private `windows-target.raw` regular file, with
  `O_NOFOLLOW`, exact inode/device/size and metadata recheck. It refuses
  physical devices, symlinks, hardlinks, QCOW2 interpreted as RAW and foreign
  image names. QCOW2 must first be exported into a **fresh disposable** RAW
  test file by the controlled laboratory, never onto a physical disk.
- Validates the protective MBR (rejecting hybrid MBR), GPT primary/backup
  headers, both CRCs, full entry-table equivalence, disk GUID, PARTUUID
  uniqueness, exact LBAs and non-overlap. This deliberately rejects unknown
  layouts instead of modifying them.
- Locates exactly one Windows FAT32 ESP, Windows NTFS data, Microsoft
  reserved and WinRE NTFS partition. OEM/other partitions are retained, and
  their entire contents are hashed alongside the ESP/WinRE contents. This
  includes BCD file bytes within the ESP, but **does not parse the BCD store
  or establish BCD runtime validity**. BitLocker/Device Encryption, the
  Windows NTFS volume's full contents, Windows boot, NVRAM/BootOrder, WinRE
  runtime and Secure Boot remain separate mandatory Windows-side gates.
- Checks any proposed Q4OS root is aligned, within usable GPT space and
  disjoint from **every** existing partition, not only NTFS and Recovery.
  Creating a GPT entry itself is a disk write and requires a separate signed
  Windows transaction. This module never creates a partition.
- Requires the previously audited native Calamares 6.10 identity and the
  expected dangerous fallback and hook observations. The **real upstream**
  `installEFIFallback=true` risks writing `EFI/BOOT/BOOTX64.EFI` on the
  Windows ESP. Q4OS native hooks also reference `EFI/debian/grub.cfg` and
  invoke `grub-install --force`. Both routes **remain forbidden**. Editing
  just `installEFIFallback` is insufficient to approve the other hooks.
- Returns a typed JSON proposal under
  `schemas/gaslux-q4os-windows-boundary.schema.json` with
  `installationAuthorized`, `calamaresJobsAuthorized`, `diskWritesAuthorized`,
  `windowsEspWritesAuthorized`, `rollbackVerified` all **false**.

This module cannot authenticate Windows-to-Linux handoff records by itself.
In particular, a caller-provided Python dictionary or an unauthenticated
`checkpoint` object is **not proof of physical disk ownership**, an immutable
baseline or a cryptographically trusted checkpoint. Current outputs are
**laboratory-only structural checks**, never capabilities usable by a writer.
A production caller must independently verify signed Windows-side identity,
transaction ID, plan and evidence before attempting any mutation.

## Checkpoint, comparison and rollback exercise

`verify_read_only_checkpoint()` requires a private `checkpoints/recovery.qcow2`
with an independently supplied SHA-256. It checks SHA-256 over the actual file,
`qemu-img info` geometry, absence of backing file, `qemu-img check`, and
**full-virtual-disk** `qemu-img compare` with the authenticated RAW image.
The same RAW image is then re-inspected for disk drift. The CI test converts
this snapshot into a **second, disposable RAW** and verifies full-byte equality
of the restoration with the original image. It deliberately mutates a
**synthetic throwaway image** afterwards and proves the stale checkpoint
comparison refuses. Original Windows disks are never attached.

`verify_windows_preservation()` independently compares the original partition
geometry, GUIDs and protected partition content hashes with a later raw-image
observation. It cannot establish a successful Windows reboot or recover a
corrupted Windows BCD/NVRAM state; it returns explicit `False` for those
unverified outcomes. A checkpoint on the same runner host is **not** an
independent durable off-host backup. Neither a test snapshot nor a manifest
can substitute for Windows startup/BCD/WinRE/encryption evidence.

## Test instructions and actual limits

The new CI workflow runs Python syntax/lint/schema tests and adversarial pytest
fixtures with `qemu-utils`. It creates *only* a 64-MiB synthetic Windows-style
GPT image, a self-contained QCOW2 and an independent restored RAW image.
No VM guest boot, real Windows filesystem installation, Calamares execution,
EFI/BCD writes, real power loss or dual boot is claimed. Read-only probes on
synthetic bytes are not a Windows recovery certification.

**Dependencies:** Q4OS #256 for ISO audits, hook policies, signed synthetic
plans and existing bounded-COW recovery work; #258 for the cross-distro
playbooks; #259 for any *future* Observer integration. No Observer contract is
modified and its generic VNC input gate remains closed. These dependencies
require human reconciliation before integration into `dev`.

**Remaining production blockers:** signed Windows-side handoff; measured
ISO-to-live provenance; independent disk controller/serial identity; complete
WinRE/BCD/ESP/BitLocker/NVRAM baselines; off-host durable rollback; controlled
GPT/root provisioning; a proven ownership-safe replacement for the Calamares
EFI fallback and shell hooks; automatic Calamares navigation without generic
VNC clicks; Linux **and** Windows boots, updates, uninstall and rollback.
Until these are independently proven, keep Q4OS out of the stable catalogue.

## 2026-11-21 — Genuine Windows evidence and real QEMU/libguestfs preflight

This later evidence extends (but does **not** supersede) the original
synthetic-only checkpoint contract above. All Windows experiments remain
on a new disposable GitHub-hosted 48-GiB QCOW2. No Q4OS installation,
GRUB, EFI fallback, ESP write, firmware change, or rollback was executed.

### Windows failure provenance

The SHA-256-pinned Windows 10 Enterprise Evaluation 22H2 ISO, QMP DVD
one-shot input, Windows Setup, first-logon NTFS marker, QCOW2 structural
check, GPT verify, Microsoft ESP loader and nonempty BCD passed in
[Action #44822087949](https://github.com/LMhdez/gaslux/actions/runs/44822087949)
on Q4OS code SHA `7c46439e97edaa1eba7282007f3d9ac1de780d57`.
WinRE was **not** present or proven. The first failed step was
`Real Windows 10 host GPT versus readonly QEMU guestfs and Safety`.
The appliance failed with the generic libguestfs message
`/usr/bin/supermin exited with error status 1`. No diagnostic from
that run identified a kernel, module, permissions, or filesystem root
cause. The [bounded JSON artifact #14672708757](https://github.com/LMhdez/gaslux/actions/runs/44822087949/artifacts/14672708757)
has ZIP SHA-256
`b0ad97f5b70d0611aa9c0a754a4ebbcdae695651359fb392c95968e2256c4c64`.
It does **not** include a full host/guest GPT witness, Safety host/guest
authentication, QCOW2 SHA before/after, or Windows recovery proof.

### Reused working kernel-selection contract

Q4OS now reuses the Safety #267 Ubuntu hosted-runner helper pinned at
`3f44ae2068fabe875f160ca007393f9e3eb99367`
(`auto_tests/tools/windows_x64_libguestfs_kernel.sh`).
It installs a **matching** `linux-image-generic` and module tree,
checks the selected kernel and `modules.dep`, copies the packaged
root-owned kernel into a private readable runner temp location,
and configures `SUPERMIN_KERNEL`, `SUPERMIN_MODULES`,
`SUPERMIN_KERNEL_VERSION`, `LIBGUESTFS_BACKEND=direct` and
`LIBGUESTFS_MEMSIZE=768`. The executing host kernel is not modified.
Ubuntu 24.04 runners in the successful lab selected
`6.8.0-151-generic`. The earlier genuine-Windows runner installed
libguestfs 1.52.0-5ubuntu3 and supermin 5.2.2-4ubuntu4 but did not
record a complete selected guest kernel/module match.

The new `auto_tests/tools/q4os_libguestfs_preflight.py` boots an
**actual QEMU/libguestfs appliance** against an entirely synthetic
64-MiB GPT regular file. It opens exactly one drive `readonly=1`,
requires the correct logical sectors and geometry, selects it by
a libguestfs label, reads the first/last GPT sectors, uses the pinned
Safety #265 GPT parser for both witnesses, compares GUIDs and PARTUUIDs,
checks the same source file's SHA-256 before/after, proves guest
shutdown/close and removes the private scratch disk.

The first synthetic preflight was refused in
[Action #44889870369](https://github.com/LMhdez/gaslux/actions/runs/44889870369).
A subsequent bounded stage diagnostic in
[Action #44890267890](https://github.com/LMhdez/gaslux/actions/runs/44890267890)
localised the error to `GUESTFS_ATTACH_READONLY` **before** appliance
launch. The Q4OS lab's former hexadecimal drive label included numeric
characters. This conflicted with libguestfs's alphabetic drive-label
contract, already fixed in the audited Safety #267 helper. Q4OS now
uses exactly `gaslux` plus twelve randomly chosen characters from
`abcdef`. The Windows read-only guestfs probe uses the same
labelled-device selection; this avoids trusting device enumeration
order. Unit tests refuse numeric labels and missing or mismatched
kernel/modules, bad geometry, partial GPT, multiple disks,
unexpected supermin failure, timeout, absent provenance and cleanup
failure.

### Real synthetic appliance PASS (not Windows)

[Action #44890525345](https://github.com/LMhdez/gaslux/actions/runs/44890525345)
on SHA `7a950d0b73e5de5a354329293ec258c4b525d778`
returned **SUCCESS**. The downloaded [bounded JSON artifact
#14700594881](https://github.com/LMhdez/gaslux/actions/runs/44890525345/artifacts/14700594881)
has ZIP SHA-256
`35a3741e17ffac6a3128c4db9346cfe7f33185e2da62a11d3a1459af0bb96e7f`.
The JSON records:

- `decision=SYNTHETIC_APPLIANCE_PASS_NO_WRITER`,
  `applianceBooted=true`, `applianceShutdownVerified=true`;
- `guestAttachedDrives=1`, `sourceReadOnly=true`,
  `virtualSizeBytes=67108864`, `logicalSectorBytes=512`;
- `hostGuestGptMatches=true` and the same SHA-256
  `7fcf2df44173cfdc544e5aa37864230d8e8bd1089e615b16326df49fa0a9cd9d`
  before and after the **synthetic** observation;
- `syntheticSourceIntact=true`, `temporarySourceRemoved=true`;
- `trustBoundary=NOT_INDEPENDENT`, `writerPresent=false`,
  `diskWritesAuthorized=false`, `installationAuthorized=false`,
  `rollbackVerified=false`, `guestDiskSerialAuthenticated=false`.

This is a real **synthetic** Linux appliance booted by QEMU, not mocked
hardware and not a Windows guest boot. The same runner controls both
observations and the disk; therefore identity correspondence is NOT
independent remote attestation. The test did **not** rerun Windows,
capture Windows host/guest GPT, prove WinRE, validate BCD contents,
prove Windows rollback, or execute Safety #267 over authenticated
Windows host/guest records.

### Mandatory early Windows gate

The Windows-only workflow
`.github/workflows/gaslux-q4os-windows10-qcow2.yml` still has
**`workflow_dispatch` only**. Before downloading the Microsoft ISO
or creating the Windows QCOW2, it now repeats the *real synthetic
appliance* probe with the **same pinned kernel selector**, exact
Safety #265 reader, no-writer labels, and bounded evidence. If the
appliance fails, it returns `BLOCKED_GUESTFS_APPLIANCE` and
**Windows Setup is not invoked**. The existing Windows read-only probe
also sets the direct backend and uses an exclusively alphabetic
libguestfs disk label, but this exact updated probe still requires
a separate genuine Windows Action to prove the operational path.

The core Safety gate remains pinned to
`f55633c90973f633dda678f583f7730fc2cdc0ce`.
`hostGuestGptMatches=true` in a synthetic experiment does **not**
authenticate production provenance. If independent host/guest
transaction evidence is absent, the only permissible Windows result
remains `DENY_UNAUTHENTICATED`, never `ACCEPT_NO_WRITER` as
installation permission. No production disk, ESP, WinRE or NVRAM writer
has been enabled. The Q4OS PR stays draft and outside the stable
catalogue.
