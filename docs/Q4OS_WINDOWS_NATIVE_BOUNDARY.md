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
