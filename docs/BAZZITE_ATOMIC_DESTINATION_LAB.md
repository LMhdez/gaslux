# Bazzite Atomic destination — read-only synthetic GPT experiment

Experimental, **not** a supported installation backend. This experiment is stacked
on PR #250 and refers to issue #254. The legacy Bazzite 42 ISO lacks independent
signature/attestation in this lab. Do not authorize Anaconda, Blivet-GUI, GPT,
ESP, formatting, EFI/NVRAM, deployment, or real Windows disk access.

## Native installer and source boundaries

- Modern live ISO: upstream documentation describes automatic partitioning;
  it is not evidence of controlled Windows partition preservation.
- Legacy installer: previous QEMU/OVMF evidence observed Anaconda's Destination,
  Custom and Advanced Custom (Blivet-GUI). An OCR-observed editor does not prove
  the actual Blivet action graph, payload digest or safe installation.
- Upstream legacy manual partitioning documentation describes a new 300 MiB
  /boot/efi ESP, a 2 GiB ext4 /boot partition, Btrfs root, and /, /var,
  /var/home subvolumes. This is a **candidate topology**, not a validated
  installer write-set for a current, signed image.
- Never reuse, format or mount the Windows ESP as the proposed Bazzite ESP.
  Whether this separation is accepted by the exact Anaconda/payload build
  still needs direct observation and boot tests.

Upstream:
https://docs.bazzite.gg/General/Installation_Guide/manual_partitioning/
https://docs.bazzite.gg/General/Installation_Guide/install-guide/

## Proposed write-set and mandatory future gate

The script `auto_tests/bazzite_atomic_destination_plan.py` audits the synthetic
70 GiB GPT fixture and emits three *proposals* inside the actual trailing free
extent, corresponding to GPT slots 4–6:

1. New, separate 300 MiB EFI system partition (proposed FAT, /boot/efi).
2. New 2 GiB ext4 /boot.
3. New Btrfs root in remaining aligned free space, with /, /var and /var/home.

For the synthetic fixture, partitions 1–3 are immutable protected GUID-typed
placeholders; they contain no Windows installation or filesystems. The script
reads actual GPT disk GUID, partition UUIDs, sector size, slot count and free
range using `sgdisk`. It does not mutate anything.

**A new GPT entry always changes shared primary and backup GPT metadata and
potentially the protective MBR**, even when all new partition *data extents*
are disjoint from Windows. The report deliberately refuses GPT metadata write
authorization. Prior to any future write, an authenticated recovery snapshot,
exact table/PMBR sector-level diff, named owner/transaction, Anaconda action
graph comparison, unchanged Windows partitions/ESP/BCD/WinRE and tested
Windows boot/recovery must all be demonstrated in disposable Windows VMs.

The resulting JSON always contains:

- `installationAuthorized=false`
- `partitionWriteAuthorized=false`
- `gptMetadataWriteAuthorized=false`
- `windowsEspWriteAuthorized=false`
- `nvramWriteAuthorized=false`
- `secureBootEnrollmentAuthorized=false`
- `stableCatalogAuthorized=false`

No output from this script is an installation credential or a production plan.
The 20 GiB synthetic Btrfs floor is a lab reject threshold, **not** a verified
Bazzite minimum, nor a replacement for production sizing/preflight.

## Reproduction and scope

The workflow `gaslux-bazzite-atomic-target-readonly.yml` uses an ephemeral
GitHub-hosted runner, the existing real GPT fixture creator, `sgdisk`, and
QEMU/OVMF **paused at startup**. Its monitor inventory confirms only the
intended readonly QCOW2 attachment and serial; no guest boots and there is no
actual Anaconda execution in this workflow. Prior installer screenshots are
in the separate #214/#250 evidence. The QCOW2 overlay is discarded and backing
immutability is audited. The workflow cannot prove guest-side disk identity.

Unproven: independent signature of the legacy installer/payload; real
Anaconda/Blivet edit actions; formatting and Atomic deployment; Linux first
boot; Windows boot; kernel updates and deployment rollback; EFI preservation;
uninstallation; recovery or stable release eligibility.

BIOS/MBR, Secure Boot enrollment, foreign partitions and real Windows
installations are rejected by construction. No stable catalog changes.
