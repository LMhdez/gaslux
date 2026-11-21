# Bazzite: independent Atomic trust and Anaconda write-set boundary (experimental)

**Date:** 2026-11-20. **Dependency:** PR #250 -> PR #262. **Not an install gate.**
No Windows disks, persistent ESP, boot variables, firmware keys, filesystem
formatting, Anaconda commit/install task or deployment writes were used.

## 1. Distinguish four separate identity claims

| Claim | Source and evidence | Current result |
| --- | --- | --- |
| A: local ISO byte hash | Prior lab Actions #44358709061 recomputed SHA-256 for the exact 7,907,770,368-byte historical ISO | Historical byte identity only |
| B: upstream checksum metadata | Same mutable Bazzite CDN publishes CHECKSUM; upstream `42.20250513` build workflow uploads checksum | NOT independent trust |
| C: independent image signature | Historical legacy build workflow has no Cosign signing/attestation stage | Legacy ISO **unverified** |
| D: installed payload identity | No measured Anaconda deployment, no signed installer/payload binding | **Unverified** |

Historical mutable source: `https://download.bazzite.gg/bazzite-stable-amd64.iso`
and name `bazzite-stable-amd64.iso`.
Lab SHA-256:
`9c8d06cd8e57f2274678edeb14b4b13a79b8117c70571a65199919a66305b5c7`.
Lab size: `7907770368` bytes.
Only the installer welcome OCR said Bazzite 42; no independently verified,
immutable exact build ID, Anaconda version, Blivet version or deployed payload
ref is available for these bytes. The historical upstream workflow at tag
`42.20250513` includes a `-CHECKSUM` and publish steps but does **not**
independently sign the ISO. Do not infer build ID from the boot screen or tag.

Upstream:
- https://github.com/ublue-os/bazzite/blob/42.20250513/.github/workflows/build_iso.yml
- https://docs.bazzite.gg/General/Installation_Guide/legacy-install/
- https://docs.bazzite.gg/General/Installation_Guide/manual_partitioning/

## 2. A separate authenticated Atomic OCI candidate

Workflow `.github/workflows/gaslux-bazzite-atomic-origin.yml` is reused
unchanged except for the experimental push trigger.
A fresh run #44711145800 succeeded with upstream Cosign public-key verification
and GitHub OCI attestation against `ublue-os/bazzite`:
`ghcr.io/ublue-os/bazzite@sha256:492f83c738838861464685aed341783c2ea2266c82a9f19f0c867fd301783fd4`.

- CI: https://github.com/LMhdez/gaslux/actions/runs/44711145800
- Evidence ZIP: https://github.com/LMhdez/gaslux/actions/runs/44711145800/artifacts/14616483426
- Vendored upstream verification key: `assets/keys/bazzite-upstream-cosign.pub`;
  upstream copy https://github.com/ublue-os/bazzite/blob/main/cosign.pub
- The mutable `stable` tag was resolved to the above signed digest for this
  run. It is **not** a pinned production ISO and does not identify the
  historical Bazzite 42 payload.

The modern live ISO build recipe signs an ISO via `cosign sign-blob` and
creates a GitHub build-provenance attestation. The signed live ISO must be
downloaded and verified separately with its exact filename, byte length,
SHA-256, detached signature and upstream key. No matching ISO has yet been
authenticated in this branch. Modern Bazzite installation documentation says
manual partitioning remains a legacy-ISO feature. Therefore the authenticated
OCI does **not** unlock the old Blivet-GUI experiment or show a usable
unattended modern installer.

Upstream:
- https://github.com/ublue-os/bazzite/blob/main/.github/workflows/build_iso.yml
- https://docs.bazzite.gg/General/Installation_Guide/install-guide/

## 3. Actual upstream action-observation interface

Anaconda Storage exposes an independently documented, read-only D-Bus
`DeviceTreeViewerInterface.GetActions()`, plus `GetDevices()`,
`GetDeviceData(device_id)`, `GetFormatData(device_id)`,
`GetDisks()`, `GetMountPoints()`, `GetBootDevice()`.
A future authenticated guest must record the **actual** responses, current
Anaconda/Blivet versions and executable hashes, the media payload digest, the
physical/synthetic GPT GUID, partitions and host-to-guest serial mapping.
A screenshot or Blivet launch label is not sufficient. Nor do `GetActions()`
results inherently describe EFI loader file writes, NVRAM `BootOrder`,
`BootNext`, primary/backup GPT sector writes or Atomic deployment side
effects. These must be independently instrumented and checked.

The upstream Anaconda `CreatePartitioning` and `ApplyPartitioning`
operations choose/schedule partitioning; `InstallWithTasks` commits the
writes. None is invoked here. Never drive Blivet editing or Anaconda
installation without the separate GASLUX-OBSERVER controller lease and
verified guest action authorization.

API reference:
- https://anaconda-installer.readthedocs.io/en/latest/autoapi/pyanaconda/modules/storage/devicetree/viewer_interface/index.html
- https://anaconda-installer.readthedocs.io/en/latest/autoapi/pyanaconda/modules/storage/storage_interface/index.html

## 4. Strict candidate comparison (no real action export yet)

`auto_tests/bazzite_anaconda_write_set_gate.py` reuses the known GPT fixture
constants from `bazzite_gpt_fixture.py` and the existing PR #262 candidate.
It does not parse raw GPT or mutate the disk. It rejects mismatched disk GUID,
guest serial, protected partition identities, foreign slots, filesystem
changes, absent/extra/duplicated Blivet actions, EFI writes to Windows,
unknown bootloader destinations, any NVRAM operations, incomplete Btrfs
subvolumes and unaccounted metadata writes.

The expected *diagnostic* list includes three new partition creations, three
filesystem formats, three Btrfs subvolume creations, primary+backup GPT
changes, protective MBR and a possible new /EFI/fedora/grubx64.efi loader on
the separate Linux ESP. These are **anticipated operations, not observed
Anaconda writes**. In particular, the global GPT tables cannot be treated as
fully transaction-owned merely because the three Linux data extents are
unallocated. No proof of Atomic deployment steps or grub updates exists.

The only accepted positive model is `synthetic-contract-replay`; even its
perfect match returns `installationAuthorized=false`, `nativeInstallerWriteSetVerified=false`.
Any claimed actual `anaconda-dbus-readonly-untrusted` export is refused
until an independently authenticated capture path has been implemented.
The GitHub Actions workflow deliberately tests this refusal and records
`anaconda-write-set-status.json` rather than treating an empty screenshot
or a synthetic write-set as real evidence.

## 5. Dependency with GASLUX-SAFETY

PR #265 defines a read-only GPT image identity checker covering both headers,
entry-array CRCs and unrecognized/overlapping partitions. The current Bazzite
lab uses its **existing** synthetic `sgdisk` fixture contract; it must later
consume the shared normalized identity record from #265 after human review,
rather than copy its GPT parser. A valid prewrite gate still requires host,
guest and Windows identities, EFI/BCD/WinRE proofs, a transaction checkpoint,
snapshots, ESP/NVRAM ownership and an independently proven rollback.

## 6. Acceptance not reached

No authenticated legacy installer ISO/payload, real Anaconda GetActions capture,
verified write-set, Atomic installation, first Linux boot, first Windows boot,
post-update boot, rollback or Windows recovery. The signed OCI result is
real upstream provenance evidence but has **no effect** on any installation
authorization. Bazzite remains UEFI/GPT only, Secure Boot MOK enrollment
remains forbidden, and no catalog or release metadata has changed.
