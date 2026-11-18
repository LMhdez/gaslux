# Bazzite official ISO / native installer OVMF laboratory evidence

**Scope:** experimental, UEFI/GPT only, **diskless QEMU/KVM/OVMF**. This is not an installation or a Gaslux stable release.

## Exact tested official medium (17 November 2026)

- Upstream source build: https://github.com/ublue-os/bazzite/actions/runs/44121421800
- Downloaded name: `bazzite-stable-live-amd64.iso` from `https://download.bazzite.gg/` (the URL is mutable).
- Exact ISO SHA-256: `6120b6edc2d87e7bdccf8dfddc8b156552cd50b152cb0a9e9dedb37fb947cbe5`.
- Exact length: `8377878528` bytes.
- Independent upstream Cosign public-key SHA-256: `af78ecfda6eb21c35195af3739341715e9cfc3f2f5911dd9c10b0670547bf6e8`.
- Actual detached Cosign signature: verified with the corresponding upstream key and pinned bytes; EFI El Torito entry and ISO volume label `Bazzite-Live` observed.

## Boot evidence

GitHub Actions https://github.com/LMhdez/gaslux/actions/runs/44160549748 passed both contract and actual VM jobs. The VM used OVMF, KVM, 8192 MiB RAM, two virtual CPUs, optical ISO in read-only mode and **no guest hard disk**. Screenshots 2 and 3 show the Bazzite native graphical installer at `Welcome. Let's install Bazzite now.`, with language, date/time, installation method, storage configuration, account and review stages. OCR of both images is a required CI assertion. Evidence: https://github.com/LMhdez/gaslux/actions/runs/44160549748/artifacts/14363078627 (short-lived GitHub artifact, retained for three days).

The ISO download, key signature, UEFI catalog, VM screenshot and OVMF are observed in the *same* workflow run. A successful workflow does **not** establish that the installer is safe for unattended Windows dual boot, or that the running installer binaries have been independently authenticated beyond the signed ISO provenance. OCI/Atomic deployment attestation is a separate trust domain.

## Fail-closed constraints and next blockers

- `pinDiscoveryOnly=true`, `catalogPinAuthorized=false`, `installationAuthorized=false`, `installerIdentityVerified=false` and `nativeInstallationVerified=false` remain in evidence after ISO verification. No signed production catalogue change.
- There is **no installer execution against any writable target**, no proved partition selection, native bootc/OSTree install, Btrfs layout, disk-only first boot, kernel updates or rollback.
- There is **no Windows 10/11 guest** in the VM, no same-disk GPT/EFI/BCD/WinRE protection validation or dual-boot evidence. Secure Boot enrollment remains unsupported for automated Gaslux installation.
- Before adding a disposable QCOW2 target, a signed transaction plan must bind the exact device identity and partitions, protect the Windows ESP/Recovery, prepare a durable snapshot, define compensating recovery and prove the native installer's safe unattended storage control. Refuse unsupported manual partitioning rather than guessing.

Human review required. Do not merge this experimental test into a production installation path without end-to-end evidence.
