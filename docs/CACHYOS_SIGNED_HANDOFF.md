# CachyOS Archiso: authenticated Windows-to-live handoff contract

**Development-only. Not bootable/installer-ready for production.**

This branch addresses an integrity gap in the earlier experimental path:
the unsigned Archiso ISO plan and a transaction marker could be replaced
before the CachyOS live environment began installing packages.

## Signed handoff design (partial implementation)

- The Windows side must generate a fresh, unpredictable per-run 128-bit
  boot nonce and a per-transaction Ed25519 signing key, or provide an
  equivalent independently reviewed and authenticated signing mechanism.
  **That Windows signer and secure boot-argument staging are not yet
  implemented in Gaslux.** No secrets/private keys belong in the ISO,
  EFI partition, repository, logs or Linux target.
- Windows must first verify the signed release catalog, physical disk and
  partition identity, NTFS/BitLocker state, rollback readiness, existing
  Windows Boot Manager and WinRE. It then produces canonical, Ed25519-signed
  JSON bound to the exact run ID, boot nonce, UEFI/GPT, disabled Secure Boot,
  ISO version bytes (size/SHA-256), ISO source filesystem UUID/path, target
  disk identity/root UUID and Windows ESP and loader hash.
- A trusted Windows staging path must place the signer public-key SHA-256
  and signed-plan SHA-256 in a verified temporary UEFI boot configuration,
  alongside the run ID and nonce. If an attacker can replace the bootloader
  and kernel cmdline, these anchors are not trustworthy.
- assets/live/cachyos-signed-grub-handoff.py verifies the Ed25519 signature,
  independently supplied signer fingerprint and expected run/root UUID, and
  exact agreement with the ISO plan. It also invokes the Archiso ISO
  integrity/identity preflight before rendering fixed GRUB arguments.
  Its CLI requires an exact ISO9660 loop mount from the source volume.
- assets/live/cachyos-handoff-auth.py runs inside the live environment and
  re-verifies the same signed envelope against /proc/cmdline. No alternative
  CLI parameter can replace /proc/cmdline in production.
- assets/live/cachyos-stage-target.sh refuses package provisioning unless
  the signed verifier is installed and all required signature artefacts are
  present. It also refuses non-QEMU/KVM guests and insecure/unknown firmware.

## Signature limitations

The Ed25519 integrity checks protect against unauthorised modification
*given* a trusted boot chain, an independently trusted public-key digest and
a trusted expected transaction/root identity. They do not themselves prove
Windows EFI/BCD authenticity, rollback readiness, the existence of a
Windows-generated private signer or a fresh Windows recovery checkpoint.
The signed document is a commitment, not an audit of the actual disk.

There is no production signer, complete Windows UEFI staging strategy or
automatic Archiso agent delivery yet. In particular, the official CachyOS
ISO cannot be assumed to run Gaslux's installer or contain its scripts.

The Linux staging path is deliberately blocked by default until its own
verified boot and recovery integration is built. Never remove its failure
guards to make a demonstration run.

## Automated tests

- Synthetic ephemeral Ed25519 private/public key pairs generated solely
  within CI test directories. These ARE NOT project release-signing keys.
- Duplicate run identifiers, nonce replay, tampered canonical JSON, wrong
  source ISO path/filesystem UUID, forged signer key, wrong target UUID,
  unrecognised GRUB parameters and modified signatures are rejected.
- GRUB handoff tests use synthetic metadata and mock ISO inspection;
  actual ext4/NTFS loopback file discovery is separately exercised in QEMU.
- All results are explicit about missing Windows recovery and EFI trust
  evidence. Passing these tests is not proof of a Windows/Linux dual boot.

## Remaining acceptance gates

1. Windows WPF/C#/PowerShell creates the authenticated handoff as part of
   the existing typed plan and rollback transaction, using a supported
   Windows cryptographic API. Key lifecycle and non-replay semantics require
   security review.
2. Integrate a verified temporary EFI boot entry; preserve Windows Boot
   Manager/BootOrder/WinRE and ensure rollback after interrupted power.
3. Boot the genuine CachyOS Archiso in disposable Windows 10/11 UEFI VMs,
   provision and validate the target, boot Linux and Windows repeatedly,
   install kernel updates and test uninstall and full Windows recovery.
4. Gather independent authenticated evidence bound to the exact executable
   and sign off with a human maintainer before any physical-disk release.
5. Maintain Mint/Zorin regressions and keep CachyOS out of the stable
   catalog and WPF picker until all checks complete.

See also docs/CACHYOS_E2E_RELEASE_GATE.md and issue #3.
