# CachyOS — signed real-ISO handoff integration (CI laboratory only)

**Scope: read-only. This is NOT the Windows USB-free installer and is NOT a
release approval.**

This branch combines the two previously independent experimental lines:

- The Ed25519 signed handoff and signed GRUB renderer from draft PR #10.
- The SHA-256-pinned real CachyOS 260809 Archiso layout and live kernel
  validation from draft PR #17, based on PR #11.

## What is exercised

`auto_tests/tools/cachyos_real_iso_signed_contract.py` runs on GitHub's
isolated Ubuntu VM and uses the same official verified ISO downloaded in the
existing CI job. It checks the fixed, independently published SHA-256
`959f6577f45e25ee9fd8c220fd221b08e4ea79412c7315c0f922dd6d86d5e33c`,
the actual Archiso squashfs identity and CachyOS LTS live kernel/initramfs
files. It then:

1. Creates an ephemeral Ed25519 signing key in a temporary directory for
   this CI test only. The private key is never exported as an artifact.
2. Signs a canonical laboratory handoff document bound to the transaction,
   boot nonce, expected root UUID, immutable ISO size, SHA-256, source path
   and UEFI/GPT/Secure Boot policy.
3. Calls the real signed GRUB renderer and source ISO verifier. It must
   select the actual LTS kernel and initramfs found in the verified ISO.
4. Requires each Gaslux authenticated kernel parameter to appear once,
   verifies the resulting GRUB syntax with `grub-script-check`, and
   refuses an unsigned change to the source ISO path or signer key.
5. Exports the **public** test key, signed laboratory plan, detached
   signature, generated GRUB entry and individual SHA-256 hashes as CI
   artifacts for independent review.

The source storage ext4 UUID, Linux root UUID, target disk identity,
Windows ESP UUID and Windows Boot Manager SHA-256 here are **synthetic
fixtures**. CI deliberately uses `require_mounted_iso=false` in the
signed-to-ISO verifier, because it does not have a separately verified
Windows/NTFS or ext4 source partition. It mounts the official ISO read-only
in the same preceding job, but cannot claim the complete production
disk-and-firmware trust chain.

## Last CI result and blocked guest check

The verified real-ISO signed contract passed in GitHub Actions run
https://github.com/LMhdez/gaslux/actions/runs/43934914445 and uploaded
test-only signed evidence artifact `14260412056`.

**The overall workflow failed** in the following, independent live-guest
probe. Its captured serial transcript reported:
`GASLUX_GUEST_PREFLIGHT_FAILURE: Secure Boot is enabled or unverifiable`.
This is a correct fail-closed refusal of an OVMF VM whose Secure Boot EFI
variable was not proven disabled; it is **not** permission to skip the
Secure Boot check or to infer that a physical Windows device is safe.
That live-guest check must be repeated with an explicitly verified
Secure Boot-disabled OVMF variable store and retained proof before it can
be counted as passed.

## Explicit limits

The Ed25519 public key digest is accepted only as an independent laboratory
input. It does not become a production signing root by virtue of passing
this test. The Windows app does not yet generate, authenticate, persist or
install a transaction signer; Windows cannot be trusted to have set the
boot arguments in firmware merely because this command renders them.

The signed test-only GRUB entry is **not** deployed to any EFI system
partition; the existing real ISO QEMU boot and guest `--check` are separate
tests. The code does not attempt a Windows install, allocate/shrink an NTFS
volume, run pacstrap, modify EFI/NVRAM or verify Windows recovery.

Production release remains blocked by issue #3:

- Windows C#/PowerShell signed plan integration with durable checkpoints,
  authenticated temporary EFI entry and independent trust anchors.
- Real installer agent on CachyOS Archiso and VM-only target installation,
  installed Linux boot, GRUB updates and Windows preservation.
- Actual Windows 10/11 UEFI/GPT QEMU/Proxmox dual-boot, BCD/WinRE/ESP/
  BitLocker validation, injected failures, rollback and human approval.

The success JSON sets `stableForPhysicalDisks=false`,
`windowsBootChainAuthenticated=false`, `windowsRecoveryVerified=false`,
`installedLinuxBootVerified=false`, and `sourceMountVerified=false`.
These fields must not be removed to make a CI gate green.

Related draft work: PRs #10, #11, #17; issue #3. AI-assisted by GPT-6.
