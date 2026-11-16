# CachyOS signed-source GRUB execution in disposable QEMU

**Experimental test only. Not a Windows installer and not a production trust chain.**

## What changed

Previously the official CachyOS 260809 GitHub Actions job:
1. Independently checked the pinned official ISO SHA-256.
2. Verified an ephemeral Ed25519-signed synthetic Windows/Archiso handoff and generated its GRUB entry.
3. **Booted a different, manually written GRUB entry** in QEMU/OVMF.

Those tests did not establish that the signed-source-derived GRUB entry reached the running kernel.

The optional `GASLUX_SIGNED_EVIDENCE_DIR` QEMU mode removes this discrepancy:

1. Verify `SHA256SUMS`, the public key digest, Ed25519 detached signature, signed transaction/ISO identity and expected GRUB instructions against the pinned lab template. Reject missing, symlinked, repacked or unexpected boot inputs.
2. Format **only a new file-backed disposable ext4 image** with the synthetic source UUID included in the signed plan. Copy the previously SHA-256-checked official ISO into it.
3. Generate GRUB EFI with the validated signed-source-derived menu entry. Append only fixed **lab serial-console** kernel options; the four authenticated Gaslux boot arguments remain unchanged.
4. Boot an isolated OVMF no-key guest and demand a real CachyOS serial login, `SecureBoot=0`, `SetupMode=1` and read-only `stage.sh --check`.
5. Compare the **running guest** `/proc/cmdline` against all four host-verified signed handoff arguments: transaction, nonce, canonical plan SHA-256, test public key SHA-256. Require `GASLUX_SIGNED_GRUB_CMDLINE_VERIFIED=1` as well as the preflight marker. Echoed shell commands and conflicting failure markers do not count.
6. Preserve the serial transcript, actual embedded GRUB configuration, expected boot arguments and SHA-256 manifests in CI artifacts.

If the signed evidence is missing or malformed, the test stops; it cannot silently fall back to an independently hard-coded entry.

## Verification and threat boundaries

The Ed25519 signature covers the canonical JSON handoff, **not** an EFI binary or independently authenticated production firmware loader. The GRUB instructions are constrained to a fixed known test template before constructing the EFI image. CI adds only a predetermined console suffix to observe the VM. The ephemeral signer and synthetic Windows/disk identifiers provide no authority over a real Windows machine.

This test can prove one boot path into the **official CachyOS live Archiso** environment. It does **not** prove first boot of an installed system.

| Gate | Covered |
|---|---|
| Pinned ISO, signed-source-derived GRUB, running guest kernel arguments | Only if the new QEMU run succeeds |
| Secure Boot variables inside disposable OVMF live guest | Only if the new QEMU run succeeds |
| Pacstrap into transaction-owned installed root | **No** |
| Installed kernel, initramfs and bootloader | **No** |
| Windows 10/11 dual boot, BCD/WinRE, BitLocker, rollback | **No** |
| Physical hardware, real Windows signer and disk geometry | **No** |

The stable catalogue and release configuration remain unchanged. The next
independent stage must install into a separate owned **virtual target** and
reboot into that installed Linux root. A live Archiso login is not equivalent
to an installed CachyOS boot.

## Review

- Parent Secure Boot proof: [PR #28](https://github.com/LMhdez/gaslux/pull/28)
- Production-stability release gate: [issue #3](https://github.com/LMhdez/gaslux/issues/3)

Human review required under [AI_POLICY.md](../AI_POLICY.md).
