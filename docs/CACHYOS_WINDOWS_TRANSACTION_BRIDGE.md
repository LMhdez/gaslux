# CachyOS — Windows transaction binding (experimental, read-only)

**NOT AN INSTALLER. NOTHING HERE AUTHORIZES DISK, BCD, NVRAM OR EFI WRITES.**

This stacked branch follows the successful VM-only CachyOS first-boot demonstration in [PR #36](https://github.com/LMhdez/gaslux/pull/36). It adds a read-only contract audit rather than incorrectly treating a virtual Archiso-to-pacstrap installation as a complete Windows/Libertix transaction.

## Contract checks

The new \`auto_tests/tools/cachyos_windows_transaction_bridge.py\` consumes four independent *candidate* sources:

1. The complete existing \`installation-plan.schema.json\` v4/v5 Windows plan, validated by \`assets/live/libertix-installation-plan.py\` with an observed installer partition.
2. The existing \`installation-state.schema.json\` execution ledger, validated by \`assets/live/libertix-installation-state.py\`. The ordered Windows preflight, artifacts, recovery, shrink, partition, live media and temporary boot stages must all be durable before the live handoff; a failed, compensated or out-of-order state fails closed.
3. A Windows baseline candidate containing byte-exact original Windows/Boot/Recovery partition geometry, disk identity, partition table ID, sector size, recorded ESP filesystem UUID, Windows EFI loader and BCD hashes, WinRE state and BitLocker state.
4. An independently signed Archiso handoff whose Ed25519 signature, public-key pin, GRUB/kernel arguments, transaction ID, target root UUID and ISO SHA-256 are checked by the existing \`cachyos-handoff-auth.py\` validator. The signed record must match the Windows plan disk identity and the candidate Windows EFI baseline.

Current support boundary is **UEFI/GPT with Secure Boot disabled**; all other layouts are rejected. Tests exercise real ephemeral Ed25519 signing/verifying and the shared Windows/live validators using synthetic plans. The experiment preserves the existing Mint/Zorin modules and makes no release-catalog changes.

A successful read-only match reports \`contractMatched=true\` but **always** reports \`storageWritesAuthorized=false\`, \`releaseEligible=false\`, \`windowsBootVerified=false\`, \`windowsBcdAndWinreRestorationVerified=false\`, \`firmwareBootOrderRestorationVerified=false\`, \`linuxKernelUpdateCrossbootVerified=false\`, and \`uninstallVerified=false\`.

## Why this is still blocked

- A user-provided JSON baseline cannot authenticate its own provenance. The Windows-side collector, stable artifact signatures, physical disk/ESP mapping and post-reboot geometry revalidation must be integrated into the actual Windows and Archiso stage before writes can be enabled.
- The current shared distribution plan does not encode immutable ISO byte length or an authenticated Windows ESP loader hash. The legacy Microsoft secure-boot-authority field is not a CachyOS trust model. Adding CachyOS to the stable catalogue would be unsafe.
- The existing QEMU target is an **empty 12 GiB virtual disk**. Its first boot cannot demonstrate preservation, boot or rollback of Windows 10/11, nor prove kernel update/crossboot or user-requested uninstall.
- The working Windows 10/11 dual-boot and recovery campaign still requires two lawfully provisioned, disposable Windows guest images, independently restorable snapshots, pre/post BCD/WinRE/ESP/BootOrder/BitLocker and partition evidence and genuine boots of both systems. No such successful campaign is attested here.
- External reviewer-signature and campaign verification are already modelled by \`auto_tests/tools/cachyos_release_gate.py\`. Do not weaken or bypass that gate, and do not substitute CI fixtures for independent evidence.

## CI and safety

\`auto_tests/test_cachyos_windows_transaction_bridge.py\` uses synthetic valid Windows transactions and real *ephemeral* Ed25519 signatures to check acceptance of consistent read-only contracts and rejection of tampered signatures, replayed nonces, foreign disks, altered EFI hashes, changed geometry, absent WinRE, incompatible firmware, altered ISO pins, incomplete ledgers and misidentified distributions.

No physical devices, Windows boot configuration, Linux target images or even local NVRAM are written by this new bridge. It is not imported by the production WPF installer, PowerShell mutators, Archiso target writer or stable catalogue. **Do not merge/enable until human review and end-to-end Windows proofs.**

AI provenance: Generated-by GPT-6; GPL-3.0 and AI_POLICY.md apply.
