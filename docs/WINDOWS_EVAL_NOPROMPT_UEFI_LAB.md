# Windows evaluation UEFI DVD boot: no-prompt **lab-only** diagnostic

## Problem and observed evidence

Authentic Microsoft Windows 10/11 evaluation ISO SHA-256 verification and hosted
QEMU/KVM device startup already work in [PR #51](https://github.com/LMhdez/gaslux/pull/51).
Nevertheless, [run #43990610168](https://github.com/LMhdez/gaslux/actions/runs/43990610168)
timed out without installed Windows firstboot. The original Windows 10 guest serial
archive showed the firmware printing `Press any key to boot from CD or DVD` then
`BdsDxe ... Time out`. The Windows 11 guest log of
[run #43992702233](https://github.com/LMhdez/gaslux/actions/runs/43992702233)
showed `BdsDxe: failed to start ... DVD ... Time out` even though the QEMU
HMP monitor acknowledged `sendkey ret`.

A disposable QEMU/KVM + synthetic GRUB boot test independently confirmed the
need for guest-side evidence: the EFI guest reached its serial READY marker,
but the host's HMP Enter command was **not** received in the EFI guest. The
failed test is retained as an **opt-in diagnostic**; HMP success is never
accepted as proof of firmware keyboard input.

## Controlled investigation

The optional `--derived-no-prompt` flag is permitted ONLY in the
**GitHub-hosted, explicitly consented, isolated KVM CI lab**. The test:

1. Independently downloads the original official Microsoft ISO via allowlisted
   HTTPS origins and rejects any byte stream whose SHA-256 differs from the
   immutable Microsoft hash pinned in the lab metadata.
2. Keeps that original ISO file **unchanged**. Extracts the already verified
   official Windows payload into a private temporary directory.
3. Requires the exact Microsoft-provided
   `efi/microsoft/boot/efisys_noprompt.bin`, `sources/boot.wim`, and an
   `install.wim` or `install.esd` from the original verified ISO.
4. Creates a **different temporary** UDF/El Torito EFI DVD using `genisoimage`
   and the original Microsoft no-prompt EFI boot image. Hashes this DERIVED
   artifact separately as `labDerivedIsoSha256`; it never claims this hash
   is Microsoft's published official ISO SHA-256.
5. Boots QEMU/OVMF with a newly created file-backed QCOW2 and private OVMF
   variables. With `--boot-probe-only`, it only checks that the firmware
   starts the UEFI DVD without reporting a timeout. It forcibly terminates the
   disposable guest after 120 seconds; it does **not** assert WinPE or Windows
   client installed firstboot.

The full Windows installed-firstboot witness (client ProductType, expected
build, EFI/GPT, Windows recovery partition, WinRE Enabled, BCD listing and
**clean Windows guest shutdown**) remains unchanged and compulsory before
`windowsClientBootVerified=true` can be returned.

## Non-negotiable boundaries

- **The derivative is NOT an official release ISO.** Its byte hash differs
  from the published Microsoft original. It is allowed **only** as ephemeral
  disposable lab media and must not be added to the signed Gaslux catalog or
  used for physical Windows installation.
- No acquired Windows ISO, remastered image, WIM, QCOW2, TPM state, password
  or encrypted material is uploaded as an Actions artefact.
- The test does not open host block devices, alter EFI NVRAM, modify the Windows
  BCD/WinRE on a physical machine, or install Linux.
- Successful **DVD probe** is NOT Windows Setup, installed Windows 10/11
  firstboot, CachyOS dual boot, kernel update, safe shrink or Windows recovery.
- Even if the derived media boots Windows Setup, release acceptance still needs
  legitimate disposable Windows 10 **and** Windows 11 clients, independent
  snapshots, real first boots of Windows and CachyOS on the SAME virtual disk,
  and BCD/WinRE/ESP/NVRAM/BitLocker/GPT recovery evidence under
  [issue #3](https://github.com/LMhdez/gaslux/issues/3).

GPL-3.0; human review mandatory under `AI_POLICY.md`. Generated-by: GPT-6.
