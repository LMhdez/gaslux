# CachyOS root-only pacstrap boundary on a Windows-containing QCOW2

**Experimental VM-only backend. NOT a production installer or proof of dual boot.**

This work stacks on signed shared-disk preflight PR #165 and the independently
verified Windows/CachyOS GPT/ESP/BCD/WinRE contracts in PRs #161–#166. It
reuses the real Archiso/pacstrap package list and native branding validation
from the separate, empty-disk CachyOS lab PR #36, **but not its disk partitioner,
ESP formatting or removable GRUB installation**.

The program `auto_tests/tools/cachyos_windows_shared_root_pacstrap.py`
implements the next root-only installation *candidate*:

1. Require actual CachyOS Archiso in QEMU, disabled Secure Boot in no-key
   OVMF, root privileges and separate explicit VM-only opt-in. Validate the
   original Ed25519 plan/signature, independent run ID, kernel-anchored
   plan/public key digests and official pinned CachyOS ISO identity.
2. Compare the single serial-bound virtio disk, exactly five partition
   entries, 128-GiB/512-byte-sector geometry, PARTUUIDs, GPT types, sector
   extents and existing ext4 root UUID with the signed intent.
3. Independently read both GPT windows, validate primary/backup CRC and the
   first four Windows GPT record bytes; reject MBR hybrids, foreign entries,
   changed Windows GPT GUIDs and mismatched Linux entry #5. The signed
   `gptWindowsSha256` is SHA-256 of the 512 bytes containing GPT entries
   #1–#4 in on-disk native GPT record encoding.
4. Read-only mount the Windows ESP, Windows NTFS and Recovery volume and
   compare SHA-256 of bootmgfw.efi, BCD, winload.efi and Winre.wim with
   the signed plan. Missing NTFS3 support or dirty/encrypted volumes fail
   closed; no unsafe fallbacks.
5. **Only in the isolated VM test mode**, with all previous checks complete,
   require an additional canonical Ed25519-signed *root-only* COW lab grant
   made with the same key anchored by the original kernel handoff. Check
   exact plan SHA-256, run/nonce, fifth Linux PARTUUID/UUID, protected Windows
   GPT digest, authenticated host checkpoint and backing-chain proof hashes,
   read-only Windows backing, COW discardability and an explicit ban on
   Windows ESP writes. This is a LAB authorization for a root-only action,
   never an upgrade of the signed read-only plan to production write access.
   The actual host-side grant issuer/checkpoint authentication is **not yet
   implemented or proven**, so no real Archiso pacstrap has been run.
6. After the signed grant passes, mount the existing ext4 root (GPT #5) at a fresh
   private root-owned empty `/mnt/gaslux-shared-root`; populate official
   Arch/CachyOS keyrings without changing signature policy; call native
   `pacstrap -K` for a minimal CachyOS kernel/root; invoke native branding
   and check `ID=cachyos`. Never run `sgdisk --clear`, `mkfs.*`,
   `grub-install`, `efibootmgr`, or copy a live root filesystem.
7. Unmount the installed root and re-check both GPTs and protected Windows
   hashes. The host is responsible for owning and discarding the COW on any
   failure, before any user-visible approval.

### Release-blocking limitations

The backend is **not activated** in the real Archiso KVM workflow. Its
code and synthetic no-device tests do **not** prove that this program ran
inside an authentic live CachyOS guest, or that package installation,
native bootloader, first Linux boot, Windows dual boot, kernel updates,
recovery after Linux install or rollback worked. Current signed plans
explicitly keep `writeAuthority=false`: that is **not** production write
authorization, and no production code may use the separate lab opt-in to
bypass it. The lab must first prove the exact image binding, disk identity
and recoverable COW ownership before executing the root-writing mode.

The Windows EFI System Partition is never mounted writable or updated by
this code. A future bootloader phase needs explicit ownership of its
own EFI files, EFI/BCD/WinRE baseline and rollback, and separate validation
of booting both systems before any stable release. The Windows base
QCOW2 remains immutable throughout the laboratory series.

The `cachyos-windows-shared-archiso-contract.yml` in PR #165 and
`cachyos-shared-cow-root-pacstrap-safety.yml` here prove only contracts,
not actual Archiso execution or a live Windows disk test. Run genuine
installation tests only with authorized, snapshotted disposable VMs.

**Issue #3 remains open. Do not merge without human review under
`AI_POLICY.md`, `AGENTS.md` where present, and GPL-3.0.**
