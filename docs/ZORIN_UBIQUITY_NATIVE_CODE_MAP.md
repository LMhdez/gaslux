# Zorin 18.1 Ubiquity — authenticated static code and write-surface map

**Experiment only — DENY_NO_WRITER.** No native install, GPT, NTFS, ESP, BCD,
WinRE, GRUB, physical-disk or production NVRAM write is authorized.

## Authentic evidence

- ISO Zorin OS 18.1 Core SHA-256:
  `44649b97bd307fc4c8529205d098ebbf98575a1e1ba2ee7d7005b697af1721d5`,
  size 3,909,091,328 bytes.
- Installed Ubiquity: `24.04.5+zorin2`, x86_64/amd64, via
  `var/lib/dpkg/status` and Casper manifest; executable
  `usr/bin/ubiquity` SHA-256
  `5819ac97c623085d08e55c08afc12e7d70be98795e603b27807bea165fad0b1b`.
- Source evidence:
  [Actions #44891962800](https://github.com/LMhdez/gaslux/actions/runs/44891962800),
  [artifact #14702053502](https://github.com/LMhdez/gaslux/actions/runs/44891962800/artifacts/14702053502).
  Archive SHA-256:
  `641bf31056addd3e54126d3e636ea524d12d0a4ac16e4188510aef8ae1f08da9`.
  Real file `zorin-native-ubiquity-code-map.json` SHA-256:
  `47f42ce781af0eb39bc19f6c3bf4f2fb20569c5467a8f17d8e6d84b273a08f24`.
- Scanner selected 68 source candidates in the original pinned SquashFS;
  58 regular files were hashed and 10 `lib/partman/lib/` candidates
  could not be attested as regular files and were **excluded**. The source
  enumeration was not truncated. The same pinned `dpkg/status`, package
  owner `.list` and Casper manifest were cross-checked.

## Code entrypoints (authenticated bytes, not execution traces)

Paths in this table refer to the ISO SquashFS. The SHA-256 refers to the
**whole source file**, not just the named function. The JSON contains full
paths, per-source package/version, symbols, exact lines and matched tokens.

| Subsystem | Source / function / line | Source SHA-256 |
| --- | --- | --- |
| Partition editor | `usr/lib/ubiquity/plugins/ubi-partman.py`, `initialize_use_disk_mode` line 738; `parted_server` line 28 | `295e4785bb9477f00c3df565a4698635631d36c5c74f40b87d302578c3a6e50f` |
| Partman commit | `usr/lib/ubiquity/ubiquity/components/partman_commit.py` | `3de7e27675e1875848c4abc50b40742c5f3c68e92d7b23f54001839851527322` |
| GRUB installer | `usr/lib/ubiquity/ubiquity/components/grubinstaller.py`, `prepare` lines 30, 34; `run` line 43 | `4f2b1e80d5401abf9164f534044162483f6d37df730dff7842ec1d651fad5579` |
| EFI mount/configuration | `usr/share/ubiquity/plugininstall.py`, `configure_bootloader` line 991 (`/boot/efi`) | `bf3d60094d1ab2609b6260a61b675581a5efb79f7044a0c0383f3733e52e3b20` |
| User account | `usr/lib/ubiquity/plugins/ubi-usersetup.py` | `56a888d8601578faeaf92af662778b1e656136fc1bbb4d6f2a766bb42d39aa72` |
| Language | `usr/lib/ubiquity/plugins/ubi-language.py`, `set_language` line 48 | `9027923200a29350c4f66202dc487b646c64f27b4b8a57e1570760bbc72ef797` |
| Keyboard | `usr/lib/ubiquity/plugins/ubi-console-setup.py` | `9a4ad8b054c98f0604866e89b92f8ef8a978bfe1c2a81ca18003510210ceabad` |
| Time zone | `usr/lib/ubiquity/plugins/ubi-timezone.py` | `d52a3baafd2484d43c90bc382fe7d1f6781f5ca2d1bb6eabb24420ba9233dd91` |
| Windows GRUB chainloading | `usr/share/grub-installer/otheros.sh`, `grub2_write_chain` line 84 | `bf0f500fdbe45489b70958a097c0c6dc22aa6934ff47845dce2aa84d4c6655bd` |

## What the evidence supports — and what it does NOT

The following are **SUPPORTED_STATICALLY**, **not** demonstrated in a
write-authorized VM:

- Ubiquity includes a partition editor based on partman, disk selection
  and existing-partition UI references.
- Root/filesystem configuration is represented in the partman plugin.
- GRUB installer and boot-device selection appear in
  `grubinstaller.py`.
- `configure_bootloader` references `/boot/efi`; boot files and NVRAM
  writes are **not** proved confined to a Gaslux transaction.
- Account, locale, keyboard, time zone and debconf/preseed references are
  present; safe non-interactive installation to an existing ext4 root is
  **not** proved.
- Windows chainloading has code references; actual GRUB dual boot on the
  same Windows QCOW2 is **not** proved.

**UNOBSERVED:** an authenticated GPT no-write mode; precise ext4 reuse
without changing other partitions; ESP ownership or avoidance of the
Microsoft subtree; direct NVRAM boot-variable behavior; complete
unattended/preseed contract; successful native installation; kernel updates;
uninstallation and independently verified rollback.

No feature is marked UNSUPPORTED merely because the bounded static search
did not find a token.

## Potential native write surfaces — not permissions

1. GPT partition table, disk label, partition metadata and boot flags:
   partman references; possible out-of-root writes. **Not authorized**.
2. Formatting: potential filesystem creation or modification. **Not
   authorized** outside an independently proved owned Linux target.
3. Root: installed packages, initramfs, users, mounts, fstab, journal,
   machine-id. Ownership and transaction would need verification.
4. EFI System Partition: GRUB/shim EFI binaries and config may modify a
   shared ESP. Only transaction-owned `EFI/Libertix` resources could ever
   be considered in a future separately approved experiment; the Windows
   EFI subtree must remain untouched.
5. UEFI NVRAM: BootNext, BootOrder and Boot#### changes must be independently
   witnessed. Direct invocation is currently UNOBSERVED.
6. GRUB menu and chainloaders: native target + Windows entry need end-to-end
   boot proof, including updates.
7. Postinstall operations: user configuration, package scripts and
   hooks may write outside expected paths. The write-set is NOT known.

The read-only schema hardcodes
`authorization=DENY_NO_WRITER`, `stable=false`,
`nativeInstallerExecuted=false`, `partitionLockdownVerified=false`,
`outsideLinuxTargetWriteSetAuthenticated=false` and
`efiAndNvramPreservationVerified=false`. The source-map validator ties
every match to a source hash, package owner and line number.

## Minimum future synthetic-native experiment (NOT authorized yet)

1. **Isolate** a disposable GitHub-hosted QEMU/KVM + OVMF VM; a synthetic
   GPT disk only, with its own ESP and ext4 Linux destination. No physical
   disks, host mounts, real Windows disk or production NVRAM. Pin ISO and
   firmware hashes.
2. **Prepare baseline** for both GPT headers/tables (CRCs and GUIDs),
   exact LBAs/byte offsets/PARTUUIDs, ESP contents/hashes, filesystem
   labels and OVMF VARS. Put known canaries outside the intended write-set.
3. **Prove recovery before writes:** immutable QCOW2 checkpoint, private
   independent overlays and VARS, verified restore/recomparison, no shared
   aliases/hardlinks/symlink escapes. An initial snapshot filename is not
   a recovery proof.
4. **Safety admission gate:** independently authenticated host/guest identity,
   signed typed plan and transaction, nonce/single use, live geometry
   revalidation and host-enforced sector/filesystem write fencing. Current
   [Safety #265](https://github.com/LMhdez/gaslux/pull/265) and
   [Safety #267](https://github.com/LMhdez/gaslux/pull/267) do not grant
   writers. Fail before starting Ubiquity if any condition is absent.
5. **Observer integration:** reuse [Observer #259](https://github.com/LMhdez/gaslux/pull/259);
   do not invent a second GUI controller. No selection of destructive
   buttons unless execution is explicitly authorized and bounded.
6. **Measure write-set:** independently capture sectors, ESP file tree and
   firmware variables before/after; reject changes to GPT if not explicitly
   authorized and *all* writes outside the approved ext4 target and
   synthetic owned EFI subtree. If Ubiquity cannot confine them, stop and
   do not attempt a Windows dual boot.
7. **Prove native installation:** boot OVMF → signed loader → GRUB →
   installed Zorin root (not `qemu -kernel`), then reboot and repeat.
   Only after this laboratory may a separate Windows-coexistence experiment
   be considered, still gated by rollback and Windows integrity.

**Alternative if Ubiquity cannot constrain its write-set:** preserve and
validate the existing Debian/Ubuntu Gaslux native-target configuration
backend (`assets/live/libertix-install-main.sh`,
`configure-target-main.sh`, `libertix-uefi-adapter.sh`). It must still
produce a properly installed system, native GRUB and both boot proofs
before being called native; the historic copied SquashFS + direct-kernel
COW result is not enough. Do not clone, weaken or bypass the Safety
contracts or introduce writers in this discovery PR.

## Boundaries

No Ubiquity installation, partition format, GPT/ESP/BCD/WinRE edit,
production NVRAM edit, kernel update, USB boot, auto-merge or stable
catalog promotion occurred. P3/P4/P5 remain unclaimed.
