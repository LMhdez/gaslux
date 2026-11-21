# Zorin 18.1 native-installer discovery (experimental)

Only read the pinned Zorin 18.1 ISO (SHA-256 `44649b97bd307fc4c8529205d098ebbf98575a1e1ba2ee7d7005b697af1721d5`, size 3909091328 bytes). No native installer, GPT, formatting, GRUB, EFI, BCD, WinRE, or NVRAM writes are authorized by this work.

Actions #44730944403, artifact #14627774087, proves an experimental Zorin SquashFS-root **direct-kernel** boot in the same disposable Windows 10 QCOW2 and later return to Windows. It does not prove native installation or selectable GRUB dual boot.

The authenticated ISO inventory identifies `usr/share/applications/ubiquity.desktop`, SHA-256 `80b8223c71f77aaa788206f10127e8843cdd8d0f957ccaddc13e565b625cdf11`, whose Exec refers to `ubiquity gtk_ui`. `casper/filesystem.manifest` SHA-256 `cc206a10d7de5cd8d373634f1b91ac35e030f5d4075acda7edcbb2b0318ee948`. Package version, executable and ownership, live process, partitioning library, automation, EFI/GRUB behavior and actual installer identity are **unobserved**.

The prior fifth Linux partition (PARTUUID `99a1212c-0662-450f-a082-291f4ba71a15`, ext4 UUID `6ffb16ae-6802-47a6-a766-0c49d2468581`, LBA 154707968–205039615, sector size 512) has GPT name `GASLUX-CACHYOS-ROOT`, not a Zorin owner. The raw disk GUID is not independently authenticated and no signed transaction or recoverable checkpoint was demonstrated. Decision: `DENY_NO_WRITER`.

Future experiment: extend existing read-only `auto_tests/tools/zorin_official_iso_installer_inventory.py` to inspect complete dpkg status and package file lists, candidate executables, autostart/desktop launchers, Snap manifests, partition/EFI code and hashes; classify each capability SUPPORTED/UNSUPPORTED/UNOBSERVED by observed basis; optionally boot ISO with an optical-only QEMU/OVMF guest after validating isolation. Reuse the existing Debian/Ubuntu backend without rewriting Mint; gate all future writes on independently authenticated disk/transaction/write-set/checkpoint and GASLUX-SAFETY PR #265/#267. Observer PR #259 also remains a dependency. Do not declare P3/P4/P5, updates, rollback or stability without real proof.
