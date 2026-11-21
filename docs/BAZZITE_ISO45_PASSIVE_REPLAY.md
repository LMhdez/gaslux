# Bazzite ISO45: replay of original passive live-boot screenshots

- Original source: [Actions #44822100590](https://github.com/LMhdez/gaslux/actions/runs/44822100590), artifact [#14672623998](https://github.com/LMhdez/gaslux/actions/runs/44822100590/artifacts/14672623998).
- Pinned original ZIP SHA-256: `ba434ddf46e892c80325608b87cf6933da88bda716e144cfd63df0a49904a00c`.
- Bazzite ISO 45.20261117.1 SHA-256: `6120b6edc2d87e7bdccf8dfddc8b156552cd50b152cb0a9e9dedb37fb947cbe5`.
- Replay input is the exact **original** ~2.5 MB Actions ZIP; no ISO download, VM, QEMU, GUI input, disk write, or Anaconda API invocation.
- Original runtime report: **C** (OCR rules missed the real Bazzite Portal desktop).
- Corrected result: **B**, when and only when the pinned archive hash, original ISO/OCI provenance, preflight, all six frame hashes and PNG dimensions, original OCR association, QEMU running status, GRUB serial trace and synthetic GPT discard audit agree.
- An independently reviewed original PNG clearly shows the Bazzite Portal, desktop, taskbar, build label `45.20261117.1` and **Install to Hard Drive** shortcut. This is the *live desktop*, not the installer destination screen.
- SHA-256 frame 0: `5ae8e1867d12d4c41001a745145d2c8fdca0b48bc3bb23325a4b69cb930cdca9`. Frames 4 and 5 share `49d9e011fc6d30b61694ab451ebfd81bdd4ad545d5ef10edf1edf71ed8914d9a`; the other four individual digests are pinned in the replay code.
- The OCR from all six frames includes `Bazzite Portal`, `Manage Bazzite`, `Read the Bazzite Docs` and `Search Apps and Actions`. The previous classifier only matched phrases such as `welcome to bazzite` or `live desktop`.
- Serial has GRUB 2.12, automatic `Launch Bazzite Installer` boot; it does **not** prove Anaconda was started.
- Original synthetic-GPT audit confirms `baseUnchanged=true` before and after, `overlayDiscarded=true` at cleanup and no Windows installation attached. This is not installation rollback.
- The replay fails closed on missing/swapped frames, modified ZIP, reordered hash manifest, absent provenance, false runtime assertions or QEMU not running.

**Scope:** `visualLiveDesktopObserved=true`; `installerDestinationObserved=false`; `anacondaProcessVerified=false`; `getActionsObserved=false`; `writeSetVerified=false`. All installation, GPT, Windows ESP, NVRAM, Secure Boot and guest-control authorities remain **false**.

The replay is not a replacement for upstream cryptographic verification: it **reuses the original signed-ISO/OCI evidence** from the unchanged heavy workflow. Only the original artifact ZIP is fetched for replay; any new ISO version requires independent signature and attestation validation, not a reused visual proof. The heavy workflow retains manual dispatch and cryptographic-source push triggers; replay-related file changes are deliberately excluded to avoid repeating an 8.38 GB download.

Next: read-only identity of the modern installer via a Safety/Observer-approved authenticated, bounded guest channel. No generic shell, SSH, GUI navigation or `GetActions()` until its contract exists.
