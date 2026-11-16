# Windows 10/11 x64 — Microsoft evaluation first boot via QEMU TCG (DISPOSABLE VM ONLY)

**Experimental, no Windows+Linux dual boot or production release gate acceptance.**

The normal Ubuntu GitHub-hosted runner used by Gaslux has **no accessible
hardware /dev/kvm**: see [#43974311441](https://github.com/LMhdez/gaslux/actions/runs/43974311441)
and [KVM diagnostic artifact](https://github.com/LMhdez/gaslux/actions/runs/43974311441/artifacts/14280726412).

This branch attempts a *real*, new Windows client installation using
QEMU's software interpreter **TCG**. It does not claim TCG is a
replacement for a production KVM validation or for dual boot.

## Source integrity and licence

- Windows 10 Enterprise 22H2 Evaluation EN-US x64 from Microsoft,
  original fwlink resolved only to allowlisted HTTPS Microsoft CDN,
  fixed SHA-256
  `EF7312733A9F5D7D51CFA04AC497671995674CA5E1058D5164D6028F0938D668`
  from [Microsoft official published Windows 10 PDF](https://download.microsoft.com/download/c/1/1/c11d2ca5-967c-45c0-bc7d-2d9ca3f1fe07/Windows10Enterprise22H2HashValues.pdf).
- Windows 11 Enterprise 26H2 Evaluation EN-US x64 from Microsoft,
  SHA-256
  `BC3F24086EBADC94489066B5AD78089E2CF5C3491E90E790BB81A2B199C10E38`
  from [Microsoft published Windows 11 verification page](https://support.microsoft.com/en-us/servicing/os/windows/docs/2026/09/verify-the-authenticity-of-a-windows-11-enterprise-evaluation-iso-file).
- Official evaluation editions only. **Do not redistribute** the ISO,
  guest image, guest local credentials, activation data or TPM state.
- Windows 10 22H2 reached the end of standard servicing in 2025;
  its scenario is historical-compatibility testing, not a recommendation
  to deploy unsupported Windows.

## QEMU-only operations

1. Refuse execution unless the GitHub runner, its Linux x64 identity,
   canonical temporary directory and explicit lab consent all match
   the fixed disposable workflow. Refuse insufficient free SSD or
   missing OVMF, QEMU or FAT tools.
2. Fetch a single original ISO using allowlisted HTTPS Microsoft
   redirects, reject too-small/too-large responses and compute SHA-256
   **before the guest is ever created**; any mismatch is fatal.
3. Create ONLY a fresh 80 GiB sparse file-backed QCOW2 in the runner's
   disposable temporary directory. The Windows Setup XML may wipe
   *only* virtual Disk 0; the QEMU process is passed no physical
   block device, host USB device, real Windows partition or host
   NVRAM. EFI uses a private copied OVMF variables file.
4. Pass the unattend XML through a fresh, test-only FAT floppy.
   Windows Setup creates EFI/MSR/NTFS, installs the actual evaluation
   image, and creates a non-root local account exclusively inside VM.
   For Windows 11 a private `swtpm` TPM 2.0 is used; bypassing
   hardware checks, product keys or activation is prohibited.
5. On first logon in the **installed Windows client**, a PowerShell
   script rechecks Win32_OperatingSystem.ProductType=1, the expected
   x64 Windows build, GPT and exactly one ESP, the presence of
   Windows EFI loader and successful read-only BCD enumeration.
   It attempts `reagentc /info` and reports only whether that
   command succeeded — **not WinRE health**. The script sends
   exact serial markers through the **guest's COM1** port.
6. The host refuses QEMU exit, empty/stale serial data, a wrong
   OS identity, missing BCD/ESP, an unverified SHA-256 or an absent
   first-logon marker. Record only the bounded serial log, its hash
   and a small result JSON in Actions artifacts, **never an ISO,
   virtual disk or user credentials**.

## Current CI approach and limits

- Run unit/negative tests and XML fixture generation for **both**
  Windows 10 and Windows 11 x64 before downloading media.
- Trigger **two independent** QEMU TCG installations in a GitHub Actions
  matrix: Windows 10 x64 and Windows 11 x64, using separate official ISO
  downloads, file-backed QCOW2 targets, OVMF variables and test-only
  control images. Windows 11 receives a *new disposable swtpm TPM 2.0*.
  Both need separate in-guest firstboot serial witnesses to pass.
  The matrix is experimental; queued/running jobs are not proof.
- QEMU TCG is much slower than KVM; a timeout or resource failure
  is a **failed test**, not a reason to fabricate evidence.
- Passing a guest firstboot check will prove only an installed
  Windows client in UEFI/GPT virtual hardware. It will NOT prove
  the Windows 10/11 dual boot with CachyOS, Windows boot after
  Linux installation, Windows Boot Manager/BCD/WinRE/ESP/BitLocker
  preservation and rollback, kernel update durability, GUI
  integration or hardware.
- Do not merge into main or enable CachyOS as stable; require
  human review under AI_POLICY.md and issue #3.

The home server's separately registered read-only self-hosted
runner is *not* used; this workflow runs only on GitHub-hosted
throwaway Ubuntu VMs.
