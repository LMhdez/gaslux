# CachyOS — Windows guest recovery-evidence binding (experimental)

**Status: read-only evidence integration, not a Windows/CachyOS installer.**
No physical disk, EFI/NVRAM, BCD or Windows system mutation is enabled.

This branch stacks on [PR #41](https://github.com/LMhdez/gaslux/pull/41) and
retains the VM-only real CachyOS install/first-boot baseline from
[PR #36](https://github.com/LMhdez/gaslux/pull/36).

## What is reused

The read-only Windows PowerShell collector, offline Python validator and test
harness were reused from [PR #15](https://github.com/LMhdez/gaslux/pull/15)
rather than reimplemented. PR #15 is experimental and this copy remains
isolated from `main`. The collector executes only inside an explicitly
authorized disposable Windows guest; GitHub's ordinary Windows Server 2022
runner **parses and tests code only**, never acts as Windows 10 or Windows 11.

Additional restrictions implemented here:
- Require `Win32_OperatingSystem.ProductType == 1` and a Windows 10/11 client
  version. Reject hosted Windows Server, even if its NT kernel is `10.0`.
- Read the selected, already identified ESP's **FAT32 filesystem serial** using
  `GetVolumeInformationW` on its existing volume GUID path, without mounting
  or assigning a drive letter. Reject unreadable, non-FAT32, zero or unknown
  values; canonicalize as `AB12-CD34`.
- The offline verifier rejects changed FAT32 serials across guest observations,
  changed Windows EFI hashes, changed WinRE WIM digests, tampered BCD, unsafe
  GPT changes and an absent subsequent Windows reboot timestamp.
- `auto_tests/tools/cachyos_windows_guest_evidence_binding.py` binds the
  Windows guest evidence to the **existing** Gaslux v4/v5 installation plan,
  ordered execution-state ledger and Ed25519 signed Archiso handoff. It matches
  source disk identity/size/sector size, Windows+ESP+WinRE GPT type/number/
  offset/size, Windows FAT serial, Windows Boot Manager SHA-256 and BCD text
  SHA-256 against the candidate baseline already referenced in the handoff.
- For `postinstall`, require exactly one newly created GPT Linux filesystem
  extent matching `disk.installer.number`, `finalOffsetBytes` and
  `finalSizeBytes`. For `rollback`, require the original GPT partition map,
  Windows EFI/BCD/WinRE/BitLocker and firmware enumeration evidence to match.
  This code **only compares** guest-provided observations.
- Linux root/ESP ownership, kernel boot and update must still be verified
  independently using the actual running Linux guest and storage geometry.

## Threat model / remaining gaps

The Windows collector outputs JSON. That output alone has **no external
authenticity or provenance guarantee**. A fabricated baseline/postinstall
report can satisfy every structural comparator, even when an actual Windows
guest never booted. The Ed25519 Archiso signer used in tests is ephemeral and
does not establish a trusted Windows firmware boot chain. The power-cut and
Windows restoration workflows are not implemented by this branch. A
pre-handoff state snapshot is not a final transaction outcome.

Therefore, even after all synthetic tests pass, the returned
`storageWritesAuthorized`, `releaseEligible`,
`windowsBootVerified`, `windowsBcdAndWinreRestorationVerified`,
`firmwareBootOrderRestorationVerified` and
`transactionIntegratedIntoProductionInstaller` values are **always false**.

The production WPF/C#/PowerShell path still needs:
1. A maintainer-approved signed distribution capability and exact ISO size
   contract with permanent Windows-owned trust anchor (not a lab key).
2. An authenticated evidence chain from Windows before changes, independent
   snapshot recovery, boot into real Archiso, Linux installed first boot,
   and an **independent** return to the original Windows 10/11 client guest.
3. Actual Windows boot, WinRE/BCD/ESP/BootOrder/BitLocker/NTFS and second-disk
   geometry checks before and after update and rollback; restore and verify
   all original GPT/EFI metadata before reporting success.
4. Secure Boot and BitLocker fail-closed refusal, retries, idempotent
   compensation and physical-disk protection, plus Mint/Zorin regressions.
5. Successful independent reviewer-signed 20-scenario Windows 10/11 campaign
   under [issue #3](https://github.com/LMhdez/gaslux/issues/3) and human review.

No new distribution is enabled in the stable release catalog.
All new Python and PowerShell tests use synthetic evidence and mock data;
the included three QEMU/OVMF smokes remain **Linux/synthetic only**.
A successful GitHub Actions workflow does not certify a Windows dual boot.

Licence: GPL-3.0. Reused code originates from Gaslux PR #15 and retains its
authorship. Generated-by: GPT-6; human review required under AI_POLICY.md.
