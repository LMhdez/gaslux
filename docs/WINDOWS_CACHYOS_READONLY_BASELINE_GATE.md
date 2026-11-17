# Windows 10/11 to CachyOS: read-only firstboot candidate gate

**EXPERIMENTAL. Does not authorize installation, alteration of an ESP, or dual boot.**

This gate is a prerequisite for a future same-QCOW2 Windows 11 UEFI/GPT and CachyOS experiment. It reuses the pinned original Microsoft ISO hashes and client profiles from the existing Windows x64 QEMU host gate. The checker only reads a result JSON, the *second* Windows guest's serial evidence and the matching SHA-256 manifest. It opens no block device, mounts no volume, generates no disk-write plan, and creates no partitions.

Required firstboot artifacts from the existing Windows two-stage temporary QEMU job are the profile-prefixed result.json, serial.log and serial.sha256 files, for either win10_22h2_en_us_x64 or win11_26h2_en_us_x64.

Reject: a non-client or non-firstboot result, unofficial/mismatched Microsoft ISO SHA-256, missing WinRE/BCD/GPT/ESP witness lines, incorrect Windows build, DVD reboots in the disk-only second-stage serial, arbitrary prompt prefixes, duplicate report keys, changed SHA-256 evidence, symlinks, oversized files or nonregular input files.

## Trust boundary

SHA-256 demonstrates consistency against the supplied manifest, **not** independent guest provenance. A forged log and forged manifest could agree. This checker never independently validates GPT geometry, EFI loader, BCD, WinRE WIM or NVRAM, and never authorizes Windows disk mutation. Even when candidateWindowsFirstbootDocumentsConsistent is true, the following properties remain false:

- windowsGuestOriginAuthenticated
- windowsBootVerified
- windowsBcdWinreRestorationVerified
- sameDiskDualBootVerified
- storageWritesAuthorized
- releaseEligible

A successful offline check cannot replace a real Microsoft QEMU/KVM client firstboot SUCCESS job, guest audit, clean shutdown or separate recovery proof.

## Required next integration

1. Run the existing two-stage official Windows firstboot job in an authorized GitHub-hosted disposable KVM runner, with its strong real-client WinRE/BCD/ESP audit and clean poweroff requirements.
2. Inside the same runner, check the profile's output using the read-only candidate tool with --profile, --result, --serial and --serial-sha256. Any nonzero return must fail closed.
3. **Not yet implemented:** retain the Windows QCOW2 only inside the disposable runner. Independently compare its exact ESP/MSR/Windows/WinRE and GPT geometry, EFI and BCD identities, Windows and Linux boot results and BitLocker/Device Encryption before/after. An independent transactional Linux writer must never use the Linux-only whole-disk initializer and must operate exclusively on transaction-owned unallocated/staging extents.
4. Validate actual same-disk Windows boot, CachyOS install/boot, updates, injected faults, WinRE/BCD/EFI/NVRAM and GPT recovery under issue #3, with human review.

PR #56 already provides read-only Windows guest evidence binding; it does not authenticate guest provenance or authorize writes. PR #42 proves a separate Linux-only VM and its whole-disk wipe/initialization **must never be reused on a preinstalled Windows disk**.

No real disks, WPF production paths, distribution catalogue, Windows ESP, WinRE, TPM, BCD or firmware NVRAM are modified.

GPL-3.0; AI_POLICY.md review required. Generated-by: GPT-6.

## COM1 marker framing and validation evidence

The Windows guest's independent PowerShell serial writes may be coalesced onto a single COM1 line. The candidate gate accepts each marker as an exact bounded whitespace-delimited token (at most 256 characters), including multiple adjacent known tokens on a line. It rejects arbitrary prompt/echo prefixes mixed into audit lines, glued markers, duplicates, conflicting values, absent required markers and the FIRSTBOOT_FAIL family even if the failure occurs more than 400 KiB before the success witnesses. This reflects the observed issues addressed in PRs #90 and #93. The result remains **candidate document consistency only** and no guest provenance or writing permission is granted.

At commit `305e288` the dedicated no-ISO CI run #44056001264 passed 27 candidate gate regressions and 11 Microsoft ISO contract tests. No actual installed Windows, Linux dual boot or recovery was executed by this workflow. Earlier intermediate runs failed because one negative test still expected the old error string; the source guard itself correctly rejected the fake prompt. Consult the exact-HEAD Actions run for the final result.
