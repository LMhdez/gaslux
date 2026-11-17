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

## 17 November 2026: real Windows evidence and stronger candidate checks

The completed Windows 10/11 **failed** official-ISO workflow
[#44048550209](https://github.com/LMhdez/gaslux/actions/runs/44048550209)
is useful for isolating the original host-side COM1 parsing defect.
Downloaded [Windows 10 archive #14312953039](https://github.com/LMhdez/gaslux/actions/runs/44048550209/artifacts/14312953039)
and [Windows 11 archive #14313808220](https://github.com/LMhdez/gaslux/actions/runs/44048550209/artifacts/14313808220)
both have a matching serial SHA-256 manifest. In each raw second-guest
serial, **all seven** expected client markers were present as exact
whitespace-delimited tokens on one line: client profile, build,
ProductType=1, GPT/ESP, Recovery GPT, WinRE enabled and BCD enumeration.
Neither contained a FirstLogon failure token. Both QEMU jobs returned
code 0; the **old host parser** nevertheless reported the Windows client
unverified because it expected one marker per line. The workflow
conclusion is still **FAILURE**, and must not be changed retrospectively.

By contrast, the [Windows 11 serial archive #14316291836](https://github.com/LMhdez/gaslux/actions/runs/44044462226/artifacts/14316291836)
from [run #44044462226](https://github.com/LMhdez/gaslux/actions/runs/44044462226)
has a valid SHA-256 but **none** of the seven Windows audit tokens; it
timed out after entering Windows Boot Manager. A Windows Boot Manager
firmware event is not a first-logon proof.

The later native Windows scanner in PRs #90/#93/#94 already addresses
COM1 coalescing and bounded token acceptance. This candidate gate
additionally requires exactly the **seven profile-specific tokens**,
rejects unknown or conflicting tokens and compares the reported
FirstLogon PowerShell script SHA-256 with the file generated from the
**current checked-out source**. It also requires the exact diagnostic
indicating both in-guest audit and clean QEMU shutdown; QEMU exit code
zero alone cannot satisfy the gate. Positive candidate documents still
never authenticate an actual guest or authorize any Linux installation.

Candidate-gate unit CI passing does not substitute for a fresh SUCCESS
real-Microsoft-ISO Windows 10/11 QEMU run with these corrected checks,
much less same-QCOW2 dual boot or Windows recovery.

## Both VM-stage COM1 manifests must be bound (experimental)

The candidate gate now requires **both** the first Microsoft DVD/Setup-stage COM1 evidence and the second disk-only Windows-client COM1 evidence, with their separately archived SHA-256 manifests. The first-stage COM1 bytes must agree with `initialDvdGuestSerialSha256` in the result JSON, must match the exact profile-prefixed first-stage manifest filename, and must contain **exactly one** documented OVMF UEFI DVD startup. The first-stage file must be nonempty and at most **2,000,000 bytes**, matching the preexisting CI archiver's retained-evidence limit. The second-stage digest, full Windows client audit and clean VM exit remain independently mandatory.

The added CLI arguments are `--initial-dvd-serial` and `--initial-dvd-serial-sha256`, taking the existing `<profile>-initial-dvd-serial.log` and `<profile>-initial-dvd-serial.sha256` artifacts from the **same** disposable GitHub runner. Missing, symlinked, nonregular, oversized, inconsistent or repeated DVD-start evidence fails closed. No source ISO, QCOW2 or credential is uploaded.

This cross-check improves **internal consistency only**. The records and SHA-256 manifests are still controlled by the laboratory; it does not independently authenticate guest provenance or prove installed Windows, CachyOS dual boot, EFI/BCD/WinRE restoration or recovery. All corresponding product approval flags remain false. This code never opens block devices or authorizes disk writes.

## Original Microsoft ISO vs derived no-prompt ISO (experimental)

PR #108 introduced a direct, SHA-pinned, **unaltered official Microsoft
Windows ISO** option for its authorized disposable KVM comparison. That
native Windows result sets `labDerivedIsoOnly=false`, retains
`officialIsoUnmodified=true`, includes the pinned official `isoSha256`,
and **does not** provide `labDerivedIsoSha256`. The older remastered
no-prompt ISO path sets `labDerivedIsoOnly=true` and provides a separate,
valid `labDerivedIsoSha256` distinct from the pinned official ISO digest.

The read-only candidate checker now requires one of these **exclusive**
reporting combinations with an explicit boolean. It rejects ambiguity:
missing mode, a derived ISO without its own distinct SHA-256, or an
original-ISO claim accompanied by a derivative hash. The existing
checks for Microsoft ISO SHA-256, PowerShell first-logon witness,
first/second serial manifests, WinRE/BCD marker content, exact full
client audit and clean shutdown diagnostic remain mandatory.

**This is format compatibility, not independent media authentication.**
The original ISO flag and digest are still self-reported by the hosted
Windows test, and an attacker who forges every input can forge them.
The candidate helper always returns
`windowsGuestOriginAuthenticated=false`,
`windowsBootVerified=false`, `sameDiskDualBootVerified=false`,
`storageWritesAuthorized=false`, and `releaseEligible=false`.
A real original-Microsoft-ISO firstboot run and independent disk identity
and rollback checks must pass before any Windows/CachyOS shared-disk
operation. The existing PR #98 **derived ISO real KVM job is not
reinterpreted** by this change.

This change is stacked on PR #98, which itself remains experimental and
must not be merged into the stable release without issue #3 evidence.
