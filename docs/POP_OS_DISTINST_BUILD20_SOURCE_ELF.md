# POP-DISTINST-ELF-SOURCE-BINDING-01 — build 20 provenance

**Verdict: SOURCE_TO_INSTALLED_ELF_UNPROVEN.** Scope: authenticated
*laboratory* Pop!_OS 24.04 Intel build 20 only. No installer, partitioner,
formatter or writer executed. This report does not promote the offline
Gaslux contracts to permission to install Pop!_OS.

## Identity and evidence classes

| Chain link | Observed evidence | Trust and missing link |
| --- | --- | --- |
| Official ISO | System76 signed SHA256SUMS known to prior Gaslux work; build 20 ISO is 2,955,067,392 bytes, SHA-256 \`a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c\` | ISO bytes pinned; this PR does not claim to reverify a fresh GPG signature |
| ISO package choice | [pop-os/iso config for 24.04](https://github.com/pop-os/iso/blob/8a441114a3332f0409d39bc940f4b149fb896870/config/pop-os/24.04.mk) specifies live \`distinst\` and \`pop-installer\` | Source-level package name only; exact historical .deb not available from current index |
| Installed ELF | Previously observed \`/usr/bin/distinst\` SHA-256 \`8bfedbc2d6921c440449ec1fda8c4e4d1c0078d69db5aa5832d9a7bf8b13e1a5\` | No original .deb digest, signed package index, build log or .buildinfo bound to these bytes |
| Installed package metadata | Historical ISO's \`/var/lib/dpkg/status\` is not present in this Git repository | Exact distinst Version, Depends, Source field and package Build-Id **NOT_OBSERVED** |
| APT publisher | [System76 release repository](https://apt.pop-os.org/release/), signed \`InRelease\` and [repository build machinery](https://github.com/pop-os/repo-release/blob/master/build.sh) | Current repository rotates to newer packages; current 2026 \`distinst\` package cannot authenticate the ISO's 2025 ELF |
| Source candidate | [pop-os/distinst@143114f7](https://github.com/pop-os/distinst/commit/143114f7fffc4060a7586b940863c3be043d9ab9), committed 2025-10-02 | Chronologically compatible, **not proved to be selected for ISO build 20** |
| Earlier review | [pop-os/distinst@282dfc4](https://github.com/pop-os/distinst/commit/282dfc441ee608e963930d0ce01f04b672ca4f71), 2026-09-16 | Postdates [public user report identifying build 20](https://github.com/pop-os/pop/issues/3612) dated 2025-10-10; cannot be the original build's source revision |
| Dependency lockfile | Both candidate 2025 and reviewed 2026 revisions have identical \`Cargo.lock\` Git blob \`131d45f2339f0e600f780c1fad22da2e6995e22c\`; crate \`distinst\` has version \`0.5.0\` | \`debian/changelog\` and current packaging version \`0.3.2\` do not uniquely identify the compiled Git source; lockfile alone is not binary attestation |
| Build provenance | No signed historical \`.buildinfo\`, \`.changes\`, APT \`InRelease\`+Packages+deb hash for the exact build-20 package, or reproducible build result acquired | **SOURCE_TO_INSTALLED_ELF_UNPROVEN** |

The 2026 upstream \`distinst\` has a package version listed as
\`0.3.2~178...~24.04~282dfc4\` in System76's current APT/Poparazzi
page. It is NOT the historical package version of build 20. Do not use
that current APT index to select a candidate historical source.

## Source comparison and causal effects (candidate, NOT proven ELF)

The five files \`cli/src/main.rs\`, \`src/installer/mod.rs\`,
\`src/installer/steps/initialize.rs\`, \`src/installer/steps/partition.rs\`
and \`src/installer/steps/bootloader.rs\` have identical Git blobs at
\`143114f7fffc4060a7586b940863c3be043d9ab9\` (2025) and
\`282dfc441ee608e963930d0ce01f04b672ca4f71\` (2026). This is
evidence of **source stability for these five files**, not evidence
that the ISO ELF was built from either revision.

| Relative stage | Potential effects visible in candidate source | Causal confidence |
| --- | --- | --- |
| CLI parse / configuration | \`--use\`, disk selection, \`--test\`, boot settings may resolve paths; no proof of secure physical disk binding | Source observation only |
| \`Installer::initialize\` | \`deactivate_device_maps()\`, \`unmount_devices()\`, \`unmount_all_partitions_with_target()\`, possible mount namespace / device-mapper state changes **before** disk.commit | These are real potential **state-changing effects**, not proven persistent sector writes; no safe dry-run claim |
| \`Installer::partition\` | Calls \`disk.commit()\` on planned disks, then \`partitions_to_format.format()\`; this is the earliest confirmed **potential persistent GPT write** in the inspected source path, not the authenticated build-20 binary | Write possible; no permission to execute |
| Mount targets | \`mount_all_targets()\` follows the partition stage; may change mount state | Source only |
| Test flag | \`PARTITIONING_TEST\` checked *after* \`partition\` and mounts | \`--test\` cannot be used as a read-only gate in this inspected source |
| Boot | For BIOS code uses \`grub-install\`; Pop UEFI calls \`bootctl install --no-variables\` and conditionally \`efibootmgr\` | Not bound to build-20 binary, cannot guarantee Windows Boot Manager/ESP preservation |

**First state change:** device-mapper deactivation/unmounting may occur
during \`initialize\`, before \`disk.commit\`. Their persistence/recovery
effects are not authenticated to the pinned ELF. **First potential
persistent disk write in the inspected source:** \`Installer::partition
→ disk.commit\`; prior state effects do not prove sector writes and do
not constitute a no-op. No claim is made about the first persistent
operation in the installed ELF, because its source revision is unproven.

## Offline forensic implementation

\`auto_tests/tools/gaslux_popos_build20_source_elf.py\` validates only
a bounded, owned read-only extraction of \`build20.iso\`, \`distinst.elf\`
and \`dpkg.status\`. On valid inputs it returns the exact installed
package Version, Architecture, Depends and optional Source field, while
refusing mismatched ISO/ELF SHA-256, ambiguous/missing package stanzas,
foreign files or an untrusted runner context. A suffix resembling a
Git abbreviated revision is a **candidate**, never attestation.

**No real ISO extraction has yet been executed by this PR.** All
positive fixtures are tiny synthetic files with monkeypatched expected
hashes; they cannot and must not support claims that official ISO,
ELF, repository signature, Cargo.lock or build-id were reverified.
The report always sets source correspondence, build-info authentication,
boot, rollback, installer execution and release eligibility to false.

## How to close the source→ELF provenance gate

Use only a disposable, authorised hosted read-only workspace: independently
verify System76's signature over the exact ISO checksum, hash the complete
download, extract (without execution) \`/var/lib/dpkg/status\` and the
\`/usr/bin/distinst\` ELF from the ISO's squashfs, capture Debian
\`Version\`/\`Depends\`/\`Source\`, \`readelf -n\` build-id and binary hash.
Obtain the corresponding historical signed APT Release/Packages index,
the .deb itself and its source package/.buildinfo/.changes. Validate the
package ELF bytes against the ISO ELF, GPG chain and package-to-source
revision; compare the locked dependencies and if possible reproduce the
build against those inputs. A matching abbreviated Git suffix alone is
NOT cryptographic source-to-binary proof. If any link cannot be
authenticated, retain **SOURCE_TO_INSTALLED_ELF_UNPROVEN**.

**Permanent denies:** \`distinstExecutionAuthorized=false\`,
\`windowsWriterAuthorized=false\`, \`productionInstallationAuthorized=false\`,
\`sameDiskDualBootVerified=false\`, \`observationComplete=false\`,
\`windowsInPlaceRollbackProven=false\`, \`releaseEligible=false\`,
\`stable=false\`. No actual write-set or preflight-to-commit
protection is demonstrated.
