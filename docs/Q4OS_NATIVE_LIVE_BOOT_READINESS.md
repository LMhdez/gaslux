# Q4OS-NATIVE-LIVE-BOOT-01 — readiness manifest and source trust

**22 November 2026 UTC.** Experimental and **read-only only**. Parent:
[Q4OS-RUNLAB-BOUNDARY-01, Draft PR #338](https://github.com/LMhdez/gaslux/pull/338),
HEAD `72018d795ce9aeec5f2918a888c12bec542fd2c9`.
Base of #338: [Draft #318](https://github.com/LMhdez/gaslux/pull/318).
**Independent Safety approval has not been observed on #338.**
The historical independent [Safety finding on #318](https://github.com/LMhdez/gaslux/pull/318#issuecomment-7078921738)
was `CHANGES_REQUIRED`. The later fix had successful CI but must not be
promoted to independently approved without a new review.

## Identified image, not an authorized image

| Attribute | Pinned historical source evidence |
| --- | --- |
| Distribution and architecture | Q4OS Andromeda 6.10 r2, x86_64 |
| Native ISO | `q4os-6.10-x64.r2.iso` (desktop native live ISO; **not** WinSetup.exe) |
| Project download | `https://downloads.sourceforge.net/project/q4os/stable/q4os-6.10-x64.r2.iso` |
| Upstream SHA-256 | `1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d` |
| Upstream checksum page | `https://sourceforge.net/projects/q4os/files/stable/q4os-6.10-x64.r2.iso/download` |
| Historical inspection | [Action #43936058057](https://github.com/LMhdez/gaslux/actions/runs/43936058057), successful byte/hash validation, SquashFS and Debian 13 live identity on 16 Nov 2026 |
| Native installer in that same verified ISO | Calamares; [configuration/installation graph evidence #43964771409](https://github.com/LMhdez/gaslux/actions/runs/43964771409), historical only |
| Calamares safety hazard | `installEFIFallback: true` could overwrite `EFI/BOOT/BOOTX64.EFI`, therefore any Windows ESP write is DENY |
| Exact media size | **NOT FIXED IN SIGNED METADATA** (historical workflow only bounded 1.5–3.0 billion bytes) |
| Signed Gaslux release-catalog metadata | **NOT FOUND / NOT VERIFIED**; `release-config.json` on `dev` lists Mint and Zorin, not Q4OS |
| Detached publisher signature/root of trust | Not independently verified in this task |
| ISO bytes freshly validated in this task | **NO** (no new download, hash recomputation or ISO mounting) |

SourceForge's published SHA-256 is a **public integrity anchor**, not a
publisher signature or the project's signed release catalogue. The presence
of a hardcoded hash in source, documentation, or CI does **not** upgrade
provenance by itself. This branch deliberately leaves
`SIGNED_RELEASE_METADATA_VERIFIED = False`.

## Machine-readable DENY-only source → destination → guest graph

[`auto_tests/tools/q4os_native_live_boot_readiness.py`](../auto_tests/tools/q4os_native_live_boot_readiness.py)
emits only a preparation document validated by
[`schemas/gaslux-q4os-native-live-readiness.schema.json`](../schemas/gaslux-q4os-native-live-readiness.schema.json):

| Graph node/edge | Evidence here | Authority |
| --- | --- | --- |
| Publisher → exact ISO version/SHA-256 | Project distribution URL and public checksum | Source reference only; no signature |
| ISO bytes → SHA-256 | Optional FD-open in an **owned private directory**, `O_NOFOLLOW|O_RDONLY`, matching `fstat`/`pread` hash and bounds | Only current bytes when an actual file is supplied; none supplied in current CI |
| ISO bytes → QEMU ISO FD | **NOT OBSERVED** | DENY |
| QEMU PID/executable/birth → QMP peer | Demonstrated *historically* with **synthetic nonbootable media** in #338; not observed with native Q4OS ISO | DENY for native boot |
| QCOW2 inode/backing/geometry → QEMU destination FD | Historic synthetic #338 only, no Q4OS ISO VM binding here | DENY |
| Firmware OVMF/SeaBIOS → QEMU FD | Historical OVMF lab only; no new firmware/ISO binding | DENY |
| QCOW2 snapshot/checkpoint → verified recovery | **NOT OBSERVED** for native Q4OS live-boot experiment | DENY |
| QEMU → ISO booted → kernel/userspace | **NOT OBSERVED** in this intervention | DENY |
| Guest observation → authenticated Guest origin | **NOT OBSERVED** | DENY |
| Calamares/partitioning → installed Linux | Prohibited in this stage | DENY |

The static manifest never claims
`QEMU_STARTED`, `ISO_BOOTED`, `KERNEL_BOOTED`,
`USERSPACE_BOOTED`, `GUEST_OBSERVATION_RECEIVED` or
`GUEST_ORIGIN_ATTESTED`. It contains no PID, disk inode, EFI path or
unverified boot signal fabricated as evidence.

With no ISO input: `SOURCE_REFERENCE_ONLY`. With a matching actual ISO:
`MEDIA_HASH_ONLY`; the original descriptor is **closed**, so this is
**not** proof that a later QEMU instance opened that same inode. Neither
level authorizes boot. The schema makes all boot/production gates
`const:false`, and is not itself a signature or a runtime policy engine.

## Read-only measurement and adversarial tests

`measure_fd(fd, expected_sha256, min_bytes, max_bytes)` is deliberately a
generic primitive for small synthetic fixtures; it checks:
- Linux FD is actually read-only, owned, regular, has one hardlink and no
  group/other permissions.
- File size within limits, no intermediate pathname opens, `pread` hashing
  from a pinned FD (without altering file offset), and `fstat` dev/inode,
  owner, mode, link count, size, mtime and ctime stable across reading.
- Digests match exactly; unexpected exceptions become finite reason codes
  without leaking private file paths.
- A file renamed after pinning is measured by the **original inode**, not
  a substitute path. An in-place modification during reading is refused.

`measure_official_iso()` only permits the fixed Q4OS file name in a
private, owned directory opened with Linux `O_DIRECTORY|O_NOFOLLOW`,
and passes the **hardcoded official digest** and historical broad size
bounds; it neither computes an arbitrary accepted official hash nor
installs/launches anything. It does not prove future
ISO→QEMU descriptor inheritance or signed source trust.

The offline tests use **synthetic tiny files only** and cover digest
mismatch, incompatible bounds, symbolic links, hardlinks, group/public
permissions, writable and invalid FDs, path substitution, in-place
mutation, invalid input, spoofed metadata/guest/gate flags and no private
path disclosure.

### Deliberate limitations

1. The exact ISO byte size has not been authenticated as a signed field.
   Broad historical bounds alone are not sufficient for release readiness.
2. A current ISO's internal Calamares, UEFI boot graph and kernel/root
   identity are **not** rechecked in this intervention. The old inspection
   cannot certify mutable upstream download content without a new byte
   hash measurement.
3. `O_NOFOLLOW` and directory FDs protect the final path components in
   the private runner model, but this tool is **not** a general hostile
   multi-user filesystem sandbox and cannot independently authenticate
   ancestor directory trees.
4. The source checksum is not an independent detached signature. Even a
   matching SHA-256 from an arbitrary caller does not grant provenance.
5. None of the tests contains QEMU-system, QMP, Guest input, Calamares,
   Windows Setup, partitioning, host disks, ESP/BCD/WinRE or NVRAM.
   This is **preparation only**, not live-boot evidence.

## Required gates before a genuine Q4OS live boot

1. Favorable independent Safety reauditoria on [#338](https://github.com/LMhdez/gaslux/pull/338)
   and this exact new differential, including QMP peer/FD binding and
   incomplete cleanup; check open findings, not just a GREEN test job.
2. Authenticate the **exact** native ISO bytes and origin, fix exact size
   and trust metadata under the signed-catalogue policy. Do not silently
   replace the pinned Q4OS 6.10 r2 ISO by a moving/latest version.
3. Compose existing `dev` HOST/FD ProcessSeal and Guest Peer/Observer
   boundaries with the Q4OS historical stack; do not duplicate them.
4. On a disposable, properly isolated runner, prove QEMU's inherited
   ISO and QCOW2 FDs are the actual verified inodes. Use a private,
   independently verified QCOW2 without foreign backing and restore-able
   checkpoint, and a verified OVMF/SeaBIOS firmware pair.
5. With separate Safety authority and valid gates, attempt **live boot only**,
   no installer launch. Independently distinguish process start, ISO/EFI
   boot, kernel, userspace, and Guest-origin attestation. If there is no
   authenticated collector, report `GUEST_ORIGIN_ATTESTED=false`.
6. Keep `run_lab()` and `QEMU_FD_BACKING_VERIFIED=false` unchanged; never
   use a successful QEMU lab to arm Windows/Calamares/ESP writers.

## CI and release gates

[`gaslux-q4os-native-live-readiness-offline.yml`](../.github/workflows/gaslux-q4os-native-live-readiness-offline.yml)
checks the exact commit, Python syntax, Ruff, Q4OS preflight regressions,
all FD adversarial fixtures, JSON Schema and a bounded **DENY-only**
manifest. It installs no QEMU, downloads no ISO and performs no boot.
Any CI success is an offline contract result, **not** native ISO validation.

`QEMU_FD_BACKING_VERIFIED=false`  
`productionStorageWritesAuthorized=false`  
`q4osNativeInstallationVerified=false`  
`sameDiskDualBootVerified=false`  
`windowsInPlaceRollbackProven=false`  
`releaseEligible=false`  
`stable=false`

**No merge** before independent Safety review and dependency integration.
Generated-by: GPT-6; GPL-3.0; human review required.
