# Bazzite / Anaconda: live D-Bus read-only capture (experimental, blocked)

**20 November 2026.** Extends PR #262 on #250. This collector does **not**
run in the host-only paused-QEMU job and does **not** authorize installation.
Bazzite remains UEFI/GPT-only, off the stable catalog.

## Confirmed evidence

- [#44714419626](https://github.com/LMhdez/gaslux/actions/runs/44714419626)
  ran **real host GPT/QEMU/OVMF** at commit `71633ff130b39104851d2e40c7df10ae4ee8987b`.
  The guest CPU remained stopped (`-S`). Three synthetic GPT partitions,
  read-only QCOW2 attachment, unique `GLXBAZRO001` serial, immutable backing
  and successful overlay discard were checked. [Artifact #14619710164](
  https://github.com/LMhdez/gaslux/actions/runs/44714419626/artifacts/14619710164).
  This job did **not** boot a Bazzite ISO or inspect a live guest D-Bus bus.
- Earlier #214/#250 optical-boot GUI images identified the Bazzite 42
  Anaconda storage UI and Advanced Custom (Blivet-GUI) control; none delivered
  a trusted guest command channel, executable hashes or native `GetActions()`
  export. An OCR label is not a storage-action graph.
- Official Anaconda documentation lists `GetActions`, `GetDevices`,
  `GetDeviceData`, `GetFormatData`, `GetDisks`, `GetMountPoints` and
  `GetBootDevice`. **The actual Bazzite 42 version/interface is not yet
  measured**; an upstream API document is not runtime proof.

References:

- https://anaconda-installer.readthedocs.io/en/latest/autoapi/pyanaconda/modules/storage/devicetree/viewer_interface/index.html
- https://anaconda-installer.readthedocs.io/en/latest/autoapi/pyanaconda/modules/storage/storage_interface/index.html
- https://github.com/LMhdez/gaslux/pull/259 (GASLUX-OBSERVER)
- https://github.com/LMhdez/gaslux/pull/265 and https://github.com/LMhdez/gaslux/pull/267 (GASLUX-SAFETY)

## New guest-side collector

`auto_tests/bazzite_anaconda_readonly_capture.py` requires a **previously
authorized, isolated live guest shell**. It does not acquire one itself,
navigate the installer, press any button, or invoke methods that schedule,
apply or commit partitioning. It refuses a missing D-Bus service without
autoactivation, resolves the unique current D-Bus owner and PID, reads the
process command line and hashes its executable. It also records available
Anaconda/Blivet RPM versions and hashes of discovered installer executables
without presenting these as independently trusted.

It introspects the guest's actual D-Bus object tree, accepts only a unique
storage viewer exporting zero-input `GetActions()`, and reads other methods
**only when present and with the observed input signatures**. Raw busctl
outputs are preserved, not fabricated. Calls use the unique owner rather
than an autoactivatable well-known name and re-check ownership after reads.
An explicit allowlist rejects `CreatePartitioning`, `ApplyPartitioning`,
`InstallWithTasks`, filesystem formatting, write tasks and arbitrary D-Bus
calls before any subprocess is executed.

The collector also reads `lsblk --json` inside the guest. It requires
exactly one disk with the laboratory serial, 70 GiB size, 512-byte logical
sectors, a GPT GUID and exactly three non-overlapping protected PARTUUIDs.
This is a **guest-side observation**, not a new GPT parser nor verification
against the host. Full, signed host-to-guest cross-validation belongs to
Safety #265/#267.

When invoked in that already authorized guest, output is only allowed
directly in the RAM-backed `/run` mount, exclusive `0600`, with an
atomicity-limited fsync and bounded JSON. The output always states
`origin=anaconda-dbus-readonly-untrusted` and denies every write permission.
It does not self-sign, contain a hard-coded HMAC secret or declare a trusted
QEMU transaction. No completed live invocation is yet evidenced.

## Existing write-set gate remains authoritative

`auto_tests/bazzite_anaconda_write_set_gate.py` is unchanged. It rejects
`anaconda-dbus-readonly-untrusted` exports. The raw `GetActions()` D-Bus
structures cannot be substituted directly for the prior synthetic replay:
they need exact type-specific interpretation and host-authenticated binding.

Unobserved and non-authorized effects include GPT primary/backup/PMBR,
formatting outside Blivet's reported actions, ESP/EFI/Microsoft, GRUB/EFI
loader, NVRAM/BootOrder/BootNext, deployment payload digest, post-update
bootloader behavior and Windows recovery. In particular, observing an empty
`GetActions()` list does **not** validate a three-partition installation
proposal.

## Next proof required for Result A/B/C

A future approved QEMU experiment must furnish a controlled **read-only
guest command channel** (e.g. independently measured live-side agent)
with GASLUX-OBSERVER authorization and Safety-bound transaction. Without
this, a host-only QEMU inventory cannot query live Anaconda at all. It must:

1. Prove the ISO's exact local SHA-256/size, QEMU launch parameters,
   read-only backing chain and immutable OVMF vars isolation.
2. Prove the live Anaconda/Blivet executable hashes, RPM version, D-Bus
   owner and available method signatures **before** attempting `GetActions`.
3. Read actual device/action objects, pair exact host and guest serial/GUID/
   PARTUUID/geometry using Safety's verified contract, and retain raw
   payloads and failure records. Do not invoke partition planning methods
   without explicitly verified non-mutating semantics; GUI input is blocked
   until the Observer grants a real lease.
4. Translate only measured actions; leave missing EFI/NVRAM/Atomic stages
   `unobserved`; run the original write-set gate and keep write permission
   false. Report complete QEMU screenshot, stdout/stderr and overlay audits.

**Current outcome:** collector/test harness available, real Anaconda bus
capture unperformed. The historical ISO `bazzite-stable-amd64.iso`,
7,907,770,368 bytes, lab SHA-256
`9c8d06cd8e57f2274678edeb14b4b13a79b8117c70571a65199919a66305b5c7`,
has no verified independent detached signature or ISO-to-Atomic-payload
binding. A signed OCI digest from #44711145800 does not replace that proof.

No Windows/physical disk, ESP, NVRAM or firmware key was written; no Atomic
deployment, Linux/Windows first boot or recovery was demonstrated.
