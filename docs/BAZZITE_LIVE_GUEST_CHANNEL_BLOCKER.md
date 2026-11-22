# Bazzite live collector: no authenticated guest execution channel (Result C)

Date: **2026-11-20**. PR #262, dependent on draft #250.
**Outcome: Result C only.** No new Bazzite boot, no live Anaconda D-Bus
call and no capture of `GetActions()`. Bazzite stays experimental UEFI/GPT.

## Source inspection: what #250 actually configured

The laboratory's real optical-boot workflow is
`.github/workflows/gaslux-bazzite-legacy-readonly-gpt.yml` from #250.
It used one downloaded `bazzite-stable-amd64.iso`, SHA-256
`9c8d06cd8e57f2274678edeb14b4b13a79b8117c70571a65199919a66305b5c7`,
7,907,770,368 bytes. That SHA is a **historical local byte identity**,
not an independently verified upstream signature or deployed Atomic payload.

The QEMU command has:

| Channel | Existing configuration | What it proves |
| --- | --- | --- |
| Optical media | IDE CD-ROM, `readonly=on` | Legacy ISO presented without host-write permission |
| Disk | one `virtio-blk-pci`, serial `GLXBAZRO001`, QCOW2 | Synthetic scratch device, **not** Windows |
| Firmware | OVMF CODE read-only, fresh disposable VARS | No persistent Windows NVRAM used |
| Network | `-nic none` | No configured guest networking |
| GUI | `-vnc 127.0.0.1:1` | Frame observation; VNC is input-capable and must not be used to bypass Observer |
| Serial | `-serial file:.../serial.txt` | Guest-to-host text log, **not** authenticated host-to-guest command execution |
| HMP | `-monitor none` | No interactive HMP endpoint in #250 |
| QGA / virtio-serial / vsock / SSH | Not configured in QEMU arguments | No supported executable collector command path was established |

This is **configuration evidence**, not runtime proof that no services are
installed in the ISO. Earlier #250 GUI observations are genuine, but do not
include a trusted shell, Anaconda PID, RPM versions or D-Bus method inventory.

The separate #262 QEMU/OVMF job deliberately uses `-S` (stopped CPU)
and temporarily reads host HMP `info block`/`info qtree` before exiting;
it does not launch the ISO, start Anaconda or query a guest D-Bus bus.
An HMP/QMP controller is a powerful VM-management surface, **not** a
preauthorized read-only collector transport.

## Why no new legacy live boot was authorized

The pinned legacy ISO still has no verified independent upstream signature
and no ISO-to-Atomic-payload binding. The independently verified OCI digest
from upstream Bazzite refers to a separate artefact and cannot authenticate
this CD-ROM. Under the requested fail-closed policy, we did **not** launch
the unsigned legacy code merely to obtain D-Bus results, nor substitute an
unverified newer ISO. No ISO, initrd, kernel, or firmware was instrumented.

No SSH, QGA, arbitrary shell, VNC input, keypress or partitioning GUI action
was enabled. No `ApplyPartitioning`, `InstallWithTasks`, `mkfs`,
deployment, EFI/NVRAM or Windows disk writes occurred.

## Limited host-only alternative, tested on real QEMU

`auto_tests/bazzite_live_channel_boundary.py` does not implement a guest
executor. It audits a **running but paused** QEMU process independently
through the host's `/proc/<pid>/cmdline`, `/proc/<pid>/stat` start ticks and
`/proc/<pid>/exe`, including the QEMU executable's SHA-256. It validates
the collector's local SHA-256, requires the exact single-device stopped QEMU
topology with no command channel, and uses the existing #262 synthetic GPT
inspector plus the existing Bazzite candidate contract. It neither
reimplements GPT parsing nor relaxes the write-set comparator.

The transaction ID is a fresh 128-bit host random value embedded in
`-name gaslux-bazzite-<id>`; an exclusively created local host marker
rejects replay, and a second independent `/proc` reading rejects PID or
start-time replacement. These checks prove **host-local identity only**;
they do not bind the guest process or constitute a Safety/Observer approval.
The collector hash is calculated/pinned inside this workflow; that is not
an independent signature or source attestation.

The host audit intentionally returns exit code **2** with JSON
`REFUSED_NO_AUTHENTICATED_GUEST_COLLECTOR_CHANNEL`, even when every
QEMU/disc check matches. It records:

- `collectorInvoked=false`, and `collectorStdout`,
  `collectorStderr`, `collectorExitCode` all **null**: no invocation
  occurred; do not attribute the host exit code to the collector.
- `isoBooted=false`, `anacondaDbusServiceObserved=false`,
  `getActionsObserved=false`, `writeSetRealObserved=false`.
- `installationAuthorized=false`, `partitionWriteAuthorized=false`,
  `windowsEspWriteAuthorized=false`, `nvramWriteAuthorized=false`.
- The observed QEMU process identity/hash, synthetic disk GUID/PARTUUIDs,
  host transaction and collector hash. No secrets or disk images are output.

The negative tests cover forged collector hash, substituted QEMU process,
PID/start-time drift, reused transaction, unapproved `-qmp`,
`-chardev`, `-vnc`, guest agent/SSH-capable device, changed NVRAM
attachment, foreign disk, changed serial and invalid transaction. The
preexisting Anaconda capture tests cover absent/replaced D-Bus service,
malformed replies and missing methods. **All contract successes are
negative-policy/host-only tests, not a live installer observation.**

## Non-negotiable missing gates

1. Independent attestation of the exact ISO booted, or an explicitly
   instrumented signed ISO with verified identity and compatibility; do
   not silently replace the legacy image. Authenticate the Atomic payload
   separately and tie both identities together.
2. An independently authenticated, _least-privilege guest read-only_
   communication mechanism that exists in the verified ISO or is explicitly
   integrated into an authenticated instrumented test build. It must have
   a fixed collector hash/entry point, no generic shell, no static HMAC
   keys, a single-use transaction, bounded output and process/VM identity.
3. GASLUX-OBSERVER #259 approval for any GUI-driven interaction; none
   is currently granted to this Bazzite experiment.
4. GASLUX-SAFETY #265/#267 verification of independently attested host
   backing, QEMU process/session identity, guest disk GUID/PARTUUIDs and
   no-writer decision. A JSON file or host nonce is not proof of
   independent guest authentication.
5. Only after these proofs: read actual Anaconda `GetActions()`,
   `GetDevices()` etc using the existing collector, then compare the
   raw observed operations to the **unchanged** #262 write-set gate.
   Unobserved GPT, ESP, NVRAM and Atomic deployment operations remain
   blocking even if `GetActions()` returns an empty list.

The next experiment must run first with a real authenticated read-only
guest endpoint in a discardable VM. Until then, the host-only lab may
attest QEMU and synthetic GPT, but must **refuse guest execution**.
