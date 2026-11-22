# GASLUX-OBSERVER — QEMU real parado → FD aberto → imagem virtual

**Scope: Linux HOST / GitHub-hosted disposable runner only. DENY-ONLY.**
Base: dev at `6439377a6a7f9b336ac9d4894b65745b5a0dc5ff`.
The older [#294](https://github.com/LMhdez/gaslux/pull/294) is intentionally
**not modified**: its stacked experimental base predates integrated
[#319](https://github.com/LMhdez/gaslux/pull/319) and re-importing its files
would duplicate the HOST/FD and ProcessSeal modules already in dev.

## Exact measured scope

`qemu_local_disk_witness.py` imports **integrated** ProcessSeal,
`process_seal`, `borrowed_readonly_proc_fd` and
`query_qemu_block_readonly`, without importing the #259 state machine.
It **never launches QEMU**; only the test supervisor starts a disposable,
non-booted QEMU with `-S`, `-nodefaults`, `-display none`, `-nic none`,
`readonly=on` and TCG. Linux /proc exposes the actual opened disk FD.
`pidfd_open` is held for both samples to guard against PID replacement.
A QMP Unix socket is accepted only when kernel SO_PEERCRED matches that
same QEMU PID and UID. The read-only allowlist remains the pre-existing
`qmp_capabilities`/`query-block`; the QMP reply fields themselves remain
`CLAIMED` and never authenticate VM identity.

The same regular-file dev/inode/size/mtime/ctime and original remote FD
`O_RDONLY` flags must survive both measurements; multiple candidate disk
FDs refuse. The pathname is workspace-owned and has no symlink/hardlink;
QEMU PID/start ticks/argv hash/executable inode are compared to externally
supplied supervisor pins. Those pins are **not independently attested**.
The module reports `localQemuReadonlyDiskFdOpenProven=true` only for the
specific local sample; the actual host Linux QEMU process demonstrably has
the pinned file open read-only. `qemuBackendToFdBindingIndependentlyProven`
stays **false**, since QMP strings and host procfs alone cannot independently
show how the QEMU block graph maps internals to exactly that FD.

## RAW/GPT/QCOW2 test evidence

The CI checks out exact [#267](https://github.com/LMhdez/gaslux/pull/267)
`0be04192acd542646a5b6cd952e01620379edf5d` for its original
`make_raw`, `make_qcow`, `verify_chain` and `host_snapshot` helpers. It
also checks out canonical [#286](https://github.com/LMhdez/gaslux/pull/286)
`9aed36cfdb8c09a461dc38811c326c54180273de` and uses that original
`libertix_disk_identity_gate` (no copied GPT parser).

A synthetic 64 MiB regular-file GPT disk is created exclusively under
the owned disposable workspace (mode 0700); its GPT/PARTUUID CRC and
geometry are read by #286 from real bytes. When QCOW2 is used, #267 checks
the actual two-level backing graph and local hashes; its read-only
`qemu-img convert` builds a separate disposable effective RAW snapshot
checked by #286. The module never treats a QCOW2 host header or the backing
RAW as a demonstrated **guest** GPT. A changed backing path/format, changed
inode or diverged PARTUUID is a refusal, not guest attestation.

CI attacks the real QEMU process with divergent seals and disk geometry,
wrong basename-equivalent disk and concurrent QEMU, cross-VM QMP socket,
abandoned PID/FD, media pathname inode swap, forged and truncated synthetic
QMP responses, wrong backing, replay within the witness, and failed cleanup.
The supervisor checks pidfd termination and process reaping. No guest is
ever started. QEMU and qemu-img access only test-owned regular files.
No physical disk, Windows ESP/BCD/WinRE/NVRAM, QGA, guest shell, installer,
network guest interface, or real write target is accessed.

## Trust-root guest: remaining blockers (do NOT infer from successful CI)

- A separately rooted, signed issuer/supervisor must authenticate the QEMU
  instance, launch executable, command line, backend configuration and
  private disk FD while preventing transient ABA and later substitution.
- A protected, authenticated host↔guest transport with fresh challenges
  must prove delivery to the **intended guest**, not a local host proxy.
- A pinned collector binary and execution identity inside that guest must
  be measured independently; the Anaconda D-Bus unique owner, PID, start
  ticks, executable/package and method whitelist must be rechecked.
- Persistent external single-use ledger, privilege separation,
  independent approval, controlled recovery, updates and boot proof remain
  absent. QMP names, host PID, UUID, self-signed JSON and same-run HMAC are
  not sufficient trust roots.

Successful local witness classification:
`status=BLOCKED_TRUST_ROOT`;
`guestChannelAuthenticated=false`,
`diskWriteAuthorized=false`,
`productionInstallationAuthorized=false`,
`rollbackProven=false`,
`stable=false`,
`externallyAttested=false`,
`freshnessAuthenticated=false`,
`replayProtected=false`.

The GitHub Actions CI is **not** an operational permit. Do not merge
before diff-scoped independent Safety review and Integrator reconciliation.

## 22 November 2026 — QEMU-owned virtio-serial HOST socket; guest provenance negative

[PR #325](https://github.com/LMhdez/gaslux/pull/325) was merged at
`8e68a475d6397ba8fef2e0f9f83758545e202a5f`; its 19 real stopped
QEMU adversarial tests prove a local QEMU process has a read-only FD for
a specific disposable RAW/QCOW2 host file. They do **not** prove a guest
collector. The #294 and #321 historical branches remain closed, #259
is not imported.

The next **test-only** experiment reuses that supervisor, #319
`host_fd_boundary.py` and `guest_transport_peer_boundary.py`. QEMU starts
with an additional private host AF_UNIX socket configured as a
`virtserialport` chardev, but **-S keeps the CPUs paused**. The host
connects, and the kernel `SO_PEERCRED` of that socket identifies the
QEMU **host process**, never a guest process. The independent QEMU
disk-FD witness and local peer witness can therefore both pass while
`guestChannelAuthenticated=false`.

This is a decisive negative counterexample to treating a QEMU-owned
socket as guest provenance: **no guest operating system, guest collector,
guest bytes or authenticated observations exist in this scenario**.
The second sample and in-memory same-witness replay check cannot
authenticate older data; another witness may re-observe the same
claimed session and report only local kernel identity. This is
explicitly **not** durable replay protection.

The same disposable GitHub Actions workflow now tests a missing
guest endpoint, a fake host-side socket, an interrupted endpoint,
a different concurrent QEMU, altered collector/transaction/provenance
claims, injected authorization flags, and attempted replay. All
guest and writer verdicts remain negative. The host-only JSON
manifest and SHA-256 are **untrusted runner-generated diagnostics**,
not an external signature or attestation. The manifest must state
`guestBooted=false` and `guestObservationsReceived=0`.

Required next trust boundary remains a protected host-to-guest
provenance protocol with independently delivered/verified collector
and guest execution identity, a protected persistent challenge
ledger and independent policy approval; attaching virtio-serial
hardware or querying QMP is not enough.

No QGA, SSH, guest commands, installer, partition operations, or
Windows/physical disk writes were added by this experiment.

### Verified runner evidence (2026-11-22, 14:02 UTC)

The first complete [GitHub Action #45030470016](https://github.com/LMhdez/gaslux/actions/runs/45030470016) finished **SUCCESS** at exact candidate HEAD `131f330691b299679a46461616b5e7fa115de882`: 28 real QEMU / Guest Peer tests plus 57 inherited Observer tests, **85/85 PASS**, Ruff, format, compileall and exact pinned #267/#286 source checks. Both the real QEMU disk-FD and local SO_PEERCRED paths ran; the chardev peer was QEMU PID 3293 and had a real host socket descriptor. QEMU was reaped. No guest boot occurred.

[Artifact #14757198793](https://github.com/LMhdez/gaslux/actions/runs/45030470016/artifacts/14757198793) contains the bounded `manifest.json` and local `manifest.sha256`, SHA-256-checked by CI before upload. The artifact ZIP digest was `7f4a4098961b442e95c32637653b9fdb243a7f471b164f20881833c5337ab3b4`; neither the ZIP digest nor the self-hashed manifest provides independent attestation. The manifest explicitly records `guestBooted=false`, `guestObservationsReceived=0`, `guestChannelAuthenticated=false`, `collectorAuthenticated=false`, `replayProtected=false`, `diskWriteAuthorized=false`, `rollbackProven=false`, and `stable=false`.

The real host endpoint is a **negative control**: authenticating its Linux host peer by SO_PEERCRED and the image's QEMU host FD is **not** a guest collector observation. A host process could otherwise impersonate guest origin. Operational installation, replay authorization and Windows recovery remain blocked. Independently Safety-review the new differential before any integration.

## GUEST-COLLECTOR-ORIGIN-01 — minimal Linux test boot (2026-11-22)

This *experimental, deny-only* next lab adds a **real booted Linux kernel**
and a fixed collector inside a private gzip-compressed initramfs. It does not
start Bazzite, Anaconda, Ubiquity, Calamares, Windows, production disks or a
general-purpose guest-agent shell.

The CI runner obtains an Ubuntu APT repository-signed `linux-image-virtual`
kernel and `busybox-static`; the initramfs generator copies only the pinned
runner bytes required for the fixed collector, /init and the virtio-serial
kernel modules. Runtime SHA-256 and installed package versions are recorded
in the untrusted evidence manifest. Those hashes prove repeatable comparison
of local bytes, **not** an external guest trust root.

The original #325/#331 QEMU HOST/FD witnesses observe the same process and
QCOW2 backing. A separate guest serial UART must report an actual Linux
kernel, init execution and collector execution. The fixed collector reads
one bounded non-executable challenge over the existing virtio-serial device
and writes one bounded report containing session UUID, external nonce,
its computed /collector.sh SHA, boot ID and counter 1.

Host validates the exact report schema/nonce/hash/counter and atomically
consumes the challenge in a local SQLite ledger with synchronous FULL. A
new ledger handle must refuse the same nonce on a repeat; tampering with
session, collector hash or claims and disconnect/truncation must also fail.
The ledger is host-controlled: **replayProtectedAgainstCompromisedHost=false**.

The mandatory report distinguishes:
- `guestCollectorExecutedObserved`: actual UART boot marker from QEMU lab;
- `guestMessageReceived`: bounded virtio-serial response received on HOST;
- `hostQemuPeerAuthenticated`: SO_PEERCRED matching the HOST QEMU process;
- `guestOriginIndependentlyAttested=false`: guest-provided claims are not a
  cryptographic proof of execution identity or independent provenance.

Positive lab outcomes, if demonstrated by exact-HEAD QEMU CI, still require
`status=BLOCKED_TRUST_ROOT`, `NOT_INDEPENDENT` and
`guestChannelAuthenticated=false`, `diskWriteAuthorized=false`,
`productionInstallationAuthorized=false`, `rollbackProven=false`,
`stable=false`. The QEMU virtual disk remains read-only and test-owned.

Until a CI success on the precise PR HEAD exists, this section describes
a **candidate experiment, not a proven guest boot**. No independent
Anaconda identity, protected challenge issuer or Windows recovery follows.

### Verified booted guest collector lab (2026-11-22, 14:47 UTC)

[GitHub Actions #45034620331](https://github.com/LMhdez/gaslux/actions/runs/45034620331) **SUCCESS** on implementation HEAD `15167cf7653f7094d83f4fafe3230d1d4d8b6be2`. The disposable QEMU actually booted Ubuntu package kernel `7.0.0-1017-azure` (package `7.0.0-1017.17~24.04.1`), executing test `/init` and a fixed static-BusyBox collector. The collector's UART read of `/proc/version`, guest boot ID claim, computed collector hash, and bounded response on the existing virtio-serial channel were checked against supervisor-owned test artefacts. The host had established the QEMU AF_UNIX peer connection *before* the guest opened its port (the initial ordering caused EOF, correctly refused before this fix).

Runtime SHA-256 from that runner:
- Kernel `1499d4e93269e5607c0aed401f55a6c256d4ca82e91b6b79f4032d0a181f22e5`
- Initramfs `5250738e2d51cb7166ac2fb2aad19f34a79fff439cb282ac0ddf24d001cf8e`
- Fixed collector `d9070b9806c926c0c0943355a146479ff598c1792783d051676a8df4aef4f12e`
- Boot serial digest `7f6630ab106045b31f2f5473b42b02c741cfe236df4f2694cbe9cfeb22b59435`.

The signed Ubuntu APT package installed on the private runner has its original root-protected kernel image in /boot; only a source package-owned kernel is copied to a private mode-0400 RUNNER_TEMP file through a bounded privileged workflow setup, without modifying /boot or touching system disks. The builder then validates the owner/mode, package kernel release/modules and recomputes SHA-256. This package trust is a local CI dependency, **not independent guest provenance attestation**.

The QEMU process and the socket HOST peer both measured PID `7787`; QCOW2 device/inode `66305/9442716` was read-only. The session response matched external nonce, session, reported collector hash and counter 1; the host SQLite ledger rejected reuse after closing and reopening. Negative cases for process seal, wrong FD, spoofed HOST proxy, wrong session/collector hash, interrupted/oversized report, forged authority and counter all passed. [Artifact #14758869232](https://github.com/LMhdez/gaslux/actions/runs/45034620331/artifacts/14758869232) is a runner-generated JSON and local SHA-256 with ZIP digest `e91815c0b96665505ad2f9226173569cc49f831035224999cd075c9084b41b94`: **unsigned and NOT independently attested**.

**Exact witness separation:** `guestCollectorExecutedObserved=true` (lab UART), `guestMessageReceived=true` (bounded channel), `hostQemuPeerAuthenticated=true` (kernel SO_PEERCRED), `labReplayConsumptionVerified=true` (host SQLite). `guestOriginIndependentlyAttested=false`, `guestChannelAuthenticated=false`, `replayProtectedAgainstCompromisedHost=false`, all writers denied, `rollbackProven=false`, `stable=false`. This demonstrates **REAL GUEST BOOT + LAB DELIVERY**, not production guest origin authentication, Anaconda identity, installation, dual boot or Windows recovery. Request independent Safety differential review and preserve Draft status.
