# Guest collector origin laboratory — Linux RAM-only boot

Scope: isolated GitHub-hosted ubuntu-24.04 runner; private 0700 workspace,
temporary 64 MiB sparse regular-file RAW image opened by QEMU with
readonly=on; no installer, Windows, deployment, partitioning, QGA, guest
shell API, network or physical device. NOT_INDEPENDENT / DIAGNOSTIC_ONLY.

Dependency: PR #331 (https://github.com/LMhdez/gaslux/pull/331), which
documents a real stopped QEMU and a QEMU-host SO_PEERCRED socket endpoint.
This branch deliberately does not modify its existing paused-QEMU workflow.
It reuses integrated ProcessSeal, QemuLocalDiskWitness, LocalSessionPins
and LocalTransportWitness; no controller from experimental #259.

## Evidence tiers

1. guestBooted: the test kernel produces a boot UUID on a separate serial
   console, followed by a matching response containing that boot UUID.
2. guestCollectorExecutedObserved: the initramfs /init invokes the test
   collector and a collector-side serial marker is observed. The collector is
   a fixed shell script, not an arbitrary command dispatcher.
3. guestMessageReceived: the host sends a fresh challenge over the
   existing QEMU virtio-serial named port and checks a bounded response,
   expected collector hash, session, transaction, VM test label and sequence.
4. hostQemuPeerAuthenticated: SO_PEERCRED identifies the local HOST QEMU
   process, whose pinned PID/start ticks/executable and file descriptor are
   checked again by integrated witnesses.
5. guestOriginIndependentlyAttested: FALSE. The same runner compiles the
   initramfs, chooses the kernel, owns QEMU and the disk, issues challenges,
   and controls the ledger and the manifest. A hostile host could forge the
   serial stream, the virtio-serial response and the ledger.

## Host/guest separation and source identity

The workflow installs Ubuntu-packaged Linux kernel, static BusyBox, QEMU,
kmod/cpio/zstd and records kernel SHA-256, initramfs SHA-256, collector SHA-256,
kernel package identity and module count. The kernel is from a package repository
used by the runner; the package installation/runner is NOT a remotely
attested independent trust root. A guest boot_id and collector-side SHA-256
check are consistency markers, not an independent measured boot or immutable
collector identity. Guest ports are only for a single challenge and response;
no host-supplied code/commands run inside the guest.

The durable LabNonceLedger writes one-use nonces under SQLite
synchronous=FULL in the private temp directory; a replay after reopening the
ledger is refused. The same runner/root can replace it. It does not authenticate
an external issuer or prevent a compromised HOST from replaying the entire VM.

All reports retain status=BLOCKED_TRUST_ROOT, guestOrigin=NOT_ATTESTED,
guestChannelAuthenticated=false, guestOriginIndependentlyAttested=false,
diskWritesAuthorized=false, productionInstallationAuthorized=false.

## Negative cases

The offline tests cover: A HOST_PROXY_SPOOF, B OLD_NONCE_REPLAY,
C WRONG_VM_SESSION, D COLLECTOR_HASH_MISMATCH, E TRANSPORT_DISCONNECT,
F TRUNCATED_RESPONSE, G FORGED_GUEST_CLAIMS, H WRONG_QEMU_PROCESS,
I WRONG_DISK_FD. HOST process/disk checks also reuse the already integrated
QEMU/FD witness. These test cases prove parser and local-contract refusal,
not independent Guest provenance.

CI uses one QEMU boot in a single job, never concurrently with the paused
QEMU workflow in the same branch. The private disk is checked byte-identical
before/after; evidence is small, hashed and runner-generated, unsigned.
No merge or write authorization should follow CI alone. Request independent
GASLUX-SAFETY review of the exact HEAD and artifact after a successful run.
