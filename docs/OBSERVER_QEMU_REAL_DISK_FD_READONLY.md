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
