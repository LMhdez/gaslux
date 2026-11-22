# Q4OS-RUNLAB-BOUNDARY-01 — read-only process, FD and QMP witness

**Status (22 Nov 2026 UTC): experimental / disposable runner / DENY-ONLY / not a native installation.**
Scope: stacked on [draft PR #318](https://github.com/LMhdez/gaslux/pull/318) at
`f6a446b2c3e4ec05cefdc2d084a3024464ca912e`. Branch:
`test/q4os-runlab-readonly-boundary-20261122`.
The historical Windows/Calamares/Observer authorization boundaries are not changed.

## Rationale and exact differences

The [prior FD laboratory](Q4OS_QEMU_FD_COMPATIBILITY.md) used a genuine,
paused QEMU and the real PR `_qemu_args()`, but reimplemented several
read-only witnesses. This follow-up retains **the same single test launcher**,
only adds a `pr_shared` scenario, and defers `run_lab()` execution entirely.

| Boundary | Original `pr_argv` QEMU lab | Operational `run_lab` | New `pr_shared` evidence |
| --- | --- | --- | --- |
| Process launch | Existing lab `subprocess.Popen` | Gated `Popen`, disabled by `QEMU_FD_BACKING_VERIFIED=false` | **Same existing lab launcher**; no operational alternative |
| QEMU arguments | Actual supervisor `_qemu_args` with `-S`/1 vCPU/128 MiB | `_qemu_args` with operational CPU/RAM, no pause | Same real `_qemu_args` with bounded disposable test modifications |
| FD inheritance | `pass_fds` with lab-pinned inode/fstat | `_owned_file`, `_pin_file`, private dir FD, `pass_fds` | Same lab-pinned files, plus process identity checks from supervisor; full operational disk preflight is **not proven** |
| QCOW2 | Own 64 MiB, no backing | Owned regular-file checks; does not itself prove a `qemu-img` backing-chain check | Exact 64 MiB / 65,536 B clusters / no backing enforced **before spawn**; wrong geometry and foreign backing refused |
| PID and birth | Lab `birth`/`assert_pidfd` | `_birth_identity`/`_pidfd_target`/`_witness` and owned-child registry when gate open | Same actual `_birth_identity`, `_pidfd_target`, `_witness` on real direct QEMU child, plus independent lab kernel measurements |
| QMP peer | Raw UNIX socket / SO_PEERCRED | Connect-only `Qmp`, `_peer`, issued `_BoundQmpSession` and gated full QMP negotiation | Real connect-only `Qmp` + supervisor `_peer` and `_socket_identity` on the **same socket**; no operational session issued |
| QMP commands | Explicit read-only allowlist | `send-key` possible only behind authenticated operational session (currently blocked) | Only `qmp_capabilities`, `query-status`, `query-block`, `query-fdsets` via isolated diagnostic parser |
| Cleanup | Lab pidfd signal and `wait` | Supervisor `_cleanup` rechecks pidfd before TERM/KILL, post-Safety correction | Real supervisor `_cleanup` on owned direct QEMU child; lab independently counts remaining own process-group members |
| Evidence | Bounded forensic JSON, ephemeral | Operational report/transaction not authorized | Same bounded JSON, exact run SHA and hashes; **not an authenticated installation ledger** |

The `ProcessSeal` and local HOST/FD readout in `dev/auto_tests/installer_observer/host_fd_boundary.py` remain separately implemented in `dev`. This historical #318 stack does **not** include that module; importing or duplicating it would create ambiguous ownership/authority. Its later integration requires the Integrator to compose the validated `dev` contracts with #318, preserving the Observer's HOST/FD and Guest Peer boundaries. The experiment does not claim a ProcessSeal or a Guest-origin witness.

## Trust, authorization and negative checks

The exact new branch creates its own `0700` private runner directory and `0600` files:
QEMU 8.2.2, q35/TCG, `-S`, 1 vCPU, 128 MiB, copied OVMF CODE/VARS,
64 MiB sparse QCOW2, synthetic nonbootable ISO plus answer ISO.
There is no Windows guest, Q4OS guest or input automation.

1. The unmodified *public* `run_lab()` is called three times with the gate false
   (without injection; with `popen_factory`; with `pidfd_factory`). All three must
   deny before any spawn, QMP, log, media mutation or factory side effect.
2. A genuine QEMU child is created by the existing diagnostic-only launcher.
   The real supervisor verifies direct-child birth ticks, kernel pidfd, executable
   and QMP `SO_PEERCRED`, on each of four read-only QMP commands. The live
   guest must stay `running=false`. An independent inode walk of
   `/proc/<pid>/fd` must match all five pinned resources.
3. `_cleanup(QEMU, pidfd_foreign)` must fail closed while QEMU and a separate
   same-UID Python child are still alive. No foreign process is signalled by
   that unauthorized cleanup attempt. The Python child is then terminated
   separately through its **own** valid pidfd during fixture teardown.
4. A separate Python UNIX socket listener under the same UID is offered as
   a false QMP peer. Supervisor `_peer` must refuse; server transcript must
   contain **zero bytes** (no QMP command). An existing socket subsequently
   replaced with a symlink must be refused before any further command.
5. A pathname substitution after pinning the original QCOW2 must not change
   its inode or SHA-256; the foreign pathname replacement is not touched by
   QEMU. The original QCOW2 is found via the FD and a private retained name.
6. Preflight refuses a wrong-size QCOW2, a foreign backing dependency and
   wrong FD/resource. A genuinely closed FD is refused by QEMU; a missing
   QMP endpoint and a synthetic spawn failure deny. Tests from the earlier
   offline suite cover unsupported greeting/capabilities/version; these are
   **not** represented as an observed incompatible real QEMU release.
7. The actual supervisor `_cleanup` must reap the direct QEMU child. The lab
   additionally checks that its known process group has no survivors.
   It cannot claim whole-host process-tree cleanup or Windows recovery.

The read-only label applies to QMP commands and diagnostic intent:
QEMU still opens its **own** private pflash VARS and QCOW2 with writable FDs.
Hashes are checked after the guest remains paused, and unrelated host devices,
real NTFS, ESP/WinRE/BCD, partition tables and NVRAM are never touched.
No command named `send-key`, `cont`, `quit`, guest agent command or Calamares
command is transmitted; `_BoundQmpSession` is deliberately never minted.

## Evidence: first GREEN read-only shared-supervisor run

[QEMU Action #45031819453](https://github.com/LMhdez/gaslux/actions/runs/45031819453)
on exact `1c9421e184aaf885e69f6b4937aaa4bb23c28b3c`: **SUCCESS**.
QEMU version `8.2.2` (Ubuntu package `1:8.2.2+ds-0ubuntu1.18`).
Only `pr_shared` plus negative cases ran; the four previous positive
compatibility cases were **not repeated**. The real QMP returned
`running=false`, `query-block` found six virtual devices, and the four
read-only QMP commands each revalidated the actual supervisor witnesses.
Foreign same-UID QMP peer refused, with zero command bytes. Public `run_lab`
three deny cases passed. Direct own QEMU cleanup reaped its child; no remaining
members of that process group were observed. All negative cases returned
verified refusals. The current candidate should be accepted only with new
GREEN Actions/forensic evidence on its **final** HEAD.

### SHA-256 and geometry (disposable `pr_shared`)

| Resource | Initial length | SHA-256 of **owned original** before/after |
| --- | ---: | --- |
| OVMF CODE | 3,653,632 bytes | `ad23261d43116abc3747d59a7837fbf578c9586a8993f4eeba064cd07eccb083` |
| OVMF VARS | 540,672 bytes | `5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e` |
| QCOW2 (64 MiB virtual, 65,536 B clusters, no backing) | 196,616 bytes initially | `1b7af784841125887e688254229e282829e17245d0e47fe7280da9b68a30d9e1` |
| Synthetic nonbootable ISO | 4,125 bytes | `1fd4ee3e633f2596da24ec60cd7f69aa834bf8083c155a4ce6aad07310da6e49` |
| Synthetic nonbootable answer ISO | 548 bytes | `093832a9ae1a6d4ba59a51d1cf1b0a0d1f6a33e8d8ab44f86c02cc0d7fcb8341` |

**Important:** the pathname `disk.qcow2` is intentionally replaced with a
different synthetic sentinel during the rename adversary. Its *postHash by
pathname* is therefore different. The **original owned QCOW2** is retained
and verified by its pinned FD/inode and SHA-256. Do not collapse these
two distinct identities or claim that the replacement has the original hash.

## Specific blocker for first genuine Q4OS live boot

`docs/Q4OS_BACKEND.md` records the native ISO `q4os-6.10-x64.r2.iso`,
upstream-published SHA-256
`1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d`
and an earlier real ISO inspection. This historical upstream checksum is
**not** an authenticated current Gaslux signed-catalogue entry or a new ISO
verification in this intervention. Before a live boot in a disposable VM:

- Revalidate the exact **native** ISO bytes, origin, SHA-256 and signature/
  signed catalogue policy for the chosen fixed version.
- Authenticate the ISO and the QEMU process/FD disk mapping to one VM,
  select compatible OVMF/SeaBIOS and owned QCOW2, and check boot device order.
- Supply Guest-origin evidence bound to the observed host VM/process; only
  kernel + userspace witnesses count as live boot, not QMP/greeting/GRUB alone.
  Reuse existing HOST/FD and Guest Peer contracts after safe branch integration.
- Obtain favourable independent Safety review of this differential.
- Keep Calamares, `installEFIFallback=true`, installer partitioning, Windows
  Boot Manager, ESP/BCD/WinRE, real Windows boot, native install and rollback
  entirely outside this step.

## Release and risk gates

`QEMU_FD_BACKING_VERIFIED=false`
`productionStorageWritesAuthorized=false`
`q4osNativeInstallationVerified=false`
`sameDiskDualBootVerified=false`
`windowsInPlaceRollbackProven=false`
`releaseEligible=false`
`stable=false`

This branch is DENY-ONLY and must not be merged without a reproducible
independent Safety differential review. No experimental process identity
or QMP readout is authority to arm production installation, send-key
or a storage writer.

Generated-by: GPT-6; GPL-3.0; human and independent technical review required.
