# Bazzite ISO45 — future read-only installer inspection: **channel refused**

**Scope:** Experimental Bazzite, UEFI/GPT only. Proposed on a branch stacked over [PR #262](https://github.com/LMhdez/gaslux/pull/262), which depends on [#250](https://github.com/LMhdez/gaslux/pull/250). No changes to Safety [#267](https://github.com/LMhdez/gaslux/pull/267), Observer [#259](https://github.com/LMhdez/gaslux/pull/259), or Observer review [#273](https://github.com/LMhdez/gaslux/pull/273).

## Evidence classes — do not combine

| Claim | Evidence and limit |
| --- | --- |
| Official ISO 45.20261117.1, SHA-256 `6120b6edc2d87e7bdccf8dfddc8b156552cd50b152cb0a9e9dedb37fb947cbe5` and OCI payload `sha256:492f83c738838861464685aed341783c2ea2266c82a9f19f0c867fd301783fd4` | Independently validated in original [ISO readback #44822100590](https://github.com/LMhdez/gaslux/actions/runs/44822100590), **not** an authentication of a new guest channel |
| ISO45 live graphical desktop | Observed via original six hash-bound PNGs; [offline Result B](https://github.com/LMhdez/gaslux/actions/runs/44892949688) |
| Installer invocation documented by upstream | Current upstream `ublue-os/bazzite/installer/system_files/shared/usr/bin/on_gui_login.sh` contains `liveinst &`; [official installation guide](https://docs.bazzite.gg/General/Installation_Guide/install-guide/) describes opening the graphical installer. These sources are **not** signed, per-ISO45 runtime PID/binary/D-Bus evidence |
| Anaconda present/running in **exact ISO45** | **Not observed.** No executable hash, PID, version, bus owner or method inventory authenticated |
| QGA, SSH, vsock, guest agent, authenticated collector transport in exact ISO45 | **Not observed.** Do not infer from Fedora packages, upstream docs or QEMU host monitor |
| GetActions(), real write-set, target disk operations, Atomic install, Windows dual boot | **Not observed; prohibited** |

Neither the serial label `Launch Bazzite Installer` nor the desktop shortcut `Install to Hard Drive` proves a running Anaconda PID or any installation operation. A future instrumented ISO would have **different identity** from the original official ISO and must never inherit its SHA/provenance or Result B.

## Implementation boundary

- `auto_tests/bazzite_iso45_guest_inspection_contract.py` checks **untrusted synthetic proposals only**. It imports the existing collector's read-only method allowlist and the pre-existing GPT lab partition constants; no new collector, shell, transport, QEMU management, or writer.
- `schemas/bazzite_iso45_guest_inspection_contract_v1.schema.json` defines version 1. The Python checks additionally enforce exact host/guest GPT identities, sector geometry, synthetic disk count, individual method response SHA-256 and duration, collector hash consistency, Anaconda process-claim fields, and cross-field invariants.
- The fixture *pretends* Anaconda exists to test structural refusal; its `servicePresent=true`, version, PID and hashes are **synthetic assertions**, not actual process evidence. The CLI exits **2** for structurally valid proposals, prints `REFUSED_NO_AUTHENTICATED_GUEST_COLLECTOR_CHANNEL`, and exits **3** for invalid proposals. It has no success/authorization path.
- `seen_transactions` is an **in-memory test aid**, not a durable anti-replay system or a trusted nonce authority. All JSON values, sha256 fields, matching host/guest inventory, transaction values and self-declared provenance remain untrusted.
- All installation, GPT metadata, partition, ESP, NVRAM, Secure Boot enrollment, guest-control, `GetActions` observation and write-set authorization flags are explicitly false, even with fully shaped input. No 'approved' boolean or runner-generated HMAC is interpreted as independent approval.
- Existing `auto_tests/bazzite_anaconda_readonly_capture.py`, `auto_tests/bazzite_live_channel_boundary.py` and `auto_tests/bazzite_anaconda_write_set_gate.py` are **unchanged**. The current collector may read `GetActions`, `GetDevices`, `GetDisks`, `GetMountPoints`, `GetBootDevice`, and bounded `GetDeviceData`/`GetFormatData`; this proposal calls **none** of them.
- CI triggers only on the dedicated contract branch/new PR changes to new files, and does not download any ISO, run QEMU, or enter the guest.

## Requirements for a future, separately reviewed v2 — **not implemented**

1. **Independent origin:** trusted external authority with keys or attestation root outside the GitHub runner and guest, verifying the *exact running* ISO + signed OCI payload and tying host QEMU pid/start ticks/argv hash, VM instance, firmware variables, transaction and guest process identity into a single authenticated claim. A nonce, self-signed ZIP/JSON, runner-generated HMAC or QEMU monitor is insufficient.
2. **Single-use state:** durable, authoritative transaction ledger (atomic consume, expiration/clock checks, immutable event sequence, crash/restart persistence), with sender binding and stale/swap/replay prevention. The current schema's `challenge` and `sequence` do **not** provide this.
3. **Disk reconciliation:** independently measured GPT primary/backup CRC, protective MBR, disk serial, size, logical sector size, GUID, PARTUUID, offsets and lengths; comparison against guest `lsblk` and explicit proof that exactly one disposable QCOW2 is connected, no Windows disk and no foreign NVRAM. The two JSON inventories are *not* independent measurements.
4. **Collector identity:** cryptographically rooted approval of exact script bytes/sha, delivery provenance and guest execution target; existing Anaconda Storage D-Bus unique owner, PID + process start time + executable SHA, package identity and version; recheck owner/PID after bounded observation. A same-run hash by the runner is not approval.
5. **Restricted operations:** prove the exact D-Bus signatures from the live runtime; allow only preexisting `READS` and `DETAIL_READS` (data-only), bounded outputs/timeouts, no service activation, no arbitrary executable or command channel, no SSH, no VNC input, no automatic UI navigation. A `GetActions` response is **not** a write grant.
6. **Independent reviews:** explicit signed/traceable, scoped Safety #267 and Observer #259 decisions for this precise experiment. Observer #273's one-shot experiment is unrelated to an ISO45 guest collector. Review must cover trust roots, privilege separation and TOCTOU at the exact host↔guest boundary.
7. **Separate v2 delivery:** only after the above proofs, design a *different* authenticated, least-privilege, read-only transport; no mutation of the signed original ISO. The verifier and runtime collector remain separate. Any install/write-set gate must still deny native installation, GPT/ESP/BCD/WinRE updates, NVRAM writes and Atomic deployments pending wholly separate write/rollback/boot evidence.

**Current absolute result:** `REFUSED_NO_AUTHENTICATED_GUEST_COLLECTOR_CHANNEL`. No demonstration of Anaconda service, `GetActions`, real Blivet write-set, installed Linux boot, Windows boot, restoration or rollback.
