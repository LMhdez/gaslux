# GASLUX-OBSERVER — GUEST-COLLECTOR-ORIGIN-01 (experimental test, NOT_ATTESTED)

## Reconciled references (2026-11-22 UTC)

- `dev` initially `8e68a475d6397ba8fef2e0f9f83758545e202a5f`.
- [#319](https://github.com/LMhdez/gaslux/pull/319) integrated HOST/FD and SO_PEERCRED.
- [#325](https://github.com/LMhdez/gaslux/pull/325) merged actual paused QEMU with read-only RAW/QCOW2 FD, QMP and canonical #267/#286 verifiers.
- [#331](https://github.com/LMhdez/gaslux/pull/331) draft at `412cca6e28d5268b10b30c3da3fd8b6e24d31a84`: a QEMU-owned `virtio-serial` HOST socket demonstrated that SO_PEERCRED identifies **QEMU**, not a guest collector. [Action #45030813901](https://github.com/LMhdez/gaslux/actions/runs/45030813901), SUCCESS 85/85; independent Safety verdict on #331 still pending at task start.
- Historical #294 closed without merge, #321 superseded; controller #259 remains experimental and is not imported.

## Actual guest boot lab — scope / source identity

The test, **not** the Observer runtime, installs a test-only kernel from the signed Ubuntu apt repository via `linux-image-virtual` and a static BusyBox via `busybox-static`. It records dpkg package/version, exact SHA-256 of the installed Linux kernel, static BusyBox, module bytes, collector source and constructed initramfs. This establishes a reproducible **runner-measured input inventory**, **not** an externally pinned upstream ISO, kernel/collector trust root or guest attestation.

The test builds a private initramfs carrying a short `/init` busybox shell collector; it loads only the host-packaged virtio-console modules and mounts tmpfs-like kernel filesystems. It does not install Linux to the disk image or modify its GPT. The QEMU system launched by the existing test supervisor uses the exact private read-only 64 MiB QCOW2 GPT image verified by pinned #267/#286, a host AF_UNIX QMP socket and a virtio-serial chardev. It begins paused, so the existing QEMU pidfd/FD and QMP witness executes before the test supervisor alone sends QMP `cont`. This QMP control is **test-only**; the production Observer gains no QMP controller, guest shell, SSH, QGA, Anaconda or installer commands.

The guest boot witness is the guest's serial console showing `GASLUX_GUEST_COLLECTOR_EXECUTED`, separate from the QEMU SO_PEERCRED host peer. The collector reads a bounded host-generated session/challenge over `/dev/vport0p1`, returns protocol version, session, nonce, source SHA claim, session counter and guest boot UUID, and emits `GASLUX_GUEST_RESPONSE_EMITTED` to the guest console. Host receipts are parsed strictly (ASCII, max 512 bytes, one newline, exact 6 fields), matched against the independent host-generated challenge and consumed under a SQLite `BEGIN IMMEDIATE` / `synchronous=FULL` single-use ledger stored in a private runner directory. The ledger rejects old nonce/session on process restart. A HOST/controller compromise can alter the ledger, challenge and serial evidence, so `replayProtectedAgainstHostCompromise=false` and `guestOriginIndependentlyAttested=false`.

## Explicitly separate the observation levels

- `guestBootObserved=true` only when the disposable VM boots far enough for an observed serial marker.
- `guestCollectorExecutedObserved=true` only when collector serial markers and the expected frame arrive together in the test. This is an observed guest execution event **under the laboratory configuration**, not remotely attested execution.
- `guestMessageReceived=true` only when real QEMU guest-port bytes pass the strict parser and host ledger.
- `hostQemuPeerAuthenticated=true` means Linux kernel SO_PEERCRED confirms QEMU is the peer to the HOST socket; this is never an identity of a guest process.
- `guestOriginIndependentlyAttested=false`, `guestChannelAuthenticated=false` always: there is no independent protected guest trust anchor, no key invisible to untrusted guest/host, no TPM/TDX/SEV/SNP attestation, no signed verified guest collector delivery. A host proxy can forge the same frame and serial text.
- `diskWriteAuthorized=false`, `productionInstallationAuthorized=false`, `inputAuthorized=false`, `rollbackProven=false`, `stable=false`. All reports `status=BLOCKED_TRUST_ROOT`, `classification=NOT_ATTESTED`.

## Safety, adversaries and reproducibility

New tests cover same-lab and persisted replay, wrong VM session, collector hash mismatch, truncated/oversized response, forged guest claims, wrong host process/selected disk through inherited QEMU/FD tests, host proxy's matching bytes, disconnect and unissued nonce. The test's private SQLite ledger is **not a production ledger**; the guest's response digest is an unauthenticated field. A matching result is neither permission to install nor proof of end-to-end guest authenticity. The workflow checks exact #267/#286 repo SHAs, hashes of integrated HOST/FD modules and inherited regression tests. QEMU is restricted to GitHub-hosted disposable runners, no network and readonly attached disk. Test tools are installed in the ephemeral runner; no physical block devices, Windows, ESP, BCD, WinRE, NVRAM or dual boot are touched.

Published artefacts contain only bounded JSON and hash from the runner, not disk images, initramfs, kernel, SQLite ledger, secrets or host guest console logs. The digest of the artifact is not an external signature. A real boot of the test initramfs is **not** a Gaslux Linux installation, dual boot, update test, rollback test or release-ready configuration.

## Next independent root

An independently provisioned and verified guest image + collector must be bound to immutable VM/backend FD identity and boot state, accompanied by protected host-to-guest transport with replay-resistant external ledger and separate Safety-approved policy. The present lab only verifies functional transport and bounded negative trust semantics. No state-machine controller #259 is needed or introduced.
