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

## Exact observed execution — 22 November 2026, 15:13 UTC

[GitHub Action #45036971429](https://github.com/LMhdez/gaslux/actions/runs/45036971429), **SUCCESS** at code HEAD `3916847d3e594e88d5e0398379efd6c386da6ca8`. The job passed the separate negative protocol suite, the **real booted guest collector** and inherited QEMU/Observer regression suite, plus Ruff check/format and Python compileall. It verified the #267/#286 fixed SHAs, the actual inherited HOST/FD source blobs and the test-runner isolation conditions.

The operational manifest reported actual Linux guest boot and collector execution observed on a separate serial-console witness, guest-port response to a fresh host nonce, and successful durable in-run challenge consumption. The QEMU PID was `7762`; host Linux SO_PEERCRED on the chardev reported that same QEMU PID (not a Guest PID); the host read-only QCOW2 inode was `2645815`. The image/backing identity was checked with the existing pinned canonical code. The disposable guest used apt package `linux-image-6.8.0-151-generic` version `6.8.0-151.151`, host-measured SHA-256 `fc6f2a37b8dafff46ac1ff66361503b1f6eeab0e2df680447299235b7d6453be`. The guest initramfs SHA-256 was `8dc98ce81d50c3a34bdc3ef0d9c2a9cd04137c3c64c487b0d2e4f545bf3e18a9` and collector source SHA-256 `79ffdfbe1fdbdf8fa466ecc2a63ee165bd9375c46a80fc6cf64c79521ca14ee6`, measured during this runner execution rather than independently authenticated from an external release catalog. No known-value hash was invented.

[Artifact #14760345793](https://github.com/LMhdez/gaslux/actions/runs/45036971429/artifacts/14760345793) is a **runner-only, unsigned** JSON manifest plus SHA-256 file. ZIP SHA-256 `65ae2bbca9fd61dbcd5d3db900322109b1c301518baa4f18b513edd72ac2495c`. This digest is not independent attestation. The manifest explicitly records:
- `guestBootObserved=true`; `guestCollectorExecutedObserved=true`; `guestMessageReceived=true`; `hostQemuPeerAuthenticated=true`;
- `labLedgerSingleUseVerified=true` and `replayProtectedAgainstHostCompromise=false`;
- `guestOriginIndependentlyAttested=false`, `guestChannelAuthenticated=false`, `diskWriteAuthorized=false`, `productionInstallationAuthorized=false`, `rollbackProven=false`, `stable=false`;
- `status=BLOCKED_TRUST_ROOT`; `classification=NOT_ATTESTED`.

The real QEMU guest was **not** Linux installed onto QCOW2; it ran a test-only initramfs directly from a signed-apt kernel. Its virtual QCOW2 was attached read-only. No Anaconda, Bazzite, Windows, backend writes, QGA/SSH shell, physical disks or bootloader operations occurred. This is **real guest boot + functional read-only guest-to-host transport** in a disposable CI VM, **not** guest-independent provenance, installed-Linux boot, dual boot, Windows recovery, or stability.
