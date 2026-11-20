# Installer Observer — experimental read-only contract

## Scope and status

This component audits installer UI evidence without running an installer, modifying
disks or modifying Windows. It continues the Q4OS Calamares investigation of
[#258](https://github.com/LMhdez/gaslux/pull/258). It is **not** a production
installer, a dual-boot proof or a generic input automation framework.

The original Q4OS map and four artifacts are preserved. The reviewed Q4OS image
is 6.10 r2, 1,851,392,000 bytes, SHA-256
`1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d`.
The upstream ISO signature remains **unverified**. Do not infer authenticity
beyond the pinned local laboratory hash.

## Implemented architecture and public interfaces

- `models.py`: immutable distribution, ISO, installer, screen, transition and
  observation records. The action enumeration contains no arbitrary shell command.
- `schema.py`: validates the bundled JSON schema, checks ISO identity, enforces
  control bounds and matches the reviewed canonical map digest.
- `evidence.py`: bounded JSON / file reads, duplicate-property rejection,
  non-traversing paths, symlink / reparse-point / hardlink checks, SHA-256 and
  self-consistent report envelopes. An envelope hash detects accidental or
  unsanctioned modification; it is **not** a cryptographic signature.
- `screenshot.py`, `locators.py`: complete PNG parsing and dimensional checks,
  pixel ROI hashes, unique control resolution; structured IDs and accessibility
  capabilities are never invented.
- `state_machine.py`: `LabAuthority`, `Frame`, `LabTransport`,
  `Grant`, `SafetyPolicy`, `StateMachine.step`. The policy permits only a
  single reviewed `Next` transition with verified source pixels, a unique
  target and proven preconditions. Any error halts the state machine; no retry.
- `replay.py`, `q4os.py`: offline interpretation of four independent original
  sessions; no input transport is instantiated.
- `transport_vnc.py`: `RfbReader` retrieves a complete RAW framebuffer over
  loopback RFB 3.8 with explicit deadline and no input encoder;
  `ReadOnlyVncTransport` checks a trusted `LabAttestor` before and after
  capture, then returns deliberately unproven scale, locator and guest
  preconditions. `click_if_current` unconditionally refuses.

A `LabTransport` exposes `capture(deadline) -> Frame` and
`click_if_current(run_id, png_sha256, point, deadline) -> None`. The
latter contract calls for **atomic** verification of the current VM,
framebuffer and approved click under the same transport-controlled critical
section. A separate VNC screenshot followed by a pointer event cannot provide
that guarantee: the guest can change frames in between. RFB has no
compare-and-click primitive. The provided adapter **never sends** pointer,
keyboard or guest-shell commands. A real click-capable QEMU transport requires
new, independently verified atomicity and attachment/VM attestation; it must
not simply weaken `LabTransport` or set a Boolean flag.

The attestor protocol is injectable for tests; **no production QEMU
attestor** is implemented. For a future implementation, independently prove
the QEMU PID / isolated process, machine configuration, exact COW overlay,
backing and all attached block devices, absence of physical disks, run and
snapshot identity, media hash, displayed scale and guest provenance. A Python
object supplied by the caller or a JSON value is not such proof.

## Execution and safety modes

1. **Inspect**: local JSON map and reviewed digest; no network or VM.
2. **Historical replay**: original PNGs, manifest reports and SHA-256 validated
   offline, including the two Summary sessions.
3. **Read-only RFB observation**: limited localhost unauthenticated RFB 3.8
   RAW capture; requires independently implemented trusted attestation to be
   useful beyond mocks, never produces an executable click. Authenticated VNC
   and other encodings are refused. No live Q4OS guest validation is claimed.
4. **Live navigation/input**: **blocked**. The exact Q4OS display scale is
   unknown (`null`), VNC widget identifiers are unproven, and atomic input
   is unavailable. The STOP boundary is `calamares-summary`. Install is
   never authorized.

No JSON can specify a process, command, file operation, disk path or executable
locator strategy. An unknown action, multiple candidates, altered pixel,
unexpected screen, changed snapshot, timeout or postcondition failure is a
terminal refusal. Distinguish a simulated transport click in unit tests from
an executed VM click. After input failures, no automatic recovery retry is
permitted, because an error may have occurred after the guest received input.

## CLI (from repository root)

Install the validation dependencies in an isolated development environment,
then run:

```bash
python -m pip install 'pytest>=9,<10' 'pillow>=11,<13' 'jsonschema>=4,<5' 'ruff>=0.8,<1'
python -m auto_tests.installer_observer.cli inspect
python -m auto_tests.installer_observer.cli replay > /tmp/q4os-observer-replay.json
python -m auto_tests.installer_observer.cli verify-report /tmp/q4os-observer-replay.json
# If an independently authenticated local copy of the exact ISO is available:
python -m auto_tests.installer_observer.cli verify-iso /path/to/q4os-6.10-x64.r2.iso
```

The `verify-iso` command requires the exact size and hash, and does not
download files or verify the upstream signing key. Use `--map`,
`--manifest` and `--originals` with the standard reviewed paths only in
a controlled laboratory; a substituted map is rejected by its digest.

## Q4OS proof and historical boundaries

The nine original states, eight transitions and two independent replicas are
retained. Two additional states are Users with synthetic fields and Summary;
two more transitions are historical observations only. Evidence is kept per
replica: original runs and Summary runs cannot be spliced into an invented
continuous guest session.

The Summary transition timings are **3279 ms** and **3328 ms**, from the
original experiments; they are not performance SLAs or measurements of this
adapter. Historical frames: **40** across four artifacts; transition records:
**36**. No proof of click Install, partition writing, Linux installation,
first Linux boot, Windows dual boot, updates or rollback exists here.

## Running CI and interpreting failures

```bash
python -m compileall -q auto_tests/installer_observer auto_tests/tests/test_installer_observer.py
python -m ruff check --config auto_tests/pyproject.toml auto_tests/installer_observer/transport_vnc.py auto_tests/tests/test_installer_observer.py
python -m ruff format --check --config auto_tests/pyproject.toml auto_tests/installer_observer/transport_vnc.py auto_tests/tests/test_installer_observer.py
python -m pytest -q auto_tests/tests/test_installer_observer.py auto_tests/tests/test_q4os_ui_map_contract.py auto_tests/tests/test_q4os_summary_gate.py auto_tests/tests/test_q4os_pair_verify.py auto_tests/tests/test_q4os_native_preflight.py
```

The Linux workflow `.github/workflows/installer-observer-contracts.yml`
also validates the source schemas, runs CLI replay, independently verifies
the report and checks exact counts. Symlink and hardlink tests run on Linux
rather than being dismissed as missing Windows privileges.

A refusal names its failed gate. Diagnose evidence hashes and manifest index
first; then screen dimensions, known control pixels, authority, snapshot,
scale and timeout. Never silence a failing test or regenerate expected hashes
to match altered input. Retain original artifacts and record a new reviewed
laboratory run if the UI truly changes. A green mock suite is evidence of
software contracts **only**, not of live VNC operation or dual boot.

## Adding another backend or UI map

Implement a separate fixed `Profile` in trusted Python code with a reviewed,
versioned schema, pinned ISO size / SHA-256, native installer identity,
canonical map hash, state recognizers, unique controls and minimum proven
pre/postconditions. Add original immutable PNGs and per-replica manifest
hashes. Keep a non-destructive STOP boundary and refuse all unverified steps.
Supply real Qt or AT-SPI identifiers **only** with attributable traces from
the same exact build and session. Introduce adversarial fixtures before any
live input, and require review before promoting an action. Never set the
Q4OS null display scale to a guessed value just to enable navigation.

There are **no verified Observer adapters** for Mint, Zorin, CachyOS,
Pop!_OS or Bazzite. No stable distribution catalog, Windows code, bootloader,
ESP, BCD, WinRE or partition logic has been changed.

GPL-3.0; human review required under `AI_POLICY.md`.

## QEMU identity witness and disposable laboratory (20 November 2026)

The existing observer motor, RFB reader, state machine, reviewed Q4OS map,
historical replays and immutable original evidence are unchanged. Two new
modules are deliberately restricted to Linux QEMU **observation**:

- `lab_identity.py` seals the QEMU executable inode/device, actual
  `/proc/<pid>/stat` start ticks, process UID and complete command-line
  digest; it pins exact ISO and QCOW2 inode/dev identities, checks the ISO's
  full SHA-256 and length, and rechecks metadata on each observation. It
  independently inspects the running QEMU process's open file descriptors,
  refusing attached block-special devices and missing sealed media. QMP is
  reached through a private Unix socket and the *kernel-provided* peer
  PID/UID (`SO_PEERCRED`) must match the sealed QEMU process. Only fixed,
  read-only QMP queries (`query-block`, `query-vnc`, `query-status`)
  and capability negotiation are emitted. Exactly one read-only raw ISO and
  one writable, non-backed QCOW2 must be present. QMP must corroborate the
  unique internal snapshot name and an empty VNC client list.
- `lab_probe.py` constructs its **own** scratch ISO and fresh QCOW2 for
  each of two separate QEMU processes. It does not accept a disk pathname,
  executable, ISO download URL, QMP command or guest action from parameters
  or JSON. It refuses root execution, boots only the synthetic test media
  with no network, no monitor and no serial input, reads RAW loopback VNC
  frames, independently validates host/QMP identity, writes SHA-256 evidence
  and destroys its temporary VM resources. The test does not run Calamares
  and it sends **zero** guest actions.
- `.github/workflows/installer-observer-lab.yml` is the separate
  least-privilege, push/dispatch QEMU witness. Its evidence archive is
  `observer-qemu-synthetic-readonly`. Unlike pytest mocks this workflow
  attempts actual QEMU process, socket, disk and frame observations; the
  Actions job and emitted `manifest.json` are required to determine
  whether these attempts succeeded.

For local reproduction on an isolated, non-root Linux VM with `qemu-img`,
`qemu-system-x86_64` and Pillow available:

```bash
export RUNNER_TEMP="$(mktemp -d)"
python -m auto_tests.installer_observer.lab_probe
# Inspect $RUNNER_TEMP/observer-qemu-lab/manifest.json and the frame PNGs.
```

The **independent seal is not a cryptographic VM launch authorization**:
a privileged host or an adversary with the same user identity can replace
the controller, connect to the loopback VNC service or manipulate QEMU
between checks. A QMP query confirming no VNC clients does not establish
exclusive future input ownership; QMP image reporting and procfs file
descriptors do not establish atomic framebuffer/input behavior. The ISO
hash is a local pin, **not** a verified upstream signature; an existing
QCOW2 whose contents were copied from Windows cannot be disproved solely
by identifying its file type. The disposable provenance in this experiment
derives from the fixed in-process creation of new scratch media. Do not
substitute caller-provided VM images.

`LabAuthority` and the read-only transport are **not** upgraded to an
input-capable grant. In particular, `ReadOnlyVncTransport.click_if_current`
still always refuses, and Q4OS's unmeasured display scale, inaccessible Qt
widget IDs, screen ambiguity and `installEFIFallback=true` remain hard
blockers. Neither serialising QMP calls nor matching framebuffer hashes
eliminates the time-of-check/time-of-use race with guest changes or external
input. No physical disk, Windows image, Calamares Install, Apply, NVRAM,
ESP, bootloader, partition write or dual-boot action is authorized here.

The adversarial tests exercise mutated QMP block inventory, media format,
read-only flag, backing chain, snapshot, VNC client/endpoint, process
identity, ISO mismatch, device paths and QMP command allow-list. Their
fixtures are **not** a live process takeover, real hot-plug, proven
exclusive input or a completed Q4OS Summary journey. Treat QEMU Actions
evidence, mock contracts and historical Q4OS replay as distinct categories
in every report.

### Proven QEMU read-only experiments, 20 November 2026

- [Actions #44698376417](https://github.com/LMhdez/gaslux/actions/runs/44698376417)
  passed with **two actual QEMU processes**, separate generated scratch
  directories and snapshots, observed 720×400 VNC RAW frames and corroborated
  QMP/process/file identities. The two runs happened to produce the same
  framebuffer hash; equality is not an acceptance requirement.
  [Evidence ZIP](https://api.github.com/repos/LMhdez/gaslux/actions/artifacts/14611258724/zip)
  (retention seven days).
- [Actions #44698826308](https://github.com/LMhdez/gaslux/actions/runs/44698826308)
  passed the same two-process observation **plus six deliberate identity-drift
  refusals per process**: changed process start ticks, wrong snapshot, changed
  QCOW2 inode, expired deadline, unavailable QMP socket and mutated synthetic
  ISO. These are **12 real-QEMU refusal observations**, not 12 attempted
  guest clicks and not proofs of physical device hot-plug exclusion or external
  VNC-input atomicity.
- The QMP contracts and original offline replay ran separately under
  [Actions #44698833041](https://github.com/LMhdez/gaslux/actions/runs/44698833041)
  and [#44698826371](https://github.com/LMhdez/gaslux/actions/runs/44698826371),
  both successful at the drift-test commit. A genuine Q4OS ISO boot and
  Calamares navigation remain **NOT EXECUTED** in this probe.

A subprocess name, PID, QMP JSON reply, VNC port or snapshot label **alone**
is never treated as sufficient authority; the attestation deliberately
requires independent kernel observations. This does not change the non-atomic
RFB input boundary: until secure input exclusivity and a measured Q4OS
locator/scale can be demonstrated, **no click is authorized**.

### Second live VNC client — negative experiment (20 November 2026)

[Actions #44699875258](https://github.com/LMhdez/gaslux/actions/runs/44699875258)
passed an extended two-VM lab: in **each separate real QEMU process**
the controller observed a valid frame, a second local RFB 3.8
spectator established a complete **shared** VNC handshake without sending
pointer or keyboard messages, and a simultaneous Observer capture was
**refused** while that second client was present. The second socket was
closed and QMP identity verification succeeded again. The test also
preserved the six earlier drift refusals per process, for **14/14
real-QEMU negative checks** and **zero guest input** across both runs.
Unlike the synthetic QMP-report fixture, this test observes an actual
additional VNC connection in a running QEMU process.

This result demonstrates only a fail-closed check **at that instant**:
the VNC service still permits another client to connect later, and RFB
does not provide atomic check-and-click. The transport therefore remains
read-only. No verified Q4OS ISO was booted; there is no automatic journey
to Summary and no action against disk partitions, firmware or Windows.


### Authenticated QEMU input-surface audit and cooperative lease (20 November 2026)

The observer now includes `auto_tests/installer_observer/qemu_surface.py`.
The probe cross-checks the actual Linux `/proc/<pid>/cmdline` bytes
against the command recorded before spawning QEMU and the existing
independent process seal. An exact allowlist rejects unexpected or
modified launch arguments. The tested lab uses `-no-user-config`,
`-nodefaults`, `-monitor none`, `-serial none`, `-display none`,
`-net none`, TCG, and no SPICE option. Its QMP endpoint is a Unix
socket under a private temporary directory, verified through peer
credentials by the existing attestor. Storage identity still requires
the independent QMP/procfs checks.

**This audit DOES NOT authorize input.** The RFB listener remains
unauthenticated TCP loopback `127.0.0.1:5900`. Another local client
completed an RFB shared session in the existing live negative experiment.
The QMP Unix socket is accessible to a process with the same UID.
Neither a `flock` controller lease nor a sealed process identity
prevents these independent emitters. Moreover, there is no atomic
compare-framebuffer-and-input primitive, and guest-side visual
control/scale proofs are incomplete. Even a fabricated blocker-free
`InputSurface` refuses authorization unless a separately proven
atomic primitive is implemented.

The new live QEMU probe tests a second `ControllerLease` holder,
the exact QEMU launch-channel contract, and the input-authority
refusal, all *before any guest input*. Its evidence manifest now records
`input_surface`, `input_authority_refused` and
`cooperative_controller_contention_refused`.

- [Real QEMU run #44709056193](https://github.com/LMhdez/gaslux/actions/runs/44709056193):
  **success**, two distinct scratch-media QEMU processes, two observed
  frames, second cooperative lease refused for each VM, 14/14 existing
  live QMP/VNC drift refusals, zero guest input.
  Evidence artifact ID `14615544390`, SHA-256 ZIP
  `4ca083afa85b714fcf447b16660efcaf7154b17057a34a0e7332e879daf9ebbd`.
- [Contracts #44709056418](https://github.com/LMhdez/gaslux/actions/runs/44709056418):
  **success**, Pytest adversarial/contract suites, Ruff,
  Python compilation, JSON Schema and the four historical Q4OS
  replays (40 PNGs/36 edges).
- Earlier runs during this change initially failed on a NUL
  decoding error in the `argv` auditor and Ruff formatting;
  both causes were corrected and retested successfully.

**Residual blocker (criterion C):** The TCP RFB listener admits an
untrusted concurrent host connection, and independent same-UID QMP
clients cannot be excluded by the current lease. The transport must
remain read-only; there is no safe authority for even a reversible
test click. A future lab should use a genuinely isolated input-capable
endpoint under a separate dedicated OS account/process namespace,
prove the absence of alternate emitters, and implement an action
transaction with fresh framebuffer binding and bounded races before
attempting one harmless action. Do not mistake the present evidence
for Q4OS Calamares navigation or disk/Windows validation.


### Unix-domain RFB/QMP laboratory: verified scope (20 November 2026)

The experimental `lab_probe.py` now launches QEMU with
`-vnc unix:<private-run>/rfb.sock` and
`-qmp unix:<private-run>/qmp.sock,server=on,wait=off`.
There is no TCP VNC configuration or alternative TCP QMP endpoint.
The run directory is owned by the unprivileged runner and mode 0700;
socket files are mode 0600, authenticated by filesystem owner,
inode and mode. Unix peer PID/UID is verified using SO_PEERCRED and
compared with independently sealed QEMU process identity.

`endpoint_gates.py` inventories the actual QEMU socket descriptors
and TCP LISTEN entries from procfs; a match immediately refuses the lab.
It also verifies socket inodes, rejects symlink/permission drift and only
removes owned original endpoint inodes after QEMU exit. Process shutdown
and removal of both sockets are checked before a successful manifest
is written. Full RFB observations remain read-only.

**Live two-VM evidence:**
[QEMU #44713137089](https://github.com/LMhdez/gaslux/actions/runs/44713137089)
passed using distinct real QEMU processes, synthetic scratch images,
independent QCOW2 snapshots, authenticated Unix socket peers, zero
QEMU TCP listeners and zero input. In each VM an external process under
the distinct `nobody` UID received EACCES from both RFB/QMP Unix paths.
A separate process with the **same UID** connected successfully to both
endpoints despite not holding the `ControllerLease`. This is an observed
counterexample to process-exclusive input isolation and deliberately
remains an active blocker. The second cooperative controller continued
to be refused, 7 existing live drift gates per VM refused as expected,
and both endpoint paths were removed safely after shutdown.

The proof is limited to the CI runner and the processes tested. A host
privileged process, a process sharing the QEMU UID, or kernel compromise
remains outside the exclusion guarantee. Even with Unix socket
confinement, framebuffer-to-input atomicity and visual-control identity
remain unproven. `ReadOnlyVncTransport.click_if_current` is unchanged
and refuses every event; no Calamares action or disk installer operation
has been performed.

The QEMU run and artifacts are **real**, while the independent
adversarial endpoint unit tests use temporary sockets and Python
process-seal fixtures and must not be conflated with guest-input proof.
