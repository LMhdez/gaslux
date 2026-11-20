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


### Dedicated-UID operational isolation experiment (20 November 2026)

The QEMU-only workflow now creates a temporary unprivileged Unix account
`gaslux_observer_ci` distinct from the original GitHub runner UID.
The read-only Observer source is staged in a dedicated-owned 0700 scratch
directory, without making the runner's home or checkout traversable.
The QEMU process and the legitimate framebuffer/QMP observer run under
this dedicated UID; RFB and QMP use 0600 Unix sockets in private 0700
session directories. No TCP replacement/proxy, QMP command forwarding,
keyboard or pointer event handler is implemented.

The original runner orchestrates a **connect(2)-only** test:
the dedicated worker announces an unguessable session ID and endpoint paths,
then pauses while the runner UID and a separate `nobody` UID attempt
direct connections to both RFB and QMP sockets. A fixed acknowledgement
releases the read-only worker. This channel cannot forward QMP commands
or RFB events. The existing ControllerLease, process seals, SO_PEERCRED,
socket inode/mode checks, QMP block/snapshot checks and no-TCP-fd
inventory remain active. Post-exit endpoint-name cleanup is independently
inspected with privileged `test` probes; evidence is copied only after
the worker exits.

**Threat boundary:**
- Controller and QEMU: temporary dedicated UID, same trust domain.
- Different-UID unprivileged client, including the original runner UID
  without elevated privileges: kernel filesystem DAC denies `connect`
  with EACCES to either endpoint.
- Another process possessing the **dedicated UID**: not excluded;
  it can access the sockets and the cooperative lease is insufficient.
- Original GitHub runner UID with **sudo** or a process with elevated
  privileges: **not excluded**. GitHub-hosted runners permit sudo, so
  an adversary controlling that credential can impersonate the dedicated
  account, replace the staged source before launch or inspect sockets.
  This is a reproducible operational restriction, not robust protection
  from a malicious runner account.
- Existing open/inherited socket file descriptors and later unauthorized
  privileged process attachment remain out of scope; the audit must not
  claim exclusive input until these are excluded by an independent
  process/privilege boundary.
- No framebuffer/input atomic compare-and-act primitive has been built.
  `ReadOnlyVncTransport.click_if_current` still refuses all events.

This experiment does **not** prove exclusive UI control, and it
does not justify Q4OS/Calamares navigation. Use a separately privileged,
reviewed, immutable launcher and a confined worker with independent
security-policy enforcement before any future guest input.


### Privileged boundary and inherited descriptor audit (20 November 2026)

The host-side `isolation_host.py` is **not** a trusted privileged
launcher. The GitHub-hosted runner retains unrestricted `sudo` and can
impersonate the dedicated `gaslux_observer_ci` UID. Its own workflow
copies Python source from a mutable checkout into the dedicated-owned
execution tree. Therefore filesystem DAC isolation against the
*unprivileged* original runner remains valid, but the runner with
administrative capabilities can gain the dedicated UID, connect to
RFB/QMP Unix sockets, and write staged source. The new laboratory
performs strictly connect-only `sudo -u gaslux_observer_ci` probes
against both live sockets and tests staged-source writability with
`test -w`; **it sends no RFB messages or QMP commands**.

The real-QEMU probe now invokes `fd_audit.audit_child_fds()` for each
discardable VM session. The audit creates an unrelated Unix socketpair,
marks one end inheritable, and runs a no-input subprocess with
`close_fds=False` as a *positive* control. The same descriptor must
then disappear under `close_fds=True`. Both QEMU and the host-side
worker launch with explicit `close_fds=True`. This detects a basic
inherited-descriptor regression; it does **not** establish that no
third-party process already possesses a connected RFB/QMP descriptor.
The latter bypasses future pathname permission changes and requires
revocation by closing the connection/terminating the server. The
existing QMP query-vnc client inventory refuses unexpected RFB clients
at verification time, but is not atomic with a future guest event.

The hostile-process classes are:
1. Legitimate QEMU and read-only observer: dedicated CI Unix UID, bound
   by a process seal, a cooperative controller lease and SO_PEERCRED.
2. Unprivileged original runner or `nobody`: rejected by the private
   directory/socket DAC policy.
3. Separate process with dedicated UID: **not excluded** and capable
   of connecting if it can reach the private session paths.
4. Original runner using unrestricted `sudo`, root, or a host
   administrator: **not excluded**; can impersonate, change staged code,
   traverse directories and interfere with QEMU.
5. Process with a pre-existing open socket descriptor: potentially
   remains connected after a pathname permission change; `FD_CLOEXEC`
   and `close_fds` only constrain *subsequent child inheritance*.
6. Alternative host facilities (ptrace, process namespaces, `/proc`
   access, privileged fd injection): not yet contained by a verified
   independent security domain.

**Required independent trusted boundary:** a separately managed runner
or isolated control VM should deploy a pinned, signed and reviewed
launcher/service from an immutable artifact **before** running
untrusted job source. The job account must lack arbitrary `sudo`,
`ptrace`, process/file-descriptor injection and write access to the
launcher, its policy and the QEMU session tree. The launcher must bind
an authenticated client identity and transaction identifier to a
narrow, reviewed, observation-only capability; it must expose neither
raw QMP nor raw RFB input through a general-purpose proxy. Media,
process, socket and session ownership must be corroborated on every
request, and all inheritable descriptors must be closed or explicitly
accounted for. The implementation requires a human-reviewed threat
model, provisioning and independent infrastructure tests; **none of
these properties is provided by the GitHub-hosted runner itself**.

**Future event protocol (specification only; not implemented):**
a sealed observation record would include `run_id`, QEMU PID/start
ticks/executable seal, QMP/RFB socket inodes and verified peer,
snapshot/media identities, frame digest, reviewed visual locator,
control identity, transition ID, expected post-state and a bounded
deadline. A trusted single-owner execution primitive would recheck
these inputs immediately before *one* allowlisted event, consume a
nonce/transaction exactly once, reject concurrent or stale sessions,
and observe the expected result after the event. A framebuffer
comparison and subsequent RFB send are **not atomic** and no number of
double-captures eliminates the TOCTOU window. Without a mechanism that
provides a demonstrable bounded race under a human-reviewed threat
model, the action must remain refused. There is no code here for
encoding or sending an RFB input or QMP mutating command.

All tests use only synthetic ISO/QCOW2 media. Neither Windows nor
Calamares nor a physical disk is touched. Passing CI is not a claim
of exclusive input authority or verified installation.


### Independent trust-boundary experiment — infrastructure result (20 November 2026)

**Classification: criterion C — the available GitHub-hosted runner cannot establish an independent trusted control domain.** The current runner is both the CI client and the administrator of the host: it has non-interactive `sudo`, checks out the same mutable source tree that is staged for the dedicated UID, can impersonate `gaslux_observer_ci`, can connect to that UID's QMP/RFB sockets, and can write the staged Python controller source. The new QEMU job records these facts in `trust_boundary_status.json`, including the measured SHA-256 of the staged source. The digest identifies the bytes observed; it is **not a signature, trusted provenance or proof of immutability**. The manifest deliberately records `source_signature_verified=false`, `independent_control_domain=false`, `criterion_A=false` and `criterion_C=true`. No service or privileged production component was installed.

#### Domains and threat model

- **A — trusted control domain (required, unavailable here):** separately provisioned control VM or dedicated runner; root-owned, reviewed, immutable controller artifact and policy; service identity and QEMU lifecycle controlled before the job/client starts.
- **B — untrusted client domain:** WPF/CI client with no sudo, no membership in the controller/QEMU groups, no private socket or media access, no ptrace/process-memory/fd injection capability. It receives only the fixed observation API.
- **C — QEMU domain:** process and disposable media owned by the control domain. QMP and RFB endpoints are private to the controller; never exposed to the client.
- **D — observation channel:** a narrow authenticated local API. It does not proxy arbitrary QMP or RFB bytes and has no keyboard, pointer, shell, installer, disk or boot operations.

An administrator/root of the trusted control domain, a compromised hypervisor/host kernel, or an attacker with equivalent privileged execution remains outside the threat model. A same-host GitHub-hosted job cannot manufacture this trust separation by changing UIDs or adding `sudo` commands.

#### Experimental client contract

`auto_tests/installer_observer/boundary_model.py` is an **in-memory architectural simulation only**. It is intentionally named a model and does not open sockets, launch QEMU, attest an executable, validate a signature or create an OS security boundary. The test harness supplies synthetic peer credentials. The fixed operations are:

1. `session.identify` — session/transaction IDs and controller, policy and QEMU identity digests, explicitly labelled as synthetic and unsigned.
2. `state.read` — bounded read-only state.
3. `frame.read` — framebuffer fixture bytes and SHA-256.
4. `session.close` — invalidate the in-memory session and discard its fixture data.

Requests have an exact field allowlist, protocol version, canonical UUIDs, session and transaction binding, one-use request ID, strictly increasing sequence and expiry. Peer UID/PID/start ticks must match the fixture. Unknown fields and operations such as `qmp.execute`, `rfb.input`, `shell.exec`, `install` and `partition` are refused. The model's close operation is **not** real QEMU termination or real socket revocation.

#### Required production architecture (not implemented)

A separately managed runner/control VM must provision a signed, pinned controller artifact and policy before any untrusted job starts. The client must not possess sudo or any route to modify the controller, its service unit, policy, QEMU media or private endpoint directory. The control service should run under a dedicated OS identity with no unnecessary capabilities, a restrictive systemd sandbox (including no-new-privileges, protected system/home/kernel paths, constrained address families and syscall policy), and a separate client identity.

The controller alone owns QEMU, its QMP/RFB Unix sockets and media. It authenticates client connections using kernel peer credentials (e.g. `SO_PEERCRED`) plus independently resolved process start identity; it returns only the four fixed operations above, with session/transaction binding and a bounded response size. The API must never forward arbitrary QMP/RFB payloads. Controller and policy artifact hashes must be verified against a trust root provisioned outside the job; a locally computed SHA-256 is only an identifier.

#### Revocation

The existing synthetic test proves that a preconnected Unix descriptor remains usable after pathname permissions are changed. The model proves only in-memory session invalidation. Neither proves revocation of a live QMP/RFB connection. A real revocation test must have the trusted controller close the accepted channel(s), terminate/restart the QEMU process that owns the servers (thereby destroying all server-side client sessions), remove the old endpoints, rotate session and transaction IDs, and prove that old clients/descriptors cannot issue further protocol messages while new connections to the old endpoint fail. No such trusted controller is available on the current runner; **real QMP/RFB revocation remains unproven**.

#### Validation classification

- **Real QEMU:** the existing read-only lab still boots two independent disposable QEMU processes with synthetic ISO/QCOW2 media. It proves QEMU identity and the runner's ability to impersonate the dedicated UID and connect to QMP/RFB, not an independent trust boundary.
- **Synthetic contract tests:** the new boundary model tests client identity mismatch, transaction/session mismatch, request replay and sequence, unknown fields, unsupported/mutating operations, expiry, evidence hash binding and model-session close.
- **Not exercised:** an independently provisioned controller VM/runner, signed artifact verification, a hostile client unable to administer that domain, ptrace/fd injection across that boundary, real pre-opened RFB/QMP FD revocation, and atomic framebuffer/action handling.
- **Input remains disabled:** no RFB events, no mutating QMP commands, no installer navigation and no production WPF integration.

This is a concrete infrastructure blocker, not a claim that a green GitHub Actions run has achieved criterion A. A dedicated trusted runner/control VM and human-approved provisioning/security policy are prerequisites before any real boundary or graphical action can be accepted.


## Remote Observer broker contract — protocol v1 (specification only)

**Purpose:** define a future read-only interface usable by distribution observers, including a future Bazzite/Anaconda consumer, without giving the client access to QMP, RFB, shells, installer controls or host disks. This section and the JSON Schemas are interface specifications only. No broker, network endpoint, key, credential, collector or Bazzite integration is deployed by this PR.

### Trust topology and deployment boundary

The remote broker/controller must execute in an independently administered control domain, not as another process, container or VM whose lifecycle, host root, cloud account or signing key is controlled by the GitHub Actions runner being treated as adversarial. The runner may submit authenticated, narrowly authorized observation requests; it must not be able to administer the broker, replace its executable/policy, read its signing key, access its hypervisor sockets or impersonate its workload identity.

A viable deployment requires a separately provisioned control VM/service, with its own administrator boundary, immutable reviewed controller and collector artifacts, private QEMU/QMP/RFB endpoints, restricted egress, independent audit storage and a controller signing key held by a KMS/HSM or equivalent trust domain unavailable to the runner. The broker must reject requests unless the deployed artifact, policy and collector hashes match independently pinned release metadata. A hash reported by the runner is not trusted evidence.

For GitHub Actions clients, prefer short-lived GitHub OIDC workload identity exchange with exact issuer, audience, repository ID, workflow identity, ref and run/commit claims pinned in broker policy. For a future WPF client, use separately enrolled device identity and short-lived credentials. mTLS protects the transport and authenticates the presented client/controller certificates; it does not authenticate the guest or prove response correctness. No long-lived private key or bearer token may be stored in this repository or exposed to job source.

### Three independent verification questions

1. **Channel authenticity:** did the client reach the intended broker and did the broker authenticate the authorized client? Use TLS 1.3 with mutual authentication where applicable, strict certificate/key pinning or workload identity, short-lived credentials, audience/repository/workflow authorization and expiry. This proves the channel principals only.
2. **Guest authenticity:** does the observed VM correspond to the intended guest, and is its boot state trusted? A QEMU PID, VM UUID, guest-agent response, ISO digest or framebuffer is not by itself a cryptographic guest attestation. Report host-observed VM/process identity separately from guest-claimed identity. Set `cryptographically-attested` only after an independent verifier validates fresh vTPM/TPM quote and measured-boot evidence against configured trust anchors, including nonce binding. If no such evidence is available, report `guest-claimed` or `host-observed` with attestation `not-provided`; never silently promote it.
3. **Response integrity:** did the independently trusted controller sign exactly this response, for this request, session, transaction and nonce? The controller signs a deterministic RFC 8785 JSON Canonicalization Scheme representation of the response with the `signature` member omitted. Ed25519 is the protocol-v1 signature algorithm. The client verifies the signature using a controller public key/key ID pinned through a trust root provisioned outside the runner, then verifies `request_sha256`, `result_sha256`, framebuffer SHA-256, nonce, request ID, operation, sequence, transaction, session and expiry. A valid signature proves that the holder of the pinned controller key signed the envelope; it does **not** independently prove the guest's truthfulness. Guest attestation remains a separate check.

### Wire contract

The strict request and response schemas are:

- `schemas/observer-readonly-request.schema.json`
- `schemas/observer-readonly-response.schema.json`

Transport is HTTPS POST over TLS 1.3. The deployment chooses its broker origin; this repository does not define or claim an active service URL. Request bodies are at most 16 KiB. Responses are at most 8 MiB, regardless of the client-requested cap. State snapshots are at most 64 KiB after canonical serialization; framebuffer is PNG only, at most 8 MiB decoded. The server enforces byte limits while streaming, not after unbounded allocation. Request timeout is 100–10,000 ms; a session expires no later than 10 minutes after creation. Every response expires within 30 seconds of issuance. Clients reject clock/expiry violations and never extend expiry locally.

Each request carries a fresh 256-bit CSPRNG nonce (unpadded base64url), UUID transaction ID, unique UUID request ID, monotonically increasing per-session sequence, fixed operation, timeout and maximum response size. `session.identify` starts a transaction with null session ID and sequence zero; the broker returns a new session UUID. All later operations require that session UUID and the same transaction ID. The broker stores nonce/request-ID consumption durably for the session lifetime, rejects duplicates, stale sequence, cross-session use and transaction changes, and binds every signed response to the exact request digest and nonce. Session state is not recovered by replaying a previous transaction.

The only operations are:

| Operation | Request | Successful result |
|---|---|---|
| `session.identify` | Create a new authorized observation session | Session UUID and expiry |
| `state.read` | Read bounded, allowlisted state fields | Structured state snapshot |
| `frame.read` | Capture one framebuffer | PNG bytes, media type and SHA-256 |
| `session.close` | Close this exact session | Closed status; old session becomes unusable |

No generic command, shell, arbitrary QMP method, raw RFB tunnel, keyboard, pointer, installer action, disk API, boot change or arbitrary file read exists in the protocol. Unknown fields and operations fail closed. Refusals are signed responses with a fixed refusal code; authentication failures before a trusted response may instead terminate the transport, which the client treats as failure rather than as an empty observation.

### Guest identity and result semantics

The signed envelope contains the controller ID/key ID, controller artifact and policy hashes, collector ID/hash, VM UUID, QEMU PID/start ticks/executable hash, guest identity assurance, attestation status, transaction/request/nonce binding, issue/expiry times, result digest and detached signature. The collector hash is measured by the controller against its independently pinned artifact, not accepted from the client.

- `host-observed`: the controller's hypervisor/control plane observed a VM/process identity. This is not guest OS identity or measured-boot proof.
- `guest-claimed`: identity came only from the guest or guest agent. Attestation status must be `not-provided`.
- `cryptographically-attested`: allowed only when a configured verifier validated fresh attestation evidence and its trust anchor. The schema requires status `verified`, evidence digest, verifier ID and trust-anchor ID.

A response `status=ok` means the requested read-only operation completed; it does not mean the guest was authenticated. Consumers must inspect guest attestation separately. An unverified guest may be displayed as unverified for diagnosis, but its data must not authorize an installation transition, destructive operation or click. Any `refused` response must contain only a refusal result and must never smuggle state/frame data.

### Revocation, replay and audit

The broker must atomically consume nonce/request ID/sequence before dispatch, enforce one in-flight request per session, bind session to authenticated client and transaction, and expire sessions server-side. Closing a session revokes its authorization and closes accepted broker channels. The broker must terminate the QEMU server process or otherwise prove that all QMP/RFB server-side sessions and pre-opened descriptors are destroyed, remove old endpoints, rotate session identity and demonstrate that old sessions/descriptors cannot communicate. Changing socket permissions alone is not revocation.

Audit records are append-only in a domain independent from the runner and include authenticated principal, workload identity claims, controller/collector hashes, policy version, VM and media identities, nonce/request/transaction/session IDs, operation, response digest, refusal reason, signature key ID, attestation verifier/trust-anchor result, timestamps and revocation outcome. Secrets, private keys and raw QMP/RFB traffic are never logged. Retention and access policy must be reviewed before deployment.

### Future Bazzite consumer boundary

A future Bazzite backend may consume this protocol only through a dedicated read-only adapter. It may request session identity, bounded state and framebuffer, then verify the signed envelope and explicitly display the guest-attestation assurance. It must not receive broker credentials or direct QMP/RFB endpoints. No Anaconda collector, Bazzite backend change, WPF integration, installer automation or input path is included here. The existing `ReadOnlyVncTransport.click_if_current` continues to refuse unconditionally because framebuffer comparison and RFB input are not atomic.

### Deployment gates and current result

Before the protocol can be called an independent trust boundary, human-reviewed infrastructure evidence must show: (a) broker administration and signing keys are outside the runner's privileged domain; (b) runner/root cannot replace controller, collector, policy or guest; (c) client authentication and authorization are independently enforced; (d) guest attestation is validated against a separately provisioned trust root or explicitly marked unavailable; (e) signed response verification and nonce/replay rejection work against hostile clients; (f) real QMP/RFB sessions and old descriptors are revoked; and (g) audit evidence is independently retained.

No broker endpoint, independent control VM, trust root, public key, certificate, KMS/HSM key, guest attestation verifier or remote execution infrastructure was available in this intervention. Therefore the protocol is **specified but not implemented**, and the trust classification remains **`NOT_INDEPENDENT` / criterion C**. The same-host runner experiment and its limitations remain unchanged.


## Local remote-response verifier (implemented; no broker)

`auto_tests/installer_observer/remote_verifier.py` implements a client-side verifier for the protocol above. It does not start a server, contact a broker, create production keys, open QMP/RFB, or provide any input operation.

### Trust provisioning

The caller must construct `TrustStore` from an independently provisioned `TrustedController` record. It pins the raw 32-byte Ed25519 public key and the expected key ID, controller ID, controller artifact SHA-256, policy SHA-256, collector ID and artifact SHA-256, VM UUID, QEMU executable SHA-256, distribution ID/version, ISO SHA-256, installer ID, attestation verifier ID and attestation trust-anchor ID.

The verifier never imports a public key or trust anchor from the response. A missing or empty trust store returns `trust-anchor-missing`; an unknown key ID returns `untrusted-key`. Test keys are generated ephemerally by tests only. No production key material or trust store is committed.

### Verification order and fail-closed behavior

1. Parse bounded UTF-8 JSON; reject duplicate properties, non-JSON constants and oversized requests/responses.
2. Validate request and response against the strict Draft 2020-12 schemas, including distribution identity and per-session request sequence.
3. Canonicalize with the RFC 8785 implementation; hash the canonical request and require exact `request_sha256` binding.
4. Bind operation, request ID, nonce, sequence, transaction ID and session ID. A successful `session.identify` must return a fresh session ID; all later responses must echo the requested session.
5. Resolve the signature key exclusively from the local trust store; compare key ID and controller/collector artifact and policy identities with pinned values.
6. Verify Ed25519 over the RFC 8785 canonical response object with only the `signature` member omitted.
7. Verify canonical `result_sha256`; for framebuffer responses, strictly decode base64, require PNG magic, enforce the byte limit and verify the raw PNG SHA-256.
8. Verify issue/expiry timestamps, the 30-second response lifetime, caller deadline, request timeout, state snapshot bound, and ten-minute maximum session lifetime.
9. For successful observations, pin VM UUID, QEMU executable digest, distribution, version, ISO digest and installer ID. By default require a signed attestation assertion whose verifier and trust-anchor IDs match local policy.
10. Atomically consume nonce/request ID and advance the session sequence through a replay guard. A duplicate, stale sequence, closed/expired session, transaction mismatch or storage failure is refused.

The request schema requires sequence zero for `session.identify` and sequence at least one for subsequent operations. The response sequence must exactly echo the request sequence.

### Replay state

`SQLiteReplayGuard` persists consumed nonces, request IDs, session transaction IDs, monotonic sequence, expiry and closure state using SQLite transactions. Its parent directory must already be owned by the current user and mode 0700; the database is created as a regular mode-0600 file, and symlinks are refused. Storage errors fail closed. `InMemoryReplayGuard` is provided for tests and short-lived processes only; it does not protect across process restarts.

A production client must protect and back up the SQLite state against rollback/tampering, and must not restore an older replay database. This local database is replay state, not a trust anchor.

### Attestation semantics — important limitation

The verifier distinguishes:
- `controller_signature_verified`: the pinned Ed25519 key signed the response.
- `controller_workload_trusted` / `collector_trusted`: controller, policy and collector hashes match local pins.
- `guest_identity_assurance`: the signed controller's declared assurance level.
- `guest_attestation_status`: the signed controller's declared attestation status.

The current response envelope contains only an attestation evidence digest, verifier ID and trust-anchor ID; it does not carry the TPM/vTPM quote or measured-boot event log. Consequently `guest_attestation_verified_locally` is always **false** and `guest_attestation_assertion` is explicitly `trusted-controller-asserted`. The verifier requires the controller to assert `cryptographically-attested` and the pinned verifier/trust-anchor IDs by default, but it does **not** independently validate the quote. A future protocol revision must carry bounded attestation evidence or a separately verifiable attestation receipt and add a local verifier before claiming guest attestation is independently established.

A valid Ed25519 signature is not TPM attestation. A trusted controller/collector hash is not proof that the guest is genuine. A correct result digest proves consistency of the signed bytes, not truthfulness of the observation.

### API and operational status

The public API is `RemoteResponseVerifier.verify(request, response, deadline=..., now=...)`. It returns a `VerifiedRemoteResponse` only after all configured gates pass, or a `VerificationRefused` with a stable refusal code. A correctly signed broker refusal is returned with `status="refused"`; it is never represented as a successful observation.

No network client, broker, workload identity exchange, TPM quote verifier, WPF integration, Bazzite adapter or installer automation is implemented. `click_if_current` remains an unconditional refusal. The verifier is a local cryptographic/contract component and does not change the overall trust classification: **`NOT_INDEPENDENT`**.
