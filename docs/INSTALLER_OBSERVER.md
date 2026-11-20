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
