# GASLUX-OBSERVER — import boundary for isolated dev (deny-only)

## Scope and pinned inputs

- Corrected Observer HOST FD [#294](https://github.com/LMhdez/gaslux/pull/294), exact parent `e7941ef3eb26c0cae1a2d7fbe1b3009eb050c5c9`; original #292 `db50e57b4e296033cb732cd4c249a0403df6b02e`.
- Source Observer [#259](https://github.com/LMhdez/gaslux/pull/259), `e9055bf6e9d83d5c758b69a3a77a8c4a6fd48748`; **not** imported as a full experimental subtree.
- Clean target `dev` fixed at `ca68de69992a8e95f9abd6367bab5458437cbfa7` at implementation time; recheck live `dev` and refresh the replay pin before integration.
- Safety GPT FD [#286](https://github.com/LMhdez/gaslux/pull/286), `9aed36cfdb8c09a461dc38811c326c54180273de`. Safety/no-writer [#267](https://github.com/LMhdez/gaslux/pull/267), `0be04192acd542646a5b6cd952e01620379edf5d`.
- Failed integration [#305](https://github.com/LMhdez/gaslux/pull/305), HEAD `903cda22dc080d52f118e9f57c844870177d62ee` (closed unmerged). Its [Action #45011213674](https://github.com/LMhdez/gaslux/actions/runs/45011213674) was **FAILED at Ruff**, before any authoritative runtime import proof; the separate clean-dev repro covers the missing import boundary.

## Dependency reconstruction

| Symbol required by original host module | Previous dependency | Transitive/operational risk | New boundary |
| --- | --- | --- | --- |
| `ProcessSeal` | `lab_identity.py` | Imports `evidence.Refusal/digest`, `state_machine.LabAuthority` and its locator, screenshot, model and UI/policy tree | Frozen plain dataclass in `host_fd_boundary.py` |
| `process_seal` | `lab_identity.py` | Import alone also loads experimental authority model; local proc fingerprint *never* independently attests VM or authorization | Extracted local Linux /proc fingerprint; rejects processes whose executable name is not QEMU |
| `_read_response`, `_execute` | `lab_identity.py` | Lab's QMP helper imports the authority tree; generic lab allowlist includes `query-vnc` and `query-status` | Bounded JSON reader, hard allowlist **only** `qmp_capabilities` and `query-block` |
| `_qemu_executable_hash` | Runtime import from `gpt_lab_provenance.py` | Module imports `gpt_readonly_producer`, `remote_verifier`, `cryptography`, `rfc8785`, and its `experiment` implementation starts QEMU/libguestfs when invoked | Local read-only SHA-256 of `/proc/PID/exe` in boundary; executable digest is not a signed trust anchor |

`evidence.py` supplies a local exception and digest to experimental `lab_identity.py`; `state_machine.py` brings `locators`, `models`, `screenshot` and grant/safety policy. None are necessary for HOST synthetic diagnostics. Existing GPT parser `#286` is consumed through the caller-provided `gpt_fd_gate` during actual GPT measurement; no copy or security-authorization fallback was introduced. No guest control, VM launcher, state-machine grant, Safety writer or installer object is included.

**Minimal Python source files for the new isolated boundary:** `auto_tests/installer_observer/host_fd_boundary.py` and `auto_tests/installer_observer/host_qemu_fd_evidence.py` (plus an existing package initializer if required by the fixed base). No third-party runtime libraries. No dynamic import fallback.

## Trust separation

1. **Pure diagnostics**: `HostPins`, `declared_context`, `correlate_qmp_fd` operate on caller-provided claims; `qmpDeviceName.assurance` stays `CLAIMED`, `localQmpFdConsistency=false` on direct correlation and `deviceFdAssociationProven=false` unconditionally.
2. **Local read-only measurements**: `borrowed_readonly_proc_fd`, `observe_descriptor`, `measure_gpt_from_proc_fd`, QCOW2 four-byte magic use a real Linux FD; read-only rechecks of remote flags/start ticks survive extraction. A caller must supply the exact external GPT #286 parser; an arbitrary validator is not authenticated here.
3. **OS/process acquisition**: `process_seal`, `_qemu_executable_hash` and `query_qemu_block_readonly` require a genuine Linux process, executable contents and peer-checked QMP Unix socket. A non-QEMU Python subprocess, missing socket or unsuitable pid is refused. No QEMU is started.
4. **Forbidden authority/operations**: `LabAuthority`, `StateMachine`, input channels, QEMU experiment/launch, machine lifecycle, signer, one-shot approval/ledger and writes are **not imported**. Existing `observe_host_qemu` remains non-authorizing; importing the functions creates **no** operational grant.

`NOT_INDEPENDENT`, `DIAGNOSTIC_ONLY`, `inputAuthorized=false`, `diskWritesAuthorized=false`, `productionInstallationAuthorized=false`, `productionWriteAuthorized=false`, `externallyAttested=false`, `freshnessAuthenticated=false`, `replayProtected=false` remain mandatory. The process and filesystem owner can alter local state. The separate correctness of local evidence does **not** establish independence, fresh challenges, backend↔FD mapping, checkpoint fencing or Windows recovery. Transient FD ABA between samples is unresolved.

## Reproducible CI boundary proof

The offline-only workflow checks out full-SHA fixed clean `dev`, the **uncorrected** #294 for a negative import repro, #286 and #267. It runs the actual #294 module in a new Python process with only its host file copied into an isolated `dev` package, and expects `ModuleNotFoundError: lab_identity`. In a separate new process, it copies exactly the two new files and requires successful import and claimed-only offline diagnostics. It asserts forbidden lab imports are absent from `sys.modules`, refuses the non-QEMU process and missing QMP socket, and rejects control command `system_powerdown`. No pre-seeding `sys.modules`, test doubles, or `PYTHONPATH` injection is used.

Additional direct original tests from #292 (31), F-01/02/03 security tests (11), #286 GPT FD (25) and #267 Safety/no-writer (22) run without suppression. Ruff check/format, compileall, checkout HEAD and clean Git checks are required. Only disposable regular files and Python subprocesses are used; no QEMU, guest input, VM installation, disk writer, physical disk/ESP/BCD/WinRE/NVRAM operations or merge.

**Integrator preconditions:** verify current `dev` SHA against the fixed demonstration; select the two exact producer files, not the whole experimental #259 tree; reconcile the host-only tests and their immutable checkout dependencies separately. Do not promote the workflow, producer, or local claims into production installation authority. Independently Safety-review only the new differential, then human review and applicable CI; no automatic merge.
