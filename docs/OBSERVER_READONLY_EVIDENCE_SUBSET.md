# Isolated Observer evidence primitives — no execution authority

**Status:** experimental, read-only/offline and **deny-only**. This integration does not permit QEMU, VNC, guest input, installation, writes, recovery or promotion to a signed production catalogue.

## Provenance and scope

- Source: [#259](https://github.com/LMhdez/gaslux/pull/259) Observer baseline, with the corrected isolated implementation copied byte-for-byte from [#270](https://github.com/LMhdez/gaslux/pull/270), commit `ea4bc70a3aac0e618372cc8cc12bb2f54e09c56f`.
- Imported only `auto_tests/installer_observer/__init__.py` and `auto_tests/installer_observer/evidence.py`.
- Added standalone tests and static CI; no runtime controller, Q4OS UI map, screenshots, replay executor, lease, screenshot capture, SSH/RFB, sockets or workflows launching QEMU.
- [#282](https://github.com/LMhdez/gaslux/pull/282) already integrated the distribution dossiers from #258. They are **not** duplicated here.
- The remaining #258 Q4OS workflows, schemas, artifact maps and experimental tools are **not** included.
- The #270 Observer modules for input, state machine, locators, screenshots, Q4OS profiles and replay remain **unintegrated**.

## Verified technical boundary

The source exports bounded reads of local regular files, rejects duplicate JSON keys, enforces canonical JSON, checks basenames and uses descriptor-based file opening on POSIX. Regression tests exercise refusal on symlink/hardlink, invalid or oversized JSON and content changed during read.

**Important:** `sealed()` is an ordinary SHA-256 digest over caller-provided JSON, **not a signature or attestation**. The parser returns user-supplied fields verbatim; `inputAuthorized`, `diskWritesAuthorized` or similar strings confer **no** rights. File checks are time-bounded observations and cannot prove independent producer identity. No Windows production execution or independent VM/QEMU binding is asserted.

Linux/Windows filesystem semantics, root/guest identity, current runtime privileges and any later imports require separate audits before use by controllers. This module must not be added to execution dispatch.

## Integration guard

All tests are offline, read-only and operate only on synthetic JSON and temporary files. Workflow only uses `contents: read` and has no `workflow_dispatch`, QEMU, guest channel or writer. Include the module in `dev` only while those limitations are preserved. Any expansion towards input authority requires distinct review and tested provenance.
