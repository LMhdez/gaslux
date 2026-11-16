# Signed candidate handoff — lab-only trust contract

This is a **read-only** Ed25519 laboratory verifier shared by the independently
developed Pop!_OS, Q4OS and Bazzite preflight branches. It is **not** an extension
to the production Gaslux/Libertix signing catalogue or state machine.

- Validates a canonical JSON handoff with an Ed25519 detached signature.
- Requires the *trusted* raw public key digest, expected transaction ID,
  firmware/layout, root UUID, ISO hash and length, target disk evidence digest,
  Windows boot evidence digest, and ESP UUID to be supplied independently by the
  **trusted lab harness**.
- A public key hash embedded in the untrusted handoff would NOT provide a trust
  root; this code intentionally does not trust such fields.
- Enforces exact backend/firmware pairing: Pop!_OS (BIOS/MBR or UEFI/GPT),
  Q4OS (BIOS/MBR or UEFI/GPT), Bazzite (UEFI/GPT exclusively).
- Has no writer or installer API. `operation` can only equal `read-only`.
  The result **always** has `installationAuthorized: false`.
- Does not implement a durable nonce/replay cache, Windows boot snapshots,
  privileged EFI boot selection, signed on-disk plan consumption or
  validated immutable boot-kernel command-line provenance.
- Test keys are ephemeral. **No maintainer production signing key is generated
  or used by the test**.

A passing signature does not bind independently submitted `os-release` files
to a verified ISO. It also does not certify a Linux installation, first boot,
Windows rollback or recovery. That work requires real disposable Windows VM
evidence and a production trust architecture with recovery checkpoints.

This contract is deliberately separate from CachyOS's own experimental handoff
and is designed for later review and convergence, not a parallel disk writer.
