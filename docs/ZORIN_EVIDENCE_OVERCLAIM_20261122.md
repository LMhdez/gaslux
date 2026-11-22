# Zorin OS — evidence boundary, 2026-11-22 (UTC)

Branch base: [PR #264](https://github.com/LMhdez/gaslux/pull/264), HEAD `c26db28473520d8d43d4833a5f9c98eceef363e4`. Observed `dev` HEAD `8e68a475d6397ba8fef2e0f9f83758545e202a5f`. GitHub identity: LMhdez.

## #219 reuse status

[#219](https://github.com/LMhdez/gaslux/pull/219) is closed without merge. [Actions #44446537908](https://github.com/LMhdez/gaslux/actions/runs/44446537908), on SHA `694ce044fa753a4f7d1f21a7a9b927c7abf1d0b3`, reported two Zorin OVMF disk-only boots around an installed initramfs regeneration (SUCCESS). It had no Windows disk. [#224](https://github.com/LMhdez/gaslux/pull/224) documents consolidation of #219 at HEAD `3a10dac2d85dd19849a0736d8f57558827277794`, and is itself closed without merge. The stacked [#264](https://github.com/LMhdez/gaslux/pull/264) retains the legacy script. The specific #219 script and workflow do **not** occur in the observed `dev` tree. Reuse in a PR stack does not establish integration into `dev`.

## Scope of this change

The existing direct-kernel COW verifier accepts bounded proof for a genuine Windows-hosted trial with a Zorin SquashFS root. This patch explicitly rejects positive assertions about native installer execution, native bootloader, Windows BCD/WinRE/recovery, kernel or bootloader upgrades, post-update reboots and rollback in **both** the proof and the Windows report. Added adversarial positive-claim tests preserve the original Mint and Zorin offline contracts. These tests do not authenticate witness origin, license a writer, or establish real dual boot.

## Outstanding evidence

- Pinned Zorin OS 18.1 Core: 3,909,091,328 bytes and SHA-256 `44649b97bd307fc4c8529205d098ebbf98575a1e1ba2ee7d7005b697af1721d5`; expected catalog metadata, not a fresh hash of the ISO in this branch.
- Need actual ISO installer inventory and the supported unattended mechanism, then native installation to an authenticated owned region only.
- Require independently restorable post-Windows checkpoint before any target mutation, identity-bound GPT primary/backup and ESP, BCD/WinRE/BitLocker evidence, Windows genuine boot and Zorin boot through persistent native bootloader, update/reboot of both, and real rollback.
- BIOS/MBR, Secure Boot and Windows 11 are separate unproven configurations. No disk writes or production release promotion follow from this patch.
- [Issue #3](https://github.com/LMhdez/gaslux/issues/3) tracks CachyOS-specific acceptance and is not Zorin approval.

CI: `.github/workflows/zorin-evidence-overclaim-deny.yml` (offline regressions only). Record exact completed run URL and HEAD before claiming success.
