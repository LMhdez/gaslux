# CachyOS OVMF Secure Boot laboratory proof

**LABORATORY ONLY — NO Windows disk modifications, installer release or
physical hardware approval.**

## Root cause under investigation

The official CachyOS 260809 ISO and independent Ed25519/GRUB contract passed
in GitHub Actions run 43934914445, but the in-guest `--check` correctly
refused the OVMF firmware because it could not prove that Secure Boot was
disabled. An unsigned GRUB/kernel reaching a serial login does not, on its own,
prove an EFI `SecureBoot` variable exists and is exactly `0`.

The previous QEMU test selected `OVMF_CODE_4M.fd` first, which can expose
a firmware environment in which the SecureBoot EFI variable is not available
for inspection. **Do not interpret a missing variable as disabled.**

## Isolated VM-only change

The disposable QEMU test now selects the explicit pair:

- `/usr/share/OVMF/OVMF_CODE_4M.secboot.fd`: Secure Boot-capable firmware,
  requiring QEMU SMM mode.
- `/usr/share/OVMF/OVMF_VARS_4M.fd`: a clean, no-enrolled-keys variable
  template. A fresh copy is made under the test's temporary directory for
  each guest. It is **not** the Microsoft-key template
  `OVMF_VARS_4M.ms.fd`, which enables Secure Boot.
- QEMU uses `-machine q35,accel=tcg,smm=on` and
  `-global driver=cfi.pflash01,property=secure,value=on`.

This configuration only determines how an **ephemeral software firmware**
starts in a disposable test VM. No real hardware EFI variables are
reconfigured.

Inside the genuinely booted CachyOS live system, the guest must read the
real `efivarfs` variables `SecureBoot` and `SetupMode`, verify each is
a 5-byte EFI variable record (four attribute bytes plus the value byte),
and require **SecureBoot=0, SetupMode=1**. Any missing, linked,
malformed, active or unexpectedly enrolled variable causes a failure.

The exact `GASLUX_OVMF_SECUREBOOT_DISABLED_VERIFIED=1` stdout marker
must be observed through the live serial console **before** the normal
guarded `--check` success marker. The controller strips only recognized
terminal control sequences and refuses plain echoed commands. The full
serial transcript and SHA-256 are collected for review, regardless of
success or failure.

This is stronger than merely booting an unsigned EFI binary but it is still
**not** a Windows-supplied Secure Boot assessment, a secure boot chain
signature, or a proof that the Windows system's policy was preserved.

## What remains unsafe/unsupported

- No Linux is installed to a VM target by this test; it only runs the
  read-only CachyOS live `--check`.
- No Windows 10/11 guest boots here and no BCD, WinRE, BitLocker, EFI Boot
  Manager, NVRAM recovery or GPT partition rollback has been tested.
- The signed Windows-to-Archiso handoff still has only a temporary CI
  signer and synthetic Windows/device identities.
- A real disk must be rejected if firmware policy is missing or ambiguous;
  never copy a VM-only Secure Boot configuration adjustment into the
  production PowerShell flow.

### References

- Debian OVMF firmware template documentation:
  https://sources.debian.org/src/edk2/2022.11-6%2Bdeb12u2/debian/ovmf.README.Debian
- libvirt Secure Boot firmware and key-enrollment distinctions:
  https://www.libvirt.org/kbase/secureboot.html
- Gaslux issue: https://github.com/LMhdez/gaslux/issues/3
