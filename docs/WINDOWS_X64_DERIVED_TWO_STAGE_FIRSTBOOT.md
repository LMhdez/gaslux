# Windows 10 evaluation — two-stage installed-firstboot in disposable KVM

**Experimental Windows-only CI laboratory. Not a Gaslux Windows/Linux installer.**

Stacked on PR #65, which proved the Microsoft SHA-256 pinned evaluation
Windows 10 optical EFI source can be repackaged only in a short-lived local
UDF derivative with Microsoft's own no-prompt EFI boot sector. This derivative
is never an official ISO and cannot be used for release media.

## Sequence and safety gates

1. Require GitHub-hosted Ubuntu x64 with physical /dev/kvm, explicit VM-only
   consent, approved repository and freshly allocated ephemeral workspace.
2. Download and hash-verify the exact original Microsoft evaluation client ISO.
   Create only a temporary UDF derivative, recording its separate SHA-256.
3. Start a Q35/OVMF guest with a brand-new 128 GiB **file-backed QCOW2**,
   Microsoft's temporary derived DVD (read-only), floppy unattended answer
   file and the VM's own variable store. Use **QEMU -no-reboot**. At the first
   reboot, QEMU exits. This alone is not evidence of an installed OS.
4. Build a **second, independent QEMU process**, using the same *owned* QCOW2,
   original copied OVMF variable store, and optional lab virtual TPM, but
   **without any DVD, floppy, HMP socket or installation media**. Reject any
   unexpected drive, missing target, reused serial transcript or boot order.
5. Require guest-origin Windows client ProductType=1, expected build,
   GPT/ESP/Recovery/WinRE/BCD serial evidence **and an actual clean Windows
   guest shutdown (QEMU exit code zero)**. If any proof is missing the
   workflow must fail, even if UEFI DVD boot succeeded.

This is restricted to a file-backed, disposable GitHub VM; **no host block
device, host ESP, physical firmware NVRAM, BCD, WinRE or BitLocker is ever
opened for mutation**. The lab ISO, installed QCOW2, Windows ISO, WIM, TPM
state and unattended credentials must not be published as artifacts.
Only serial, SHA-256 and a negative/positive decision record may be kept.

## Status

GitHub Actions must independently confirm real Windows firstboot.
Until then, Windows client setup, firstboot and recovery remain **unproven**.
A one-time QEMU reboot exit or UEFI firmware log must not set
"windowsClientBootVerified" true. Even a successful Windows-only guest test
cannot establish Windows+CachyOS dual boot, recovery or Gaslux stable release.

This implementation is a candidate for code review under AI_POLICY.md,
GPL-3.0 and issue #3. Do not merge into main.
