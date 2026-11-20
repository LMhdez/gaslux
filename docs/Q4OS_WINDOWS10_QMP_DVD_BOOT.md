# Q4OS Windows 10 evaluation lab — one-shot OVMF DVD boot

## Root cause and scope

[Action #44732384774](https://github.com/LMhdez/gaslux/actions/runs/44732384774)
failed in step 7, exit code 124 after 18,000 seconds. The genuine,
SHA-256-verified Windows 10 evaluation DVD entered OVMF Boot0001 and
emitted **"Press any key to boot from CD or DVD"** to its serial log.
No key arrived. OVMF reported the DVD boot timeout, no Windows disk boot,
and entered the UEFI Interactive Shell. No Windows first logon, GPT
inventory, independent attestation or rollback was proven.

The original workflow also exported an ephemeral unattended VM password
through GITHUB_ENV. Its value appeared in the Action job's environment
logs. The current workflow generates the password only inside the
unattended preparation step and does not export it to later steps.
Neither the password nor the unattended ISO/XML is uploaded.

## Controlled correction — experimental, QEMU only

The already authorized, disposable GitHub-hosted lab still downloads
the exact official Microsoft Windows 10 Enterprise Evaluation ISO
(SHA-256
\`ef7312733a9f5d7d51cfa04ac497671995674ca5e1058d5164d6028f0938d668\`).
The source ISO and Windows install medium are not changed.

The initial QEMU invocation now creates a QMP UNIX-domain socket inside
the private, runner-owned Windows workspace. The Python script
\`auto_tests/tools/q4os_win10_qmp_boot.py\`:

1. Validates the private directory and owned socket; requires a real QMP
   greeting, capability negotiation and running VM status.
2. Observes the **actual UEFI serial console**; strips ANSI escapes and
   waits for the exact Windows DVD prompt, for at most 90 seconds.
3. Sends **one** QMP \`send-key\` with \`qcode=ret\`, checks the QMP
   acknowledgement and never sends a second key. The process exits before
   subsequent Windows Setup reboots; the DVD prompt on later restarts
   must time out normally so the boot order proceeds to Windows.
4. Detects UEFI Interactive Shell and DVD boot timeout signatures,
   rejecting them before any further steps. No prompt, missing/malformed
   QMP, rejected key, or no observable QCOW2 allocation within 600
   seconds also fails closed.
5. Records only a small structured status JSON with no raw serial,
   screenshots, ISO, QCOW2, NVRAM, password or unattended XML.
6. **Does not call Windows Setup, modify BCD/WinRE, install Linux,
   format anything, or run Calamares/GRUB/efibootmgr.**

The observed QCOW2 growth is only **a progress heuristic**; it does not
prove Windows Setup started or completed. Windows first-logon must still
be established by the subsequent read-only Windows file, ESP and BCD
witness checks. The subsequent Safety #267 gate is always no-writer, and
its lack of independent authenticated host/guest evidence is explicit.
The current unattended GPT target does not guarantee a WinRE partition.

The stage-7 QEMU timeout is bounded to 7,200 seconds with KVM or
14,400 seconds with TCG (formerly 18,000 seconds), while the missing
initial prompt/QMP and no-progress cases fail much earlier. On
failure, the step terminates the disposable QEMU process, leaves
the output limited to an explicit refusal and publishes only bounded
text/JSON (if produced).

## Validation boundaries

The controller's synthetic regression suite tests a detected prompt,
missing prompt, QMP unavailable/malformed/rejected, one key sent,
EFI Shell, UEFI timeout, missing disk activity, directory/symlink
protection, and an attempted later DVD prompt with **no reinjection**.
It is deliberately not a Windows first-boot test.

No real Windows proof should be asserted until a new, single
GitHub-hosted Windows QEMU Action verifies the first-logon witness,
Windows Boot Manager and BCD, host/guest GPT inventories and the
unchanged QCOW2 digest before and after **read-only** observation.
\`DENY_UNAUTHENTICATED\` and \`DENY_NO_WRITER\` remain refusal
terminology, never write permissions.

This backend remains experimental. The stable catalogue, Installer
Observer #259 and Safety #265/#267 branches are untouched. No physical
disk, shared Windows ESP or WinRE partition is modified by Q4OS.

## Genuine Windows evidence and subsequent read-only blocker (20 November 2026)

[Action #44818428023](https://github.com/LMhdez/gaslux/actions/runs/44818428023)
on `c993b207b52ee1014583198d7378cea025089768` reached
Windows 10's genuine first logon on an isolated 48-GiB QCOW2.
The original Microsoft ISO SHA-256 matched the pinned
`ef7312733a9f5d7d51cfa04ac497671995674ca5e1058d5164d6028f0938d668`.
QMP emitted `dvd_key_sent_once` at 21:22:54 UTC, confirming the prompt,
handshake, send-key acknowledgement and early QCOW2 activity.
Windows QEMU shut down cleanly at 21:27:51 UTC;
`qemu-img check` reported no errors. A **separate read-only** Linux
`qemu-nbd` inspection established presence of a Windows first-logon
marker, `Windows/System32/winload.efi`,
`EFI/Microsoft/Boot/bootmgfw.efi`, nonempty BCD, and a GPT
`sgdisk --verify` success. It found ESP, MSR, and Microsoft basic-data
NTFS GPT partitions, **not** a WinRE GPT partition.
BCD contents and Windows Recovery functionality were not audited.
These steps do not establish restoration capability or dual boot.

The subsequent independent GPT observation stopped at 21:28:02 UTC
with `incomplete host GPT edges`. It did **not** reach a second
libguestfs GPT inventory, the SHA-256 before/after comparison, or
the real-input Safety #267 no-writer denial.

The 594-byte [run artifact #14670747112](https://github.com/LMhdez/gaslux/actions/runs/44818428023/artifacts/14670747112)
was downloaded and verified at ZIP SHA-256
`8aa790e22eb5d50a67acf96ccfcb93f5f0a0226ed9080bea1f6b5c46e86d83ec`.
Only `boot-controller.json` and `q4os-readonly-failure.json`
were present; both explicitly deny installation/writes, and neither
contains ISO, disk images or credentials.

### Specific read-only extractor defect and regression

The host probe used two `qemu-img dd` calls. For the end-of-disk GPT
window, it incorrectly combined `count=2`, `bs=1M`, and
`skip=49150` for a 48-GiB disk. QEMU `qemu-img dd` constrains the
input by `count` **before** applying `skip`, therefore the skip
lands past that constrained input and creates an empty output rather
than the expected 2-MiB GPT tail. The command may return zero even
when the resulting file is empty. The code correctly refused it.

The correction preserves the **same** QEMU decoder and Safety #265
GPT parser, removes `count=2` **only from the final edge extraction**
(so `skip` reads the final two MiB to EOF), checks exact length and
file ownership before reading, and keeps a sparse GPT-only witness.
The start edge retains `count=2`. No Windows partition payload or
filesystem content is extracted by this stage.

A new regression converts an entirely synthetic 64-MiB GPT RAW file
to QCOW2, uses actual `qemu-img dd` for both edges, verifies byte
identity with source and GPT/CRC equivalence using the existing
Safety parser, checks QCOW2 SHA-256 before/after, and reproduces
the original broken `count+skip` command as a negative case.
No genuine Windows, EFI writer, NVRAM, GRUB or Calamares is involved
in that synthetic regression. The test does not confer any
installation authorization.

Q4OS's unattended layout remains unsuitable for native Linux
placement: only ESP, MSR and Windows NTFS are explicitly provisioned,
there is no owned Q4OS root extent, and WinRE was absent on the
observed image. The latest Safety #267 branch extends the experimental
synthetic QEMU host/guest witness suite while leaving the pinned
core identity/no-writer modules unchanged. Q4OS continues to use
`f55633c90973f633dda678f583f7730fc2cdc0ce`,
not the untested current Safety HEAD. No-writer remains a refusal.
