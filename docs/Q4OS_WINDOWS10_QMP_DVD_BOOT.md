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
