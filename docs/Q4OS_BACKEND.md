# Q4OS — native partitioned installation workstream

**Status: read-only experimental candidate probe, no installer.**
Independent of CachyOS. Stacked only on shared lab-media preflight.

Q4OS 6.10 Andromeda was announced as the updated stable release on
8 October 2026. It is based on Debian 13 Trixie. The native Q4OS live
media uses Calamares. The distinct **Q4OS for Windows** program installs
into a Windows filesystem folder: that is *not* the Gaslux native
partitioned installation model.

## Important identity mismatch

Unlike the existing `osReleaseId=q4os` assumption in the draft signed
catalogue v2 policy, Q4OS 6.9 evidence shows `ID=debian` in
`/etc/os-release`. Q4OS identity requires independently checked
Q4OS-specific version evidence (e.g. `/etc/q4os_version`) **from the
same verified native ISO**, plus a real Calamares installation payload.
This early module refuses missing/malformed version evidence, and
reports that ISO-to-live identity binding is **not yet proven**.

The current probe conservatively rejects Secure Boot enabled until
the exact native image signing chain is independently verified; this
does not claim Q4OS itself lacks Secure Boot support.

## Support boundaries

- BIOS/MBR and UEFI/GPT are candidate modes only; the existing MBR
  4-entry/extended/logical and UEFI ESP preservation requirements apply.
- UEFI/MBR and BIOS/GPT are refused.
- The user must not be sent to Calamares' interactive partitioning; an
  authenticated unattended native backend and transaction-owned target
  provisioning are not implemented.
- No ISO URL, exact bytes or SHA-256 is invented or included in the
  stable distribution catalogue.

## Still blocked

Actual ISO inspection; native Calamares partition intent handoff;
Windows storage transaction; disk ownership evidence; bootloader
and update durability; first Linux and Windows boot; uninstall; power
loss; and WinRE/BCD/MBR/ESP rollback in disposable Windows 10/11 VMs.

Official Q4OS sources:
- https://q4os.org/blog.html
- https://q4os.org/dqa007.html
- https://www.q4os.org/forum/viewtopic.php?pid=35537
