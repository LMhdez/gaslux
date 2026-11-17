# Gaslux signed distribution capabilities: catalogue v2 (experimental)

This contract adds machine-readable provenance about a distribution's **installer backend**, not an
authorization to modify any Windows or Linux disk. The deployed v1 RSA/SHA-256 catalogue and
`release-config.json` remain unchanged. v1 is still accepted only for signed Mint/Zorin entries.

## Trust boundary

1. The maintainer pins a specific immutable ISO size and SHA-256 in the release configuration.
2. v2 config requires a `capabilities` object on **every** distribution. Its JSON Schema is
   `schemas/distribution-capabilities.schema.json`; the release schema embeds an equivalent
   definition. `iso-tools/generate-release-metadata.py` validates identity/backend semantics.
3. A release catalogue, including capability bytes, is signed with the existing application-pinned
   offline RSA/SHA-256 private key. **Never** check that key into Git and never manufacture an ISO hash.
4. The WPF loader verifies the same detached signature on the complete catalogue **before parsing**,
   checks v2 field shapes, rejects unknown/duplicate keys and enforces identity/backend pairing.
5. For v2, the Windows wizard lists **only** explicitly released Mint/Zorin records. Ineligible
   records are not routed to a disk writer or to the Debian squashfs extractor. The main-channel
   metadata generator excludes all non-released records even if a development config contains them.
6. The existing plan v4/v5 validators in C#, PowerShell, Python and JSON Schema remain independently
   fail-closed for Mint/Zorin. v2 capability assertions in the PowerShell and live Python modules are
   **read-only**; neither module accepts unsigned catalogues as an installation authorization.

## Backend isolation

| Distro | Backend | Source | Firmware layouts listed as upstream candidates | Boot | Release permission |
|---|---|---|---|---|---|
| Mint, Zorin | `debian-squashfs` | `casper-squashfs` | BIOS/MBR, UEFI/GPT | GRUB | Existing versions only |
| CachyOS | `archiso-cachyos` | `archiso` | BIOS/MBR, UEFI/GPT | GRUB for selected lab strategy | Blocked |
| Pop!_OS | `system76` | `pop-live` | BIOS/MBR, UEFI/GPT | GRUB BIOS, systemd-boot UEFI | Blocked |
| Q4OS | `q4os-native` | `q4os-native-iso` | BIOS/MBR, UEFI/GPT | GRUB candidate | Blocked |
| Bazzite | `fedora-atomic` | `fedora-atomic-iso` | **UEFI/GPT only** | Fedora Atomic UEFI GRUB candidate | Blocked |

Candidate matrices are **not tested Gaslux combinations**. Exact OS release and source image formats
must be validated before a dedicated backend can be enabled. Pop!_OS requires Secure Boot disabled
per current System76 instructions. Bazzite may require user-mediated key enrollment and the newer
installer has documented manual-partitioning limitations. Gaslux cannot silently bypass those
requirements. Q4OS WinSetup installs inside a Windows filesystem folder; it is **not** proof of a
partitioned native installation.

Official reference documentation (accessed 2026-11-16):

- https://wiki.cachyos.org/installation/installation_on_root/
- https://support.system76.com/support/bootloader
- https://support.system76.com/support/install-pop
- https://docs.bazzite.gg/Gaming/Hardware_compatibility_for_gaming/index.html
- https://docs.bazzite.gg/General/Installation_Guide/legacy-install/
- https://www.q4os.org/dqa014.html

## Still required before even a VM installation

A signed v2 catalogue **does not** introduce a new installation plan schema, authenticated
Windows-to-live handoff, backend-specific actual installation agent, persistent boot/update hooks,
first-boot ownership verification, rollback or uninstall. Each backend needs those components and
fresh Windows 10/11 disposable-VM evidence (including Windows boot, Linux boot, updates, power-loss
rollback, WinRE/BCD and BootOrder), plus human review. No real disk should run this code yet.
