# CachyOS: installed native KDE Plasma Wayland graphical boot, disposable QEMU only

**Draft experiment, not Gaslux production GUI/Windows dual boot.**

This feature branches from [PR #36](https://github.com/LMhdez/gaslux/pull/36),
which already passed the official SHA-256-pinned CachyOS Archiso, native
signed `pacstrap`, EFI GRUB and separate installed-system first boot.

It adds a separate **lab-only opt-in** after signed live-guest preflight:

1. Install native, signed `plasma-meta`, `plasma-workspace`, `kwin`,
   `qt6-wayland`, `sddm`, `mesa`, `dolphin`, `konsole` and GUI dependencies
   from CachyOS/Arch repositories directly into the independent
   VM-owned target disk. NEVER copy the live ISO rootfs.
2. Configure the dedicated disposable `gasluxtest` account, locale,
   timezone, a QEMU-only SDDM autologin and native
   `graphical.target` + Plasma Wayland. Autologin without a normal user
   password is **exclusively** for this disposable CI VM, never the
   public Windows installation wizard or real hardware.
3. Install the same EFI GRUB without firmware NVRAM writes, close
   Archiso, and boot an **independent** OVMF guest with ONLY its
   12 GiB QCOW2 installed target (no live ISO/installer disk).
4. Inside the running installed guest, require the existing
   kernel, root UUID, distro identity and pacman firstboot proof
   PLUS `sddm.service` active and a `gasluxtest` user process for
   both `plasmashell` and `kwin_wayland`. This is a real graphical user
   session, not a package-file presence check.
5. Only after both runtime markers, request a framebuffer screendump
   from QEMU's local Unix monitor. Validate P6 dimensions, exact
   pixel length and meaningful pixel diversity before accepting
   visual proof. Retain the actual QEMU screenshot and SHA-256 plus
   raw guest console evidence in Actions artifacts.

**Fail closed** if package signatures, virtual disk identity, session
processes, live-to-installed reboot, QEMU monitor, raw pixel geometry,
or framebuffer content do not match. A black/text-only screenshot is
not a passing KDE graphical session.

## Limitations

- This does NOT establish a complete production graphical installation
  through Gaslux WPF, including interactive user account, localization,
  keyboard, session preferences or device-specific GPU drivers.
- Wayland with virtual DRM is chosen for a deterministic
  headless CI witness; success does not imply a production Wayland,
  AMD, Intel or NVIDIA hardware session is functional.
- Real Windows 10/11 dual boot, WinRE/BCD/BitLocker/ESP rollback,
  Secure Boot enabled, MBR/BIOS, reinstall, updates and real hardware
  remain OUTSIDE this experiment.
- Human review and issue #3 remain release requirements. Keep the
  CachyOS installer disabled in stable distribution metadata.

Official references:
- https://wiki.cachyos.org/pt/configuration/desktop_environments/kde/
- https://wiki.archlinux.org/title/SDDM
- https://archlinux.org/packages/extra/x86_64/plasma-workspace/

Relevant branch: `feature/cachyos-qemu-plasma-graphical-session`.

## Version-accurate package correction

The first official-ISO graphical attempt
[Actions #43963396311](https://github.com/LMhdez/gaslux/actions/runs/43963396311)
failed safely during pacstrap, with the real guest reporting
`target not found: plasma-x11-session` and `target not found: kwin-x11`.
KDE removed its Plasma X11 session in Plasma 6.8 during October 2026,
while the official CachyOS wiki still described the older X11 packages.
The branch now uses signed native Plasma Wayland packages, KWin
`kwin_wayland` runtime verification and QEMU virtio virtual DRM. This
is a correction to the executable package contract, **not** a relaxation
of signature or virtual-disk protections.

References:
- https://planet.kde.org/david-edmundson-2026-06-02-ex-11-prepping-for-plasmas-last-x11-supported-release/
- https://discuss.cachyos.org/t/did-kwin-x11-get-removed-from-the-repos/37201
