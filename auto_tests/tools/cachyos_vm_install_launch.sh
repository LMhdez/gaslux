#!/usr/bin/env bash
# VM-only, short-lived, systemd-run-generator handoff. Never installs here.
# The real installer is a distinct transient service with a long deadline.
set -Eeuo pipefail
exec >/dev/ttyS0 2>&1
[[ "$(id -u)" == 0 ]] || { echo 'GASLUX_VM_LAUNCH_REFUSED_NOT_ROOT'; exit 11; }
case "$(systemd-detect-virt --vm)" in qemu|kvm) ;; *) echo 'GASLUX_VM_LAUNCH_REFUSED_NOT_QEMU'; exit 12 ;; esac
[[ -f /run/gaslux-control/gaslux-run.sh &&
    -r /run/gaslux-control/lab.env &&
    ! -L /run/gaslux-control/gaslux-run.sh ]] || exit 13
options="$(findmnt -rn -M /run/gaslux-control -o OPTIONS)"
[[ ",$options," == *,ro,* ]] || exit 14
# systemd.run-generator's oneshot service inherits the default start timeout.
# Running long pacman-key/pacstrap inside that oneshot can terminate
# prematurely with no useful Bash exit marker. Spawn a separately supervised,
# bounded Type=simple unit and let the kernel command line oneshot return promptly.
# The independent Bash INSTALL_BEGIN marker remains mandatory.
systemd-run --no-block --unit=gaslux-vm-install   --property=Type=simple   --property=TimeoutStartSec=infinity   --property=RuntimeMaxSec=1800   --property=StandardOutput=journal+console   --property=StandardError=journal+console   /usr/bin/bash /run/gaslux-control/gaslux-run.sh
echo 'GASLUX_VM_INSTALL_UNIT_SUBMITTED'
