#!/usr/bin/env bash
# Minimal systemd-run bridge; no disk access or mutation in this launcher.
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || exit 11
opts="$(findmnt -rn -M /run/gaslux-control -o OPTIONS)"
[[ ",$opts," == *,ro,* ]] || exit 12
[[ -x /run/gaslux-control/gaslux-install.sh && ! -L /run/gaslux-control/gaslux-install.sh ]] || exit 13
systemd-run --no-block --unit=gaslux-cachyos-shared-root-pacstrap \
  --property=Type=oneshot \
  --property=TimeoutStartSec=infinity \
  --property=RuntimeMaxSec=3600 \
  --property=StandardOutput=journal+console \
  --property=StandardError=journal+console \
  /run/gaslux-control/gaslux-install.sh
