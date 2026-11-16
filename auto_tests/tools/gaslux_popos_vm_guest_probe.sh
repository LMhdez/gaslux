#!/usr/bin/env bash
# LAB-ONLY, read-only execution of the authenticated Pop!_OS native installer.
set -Eeuo pipefail
die() { printf 'GASLUX_POP_GUEST_DISTINST_FAILURE: %s\n' "$*" > /dev/ttyS0; exit 1; }
[[ $# -eq 1 && "$1" =~ ^[a-f0-9]{64}$ ]] || die 'native-agent SHA-256 missing'
[[ "$(id -u)" -eq 0 ]] || die 'guest root is required'
case "$(systemd-detect-virt --vm)" in qemu|kvm) ;; *) die 'not a disposable VM' ;; esac
[[ -r /etc/os-release ]] || die 'missing live identity'
. /etc/os-release
[[ "${ID:-}" == pop && "${VERSION_ID:-}" == 24.04 ]] || die 'wrong Pop live identity'
[[ -x /usr/bin/distinst && ! -L /usr/bin/distinst ]] || die 'distinst executable missing'
[[ "$(sha256sum /usr/bin/distinst | awk '{print $1}')" == "$1" ]] ||
  die 'live distinst hash mismatch against verified official ISO'
[[ "$(findmnt -rn -M /run/gaslux-pop-lab -o FSTYPE)" == vfat ]] ||
  die 'lab script media is not FAT'
findmnt -rn -M /run/gaslux-pop-lab -o OPTIONS | tr , '\n' | grep -qx ro ||
  die 'lab script media is not read-only'
# The sole native invocation is --help. No target disk is attached.
tmp="$(mktemp -p /run -t gaslux-distinst-help.XXXXXX)"
trap 'rm -f -- "$tmp"' EXIT
/usr/bin/distinst --help > "$tmp" 2>&1 || die 'native distinst --help failed'
grep -Fq -- '--squashfs' "$tmp" || die 'distinst CLI lacks squashfs flag'
grep -Fq -- '--block' "$tmp" || die 'distinst CLI lacks target disk flag'
printf 'GASLUX_POP_DISTINST_SHA256=%s\n' "$1" > /dev/ttyS0
printf 'GASLUX_POP_DISTINST_GUEST_READONLY_PASS=1\n' > /dev/ttyS0
