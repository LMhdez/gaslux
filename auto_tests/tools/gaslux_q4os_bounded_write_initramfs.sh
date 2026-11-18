#!/usr/bin/env bash
# Isolated, explicitly opted-in Q4OS synthetic COW guest only.
# Reuses the proven read-only initramfs builder without changing its default.
set -Eeuo pipefail

die() { printf 'GASLUX_Q4OS_WRITE_INITRAMFS_REFUSED=%s\n' "$*" >&2; exit 1; }
[[ "${GITHUB_ACTIONS:-}" == true &&
   "${GASLUX_Q4OS_SYNTHETIC_WRITE_LAB_ONLY:-}" == yes ]] ||
  die 'Synthetic QEMU write lab must be explicitly enabled in GitHub Actions'
[[ $# -eq 3 ]] || die 'Usage: KERNEL FRESH_ROOTFS FRESH_OUTPUT'
kernel="$1"
rootfs="$2"
output="$3"
[[ "$kernel" == /* && -f "$kernel" && ! -L "$kernel" ]] || die 'Invalid kernel'
[[ "$rootfs" == /* && ! -e "$rootfs" && ! -L "$rootfs" ]] ||
  die 'Rootfs must not exist'
[[ "$output" == /* && ! -e "$output" && ! -L "$output" ]] ||
  die 'Output must not exist'
agent="$(dirname "$0")/q4os_guest_bound_write_agent.py"
[[ -f "$agent" && ! -L "$agent" ]] || die 'Guest agent not found'

interim="$output.readonly"
[[ ! -e "$interim" && ! -L "$interim" ]] ||
  die 'Intermediate read-only archive already exists'
bash "$(dirname "$0")/gaslux_q4os_identity_initramfs.sh" \
  "$kernel" "$rootfs" "$interim"
[[ -f "$rootfs/init" && ! -L "$rootfs/init" &&
   -f "$rootfs/guest_probe.py" ]] || die 'Read-only guest image not built'
[[ "$(grep -Fxc 'exec /usr/bin/python3 /guest_probe.py' "$rootfs/init")" == 1 ]] ||
  die 'Unexpected read-only guest entrypoint'
install -m 0700 "$agent" "$rootfs/guest_write.py"
sed -i 's@^exec /usr/bin/python3 /guest_probe.py$@exec /usr/bin/python3 /guest_write.py@' "$rootfs/init"
[[ "$(grep -Fxc 'exec /usr/bin/python3 /guest_write.py' "$rootfs/init")" == 1 ]] ||
  die 'Write agent not activated'
(
  cd "$rootfs"
  find . -print0 | cpio --null --create --format=newc --quiet
) | gzip -1 > "$output"
[[ -s "$output" ]] || die 'Write initramfs is empty'
gzip -t "$output" || die 'Write initramfs gzip stream is corrupt'
rm -- "$interim"
echo 'GASLUX_Q4OS_BOUNDED_WRITE_INITRAMFS=PASS'
echo 'GASLUX_Q4OS_INSTALLER_OR_PARTITION_WRITER=NOT_INCLUDED'
