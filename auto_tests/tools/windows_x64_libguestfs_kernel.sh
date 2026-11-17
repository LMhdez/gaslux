#!/usr/bin/env bash
# Source this from an explicit GitHub-hosted disposable Windows VM job.
# Ubuntu hosted runners can boot a newer AWS kernel without shipping its
# /boot/vmlinuz image. libguestfs/supermin cannot boot that host kernel.
# Select a separately installed, complete generic kernel + matching modules.
# This does NOT switch or install the runner's executing kernel.
set -Eeuo pipefail

if [[ "${GITHUB_ACTIONS:-}" != true ||
      "${RUNNER_ENVIRONMENT:-}" != github-hosted ||
      "${RUNNER_OS:-}" != Linux ||
      "${GITHUB_REPOSITORY:-}" != LMhdez/gaslux ||
      "${RUNNER_TEMP:-}" != /home/runner/work/_temp ]]; then
  echo "GASLUX_GUESTFS_KERNEL_GATE_FAILED: non-hosted runner" >&2
  return 1 2>/dev/null || exit 1
fi
if [[ -z "${GITHUB_ENV:-}" || ! -f "$GITHUB_ENV" || -L "$GITHUB_ENV" ]]; then
  echo "GASLUX_GUESTFS_KERNEL_GATE_FAILED: no owned Actions environment" >&2
  return 1 2>/dev/null || exit 1
fi

versions=()
for candidate in /boot/vmlinuz-*-generic; do
  [[ -f "$candidate" && ! -L "$candidate" ]] || continue
  version="${candidate##*/vmlinuz-}"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-generic$ ]] || continue
  modules="/lib/modules/$version"
  [[ -d "$modules" && ! -L "$modules" && -f "$modules/modules.dep" ]] || continue
  [[ "$(stat -c '%u' "$candidate")" == 0 ]] || continue
  versions+=("$version")
done
if (( ${#versions[@]} == 0 )); then
  echo "GASLUX_GUESTFS_KERNEL_GATE_FAILED: no complete packaged generic kernel" >&2
  return 1 2>/dev/null || exit 1
fi

version="$(printf '%s\n' "${versions[@]}" | sort -V | tail -n 1)"
# Ubuntu installs /boot/vmlinuz-* as root:root 0600, so an unprivileged
# GitHub runner cannot let supermin copy that image even when modules exist.
# Never chmod /boot or run guestfish as root. Copy ONLY this packaged kernel
# into the current runner's private ephemeral temp directory.
kernel_dir="$(mktemp -d "$RUNNER_TEMP/gaslux-guestfs-kernel-XXXXXXXX")"
chmod 700 "$kernel_dir"
image="$kernel_dir/vmlinuz-$version"
sudo install -m 0600 -o "$(id -u)" -g "$(id -g)" \
  "/boot/vmlinuz-$version" "$image"
if [[ ! -f "$image" || -L "$image" || ! -r "$image" ||
      "$(stat -c '%u' "$image")" != "$(id -u)" ]]; then
  echo "GASLUX_GUESTFS_KERNEL_GATE_FAILED: no private readable image" >&2
  return 1 2>/dev/null || exit 1
fi
export SUPERMIN_KERNEL="$image"
export SUPERMIN_MODULES="/lib/modules/$version"
export SUPERMIN_KERNEL_VERSION="$version"
export LIBGUESTFS_BACKEND=direct
export LIBGUESTFS_MEMSIZE=768

# In subsequent workflow steps, apply the same tested version rather than
# allowing supermin to choose the incomplete running AWS kernel again.
{
  printf 'SUPERMIN_KERNEL=%s\n' "$SUPERMIN_KERNEL"
  printf 'SUPERMIN_MODULES=%s\n' "$SUPERMIN_MODULES"
  printf 'SUPERMIN_KERNEL_VERSION=%s\n' "$SUPERMIN_KERNEL_VERSION"
  printf 'LIBGUESTFS_BACKEND=direct\nLIBGUESTFS_MEMSIZE=768\n'
} >> "$GITHUB_ENV"
echo "GASLUX_GUESTFS_APPLIANCE_KERNEL_SELECTED=$version"
