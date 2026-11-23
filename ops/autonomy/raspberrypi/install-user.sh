#!/bin/sh
# Install ONLY unprivileged systemd user timer and paused config. No sudo, no token writes.
set -eu
umask 077
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
command -v python3 >/dev/null
command -v systemctl >/dev/null
[ "$(id -u)" -ne 0 ] || { echo "Refusing root installation" >&2; exit 1; }
home=$HOME
[ -d "$home" ] || exit 1
dest="$home/.local/lib/gaslux"
units="$home/.config/systemd/user"
private="$home/.config/gaslux"
# Refuse unexpected symlink directories and existing service/script targets.
# Existing state is not overwritten: reinstallation requires explicit inspection.
for directory in "$dest" "$units" "$private"; do
    [ ! -L "$directory" ] || { echo "Refusing symlink directory: $directory" >&2; exit 1; }
done
mkdir -p "$dest" "$units" "$private"
chmod 700 "$private"
for target in "$dest/raspberrypi_scheduler.py" \
              "$units/gaslux-fallback.service" \
              "$units/gaslux-fallback.timer"; do
    if [ -e "$target" ] || [ -L "$target" ]; then
        echo "Refusing to overwrite existing file: $target" >&2
        exit 1
    fi
done
install -m 600 "$base/raspberrypi_scheduler.py" "$dest/raspberrypi_scheduler.py"
install -m 600 "$base/gaslux-fallback.service" "$units/gaslux-fallback.service"
install -m 600 "$base/gaslux-fallback.timer" "$units/gaslux-fallback.timer"
if [ ! -e "$private/raspberrypi-scheduler.json" ] && [ ! -L "$private/raspberrypi-scheduler.json" ]; then
    install -m 600 "$base/scheduler.example.json" "$private/raspberrypi-scheduler.json"
fi
systemctl --user daemon-reload
systemctl --user enable --now gaslux-fallback.timer
printf '%s\n' 'Installed and armed as systemd user timer. DEFAULT IS PAUSED.' \
  'Inspect: systemctl --user list-timers gaslux-fallback.timer' \
  'Inspect: journalctl --user -u gaslux-fallback.service -n 30 --no-pager'
