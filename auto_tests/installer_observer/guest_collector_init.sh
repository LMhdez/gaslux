#!/bin/sh
# Experimental, read-only Linux guest collector. No shell/command dispatch.
# Input: one bounded challenge line on the named virtio-serial port.
# Output: one result line and separate guest serial-console marker.
exec 3<>/dev/virtio-ports/gaslux.observer || exit 21
IFS=' ' read -r kind nonce session transaction vm sequence claimed_hash <&3 || exit 22
[ "$kind" = "GCL1" ] || exit 23
[ "$sequence" = "1" ] || exit 24
set -- $(sha256sum /collector)
actual_hash="$1"
[ "$actual_hash" = "$claimed_hash" ] || exit 25
boot_id=$(cat /proc/sys/kernel/random/boot_id)
[ -n "$boot_id" ] || exit 26
printf 'GASLUX_COLLECTOR_EXECUTED %s\n' "$boot_id" > /dev/ttyS0
printf 'GCR1 %s %s %s %s %s %s %s\n' "$nonce" "$session" "$transaction" "$vm" "$sequence" "$actual_hash" "$boot_id" >&3
sleep 2
