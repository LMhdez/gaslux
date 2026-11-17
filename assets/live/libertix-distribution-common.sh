#!/bin/bash

# Discover and validate the payload by filesystem capabilities. Distribution
# names are presentation metadata and never select an extraction code path.

distribution_squashfs_path_exists() {
    local rootfs="$1" path="$2"

    # Require the complete listed pathname, not an unrelated prefix/suffix.
    # In -ll output, ordinary files end in the pathname; symlinks instead
    # include "pathname -> destination". A substring grep accepts lookalikes.
    # Consume the full listing so pipefail also notices an unsquashfs error.
    unsquashfs -ll "$rootfs" "$path" 2>/dev/null |
        awk -v expected="squashfs-root/$path" '
            $1 ~ /^-/ && $NF == expected { found = 1 }
            $1 ~ /^l/ && NF >= 3 && $(NF - 2) == expected && $(NF - 1) == "->" {
                found = 1
            }
            END { exit !found }
        '
}

read_distribution_os_release_value() {
    local rootfs="$1" key="$2"

    unsquashfs -cat "$rootfs" etc/os-release 2>/dev/null |
        awk -F= -v expected="$key" '
            $1 == expected {
                value = substr($0, index($0, "=") + 1)
                if (value ~ /^".*"$/ || value ~ /^\047.*\047$/) {
                    value = substr(value, 2, length(value) - 2)
                }
                print value
                exit
            }
        '
}

resolve_distribution_rootfs_or_die() {
    local iso_root="$1" candidate
    local -a candidates=()

    while IFS= read -r -d '' candidate; do
        candidates+=("$candidate")
    done < <(
        find -L "$iso_root" -mindepth 2 -maxdepth 3 -type f \
            -name filesystem.squashfs -print0
    )

    if [ "${#candidates[@]}" -ne 1 ]; then
        echo "Expected exactly one filesystem.squashfs payload, found ${#candidates[@]}" >&2
        return 1
    fi
    printf '%s\n' "${candidates[0]}"
}

assert_distribution_rootfs_compatible_or_die() {
    local rootfs="$1" expected_id="$2" actual_id id_like token compatible=false

    [ -f "$rootfs" ] || {
        echo "Distribution root filesystem is missing: $rootfs" >&2
        return 1
    }
    for required in \
        etc/os-release \
        var/lib/dpkg/status \
        usr/sbin/update-grub \
        usr/sbin/update-initramfs \
        usr/bin/lsinitramfs; do
        distribution_squashfs_path_exists "$rootfs" "$required" || {
            echo "Distribution payload is missing required capability: $required" >&2
            return 1
        }
    done

    actual_id="$(read_distribution_os_release_value "$rootfs" ID)"
    id_like="$(read_distribution_os_release_value "$rootfs" ID_LIKE)"
    [[ "$actual_id" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || {
        echo "Distribution payload has an invalid or missing os-release ID" >&2
        return 1
    }
    [ "$actual_id" = "$expected_id" ] || {
        echo "Distribution identity mismatch: expected $expected_id, found $actual_id" >&2
        return 1
    }

    for token in $actual_id $id_like; do
        case "$token" in
            debian|ubuntu) compatible=true ;;
        esac
    done
    [ "$compatible" = true ] || {
        echo "Distribution payload is not in the Debian/Ubuntu family" >&2
        return 1
    }

    echo "Distribution payload verified: ID=$actual_id ID_LIKE=${id_like:-none} rootfs=$rootfs"
}

# Recheck the pinned ISO and its actual Ubuntu-family payload before any live
# resize, wipefs or mkfs operation. The later verification before extraction is
# intentionally retained to reject media changed after this read-only check.
preflight_legacy_installer_iso_or_die() {
    local iso_path="$1" expected_sha="$2" distribution_id="$3" expected_os_id="$4"
    local mountpoint="/mnt/libertix-iso-preflight" rootfs="" validated=false

    case "$distribution_id:$expected_os_id" in
        mint:linuxmint|zorin:zorin) ;;
        *)
            echo "Legacy ISO preflight rejected an unsupported distribution identity" >&2
            return 2
            ;;
    esac

    verify_file_sha256 "$iso_path" "$expected_sha" || {
        echo "Legacy ISO preflight rejected the installer SHA-256" >&2
        return 1
    }

    mkdir -p "$mountpoint" || return 1
    if findmnt -rn -M "$mountpoint" >/dev/null 2>&1; then
        echo "Legacy ISO preflight mountpoint is already in use" >&2
        return 1
    fi

    if ! mount -t iso9660 -o ro,loop,nosuid,nodev,noexec "$iso_path" "$mountpoint"; then
        echo "Legacy ISO preflight could not mount the installer image read-only" >&2
        return 1
    fi

    if rootfs="$(resolve_distribution_rootfs_or_die "$mountpoint")" &&
        assert_distribution_rootfs_compatible_or_die "$rootfs" "$expected_os_id"; then
        validated=true
    fi

    if ! umount "$mountpoint"; then
        echo "Legacy ISO preflight could not release the installer mount" >&2
        return 1
    fi
    if [ "$validated" != true ]; then
        echo "Legacy ISO preflight rejected the distribution payload" >&2
        return 1
    fi
    echo "Legacy installer ISO and distribution identity verified before Linux partition writes"
}
