#!/usr/bin/env bash
# Preserve the Zorin lab's public two-argument contract.
# Implementation is shared with Mint; this wrapper never selects a disk.
set -Eeuo pipefail
[[ $# -eq 2 ]] || { echo 'Usage: Zorin lab ISO SHA256' >&2; exit 1; }
exec bash auto_tests/tools/gaslux_legacy_installed_target_lab.sh zorin "$1" "$2"
