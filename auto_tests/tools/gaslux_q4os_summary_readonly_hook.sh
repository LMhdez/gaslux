#!/usr/bin/env bash
# EXECUTED ONLY as a hook in the pinned Q4OS 6.10 r2 official ISO lab.
# Single non-destructive Users -> Summary click in synthetic COW; NEVER Install.
# All typed account data are public fixture strings and exist only in volatile VM RAM.
set -Eeuo pipefail

[[ "${GITHUB_ACTIONS:-}" == true && "${GITHUB_REPOSITORY:-}" == "LMhdez/gaslux" ]] ||
  die "Refuse Q4OS Summary outside owned GitHub Actions lab"
[[ "${GASLUX_Q4OS_SUMMARY_READONLY:-}" == 1 &&
   "${GASLUX_Q4OS_NATIVE_COW_VIEW_ONLY:-}" == yes &&
   "${GASLUX_Q4OS_LAUNCH_INSTALLER:-}" == yes ]] ||
  die "Summary preview requires exact Q4OS lab-only consent and COW"
[[ "$native_cow_view" == yes && "$calamares_users_view_verified" == 1 &&
   "$calamares_users_view_captured" == 1 && "$calamares_cow_radio_clicked" == 1 ]] ||
  die "Summary requires previously verified Users view and synthetic partition preview"
[[ -n "${GASLUX_Q4OS_SUMMARY_READONLY_GUARD:-}" &&
   -f "$GASLUX_Q4OS_SUMMARY_READONLY_GUARD" &&
   ! -L "$GASLUX_Q4OS_SUMMARY_READONLY_GUARD" ]] ||
  die "Missing original-screenshot read-only gate"
command -v tesseract >/dev/null || die "Summary preview requires independent OCR"
test -s "$work/vnc-users-page.png" || die "Original Users screenshot unavailable"

readonly_gate="$GASLUX_Q4OS_SUMMARY_READONLY_GUARD"
python3 "$readonly_gate" pre "$work/vnc-users-page.png" ||
  die "Refuse unknown original Users screenshot"
# Coordinates derived from original 1280x800 PNGs in run #44641233701.
# Each move lands INSIDE a labelled field bounding box; never on disk buttons.
# The password is a dummy fixture and is not a user secret or actual account.
timeout 20s vncdo -s 127.0.0.1:1 move 420 198 click 1 key ctrl-a type 'Gaslux Lab' ||
  die "Could not fill disposable full name"
timeout 20s vncdo -s 127.0.0.1:1 move 420 265 click 1 key ctrl-a type gasluxlab ||
  die "Could not fill disposable user name"
timeout 20s vncdo -s 127.0.0.1:1 move 420 334 click 1 key ctrl-a type gaslux-lab-vm ||
  die "Could not fill disposable computer name"
timeout 20s vncdo -s 127.0.0.1:1 move 420 402 click 1 key ctrl-a type LabOnlySafe2026 ||
  die "Could not fill synthetic password"
timeout 20s vncdo -s 127.0.0.1:1 move 625 402 click 1 key ctrl-a type LabOnlySafe2026 ||
  die "Could not confirm synthetic password"
sleep 2
timeout 20s vncdo -s 127.0.0.1:1 capture "$work/vnc-users-dummy-filled.png" ||
  die "Could not capture filled Users screen"
python3 "$readonly_gate" filled "$work/vnc-users-page.png" "$work/vnc-users-dummy-filled.png" ||
  die "Users credentials not visibly validated; no Next click"

# Exactly ONE Next click; no Install action, regardless of post-click state.
summary_started_ms="$(date +%s%3N)"
timeout 20s vncdo -s 127.0.0.1:1 move 1002 644 click 1 ||
  die "Single synthetic Users Next click failed"
summary_verified=0
for summary_tick in 1 2 3 4 5 6 7 8 9 10; do
  sleep 2
  timeout 20s vncdo -s 127.0.0.1:1 capture "$work/vnc-summary-page.png" ||
    die "Cannot capture Calamares after Users Next"
  if python3 "$readonly_gate" summary "$work/vnc-users-dummy-filled.png" \
     "$work/vnc-summary-page.png" > "$work/summary-gate.txt" 2>&1; then
    summary_verified=1
    break
  fi
done
[[ "$summary_verified" == 1 ]] || {
  cat "$work/summary-gate.txt" >&2 || true
  die "Summary never passed visual inspection; no Install was clicked"
}
summary_finished_ms="$(date +%s%3N)"
summary_elapsed_ms=$((summary_finished_ms-summary_started_ms))
[[ "$summary_elapsed_ms" -gt 0 && "$summary_elapsed_ms" -lt 250000 ]] ||
  die "Summary transition elapsed time missing/implausible"
mkdir -p "$GASLUX_CANDIDATE_BOOT_EVIDENCE_DIR"
export GASLUX_Q4OS_SUMMARY_BASENAME="$work/vnc-users-dummy-filled.png"
export GASLUX_Q4OS_SUMMARY_PNG="$work/vnc-summary-page.png"
export GASLUX_Q4OS_SUMMARY_ELAPSED_MS="$summary_elapsed_ms"
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path
src = Path(os.environ["GASLUX_Q4OS_SUMMARY_BASENAME"])
dst = Path(os.environ["GASLUX_Q4OS_SUMMARY_PNG"])
root = Path(os.environ["GASLUX_CANDIDATE_BOOT_EVIDENCE_DIR"])
result = {
  "kind": "q4os-users-to-summary-readonly-cow",
  "phase": "summary-observed",
  "beforeScreenshot": "vnc-users-dummy-filled.png",
  "beforeSha256": hashlib.file_digest(src.open("rb"), "sha256").hexdigest(),
  "afterScreenshot": "vnc-summary-page.png",
  "afterSha256": hashlib.file_digest(dst.open("rb"), "sha256").hexdigest(),
  "elapsedMs": int(os.environ["GASLUX_Q4OS_SUMMARY_ELAPSED_MS"]),
  "runId": os.environ["GITHUB_RUN_ID"],
  "replica": int(os.environ["GASLUX_REPLICA"]),
  "sourceCodeCommit": "6b6d5521dbd4c2c26712fb57cb6ae5b29e0c69bb",
  "syntheticCredentialsOnly": True,
  "windowsDiskAttached": False,
  "calamaresInstallClicked": False,
  "partitionWriterAuthorized": False,
  "summaryVisualGatePassed": True,
}
(root/"summary-experiment.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
print("GASLUX_Q4OS_SUMMARY_READONLY_JSON="+json.dumps(result,sort_keys=True))
PY
echo "GASLUX_Q4OS_USERS_TO_SUMMARY_ONLY=PASS"
echo "GASLUX_Q4OS_INSTALL_CLICKED=NO"
