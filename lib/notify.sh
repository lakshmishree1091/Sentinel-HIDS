#!/usr/bin/env bash
# lib/notify.sh — Notification hook (Sentinel-HIDS)
#
# Separates DETECTION from NOTIFICATION. The modules detect and log; this hook
# decides whether a run is worth interrupting a human for, and how to reach them.
# Design choices (defensible in the demo):
#   * Fires ONCE per run with a SUMMARY — never one message per finding (that's
#     how alert systems get muted and ignored).
#   * Only fires at/above a severity floor (default: high) — routine info/low/
#     medium noise never pages anyone.
#   * Method is swappable: email today (msmtp), but desktop/Slack/webhook is a
#     one-function change. Nothing else in the tool knows or cares how we notify.

# hids::notify <run_start_line>
#   run_start_line = the JSON log's line count captured BEFORE this run began,
#   so we summarise only the findings this run produced.
hids::notify() {
  local run_start="${1:-0}"
  [[ "${NOTIFY_ENABLED:-1}" == "1" ]] || return 0      # master off-switch
  [[ -f "$HIDS_JSON_LOG" ]] || return 0

  local this_run
  this_run="$(tail -n +"$((run_start + 1))" "$HIDS_JSON_LOG" 2>/dev/null)"
  [[ -z "$this_run" ]] && return 0                      # nothing fired this run

  # Count findings at/above the severity floor (default: high + critical).
  local floor="${NOTIFY_MIN_SEVERITY:-high}"
  local want='"high","critical"'
  [[ "$floor" == "critical" ]] && want='"critical"'

  local n_crit n_high
  n_crit="$(printf '%s\n' "$this_run" | jq -r 'select(.severity=="critical") | .severity' | grep -c . || true)"
  n_high="$(printf '%s\n' "$this_run" | jq -r 'select(.severity=="high")     | .severity' | grep -c . || true)"

  local n_alert=$(( n_crit + n_high ))
  [[ "$floor" == "critical" ]] && n_alert=$n_crit
  (( n_alert > 0 )) || return 0                         # nothing serious enough

  # Build a readable summary: one line per qualifying finding.
  local jq_filter='select(.severity=="high" or .severity=="critical")'
  [[ "$floor" == "critical" ]] && jq_filter='select(.severity=="critical")'
  local body_lines
  body_lines="$(printf '%s\n' "$this_run" \
    | jq -r "$jq_filter | \"  [\(.severity|ascii_upcase)] \(.module): \(.description)\"")"

  local subject="[Sentinel] $HIDS_HOSTNAME — $n_crit critical, $n_high high finding(s)"
  local body
  body="$(printf 'Sentinel-HIDS alert on host: %s\nTime: %s\n\nFindings this run (>= %s):\n%s\n\n-- Human log: %s\n-- JSON log:  %s\n' \
    "$HIDS_HOSTNAME" "$(date --iso-8601=seconds)" "$floor" "$body_lines" "$HIDS_LOG" "$HIDS_JSON_LOG")"

  # --- The swappable part: how we actually deliver. Default = email via msmtp.
  case "${NOTIFY_METHOD:-email}" in
    email)
      if [[ -z "${NOTIFY_EMAIL_TO:-}" ]]; then
        hids::log warn "notify: NOTIFY_EMAIL_TO not set in config; skipping email"
        return 0
      fi
      if ! command -v msmtp >/dev/null 2>&1; then
        hids::log warn "notify: msmtp not installed; skipping email"
        return 0
      fi
      printf 'To: %s\nSubject: %s\n\n%s\n' "$NOTIFY_EMAIL_TO" "$subject" "$body" \
                | msmtp ${NOTIFY_MSMTP_CONFIG:+-C "$NOTIFY_MSMTP_CONFIG"} "$NOTIFY_EMAIL_TO" \
        && hids::log info "notify: alert email sent to $NOTIFY_EMAIL_TO" \
        || hids::log warn "notify: msmtp failed (see ~/.msmtp.log)"
      ;;
    *)
      hids::log warn "notify: unknown NOTIFY_METHOD '${NOTIFY_METHOD}'"
      ;;
  esac
}
