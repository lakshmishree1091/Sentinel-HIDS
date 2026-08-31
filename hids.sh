#!/usr/bin/env bash
# hids.sh — main entry point. Runs all five modules against this host and
# prints a summary of what this run found. Safe to run repeatedly.
#
#   ./hids.sh            # run all checks
#
# First run records the baseline (what "normal" looks like) and stays quiet.
# Later runs alert on anything that has changed since that baseline.
set -uo pipefail

# Resolve the repo root from this script's location so paths always work.
HIDS_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export HIDS_HOME

# Load the shared library, then set up and read config.
source "$HIDS_HOME/lib/core.sh"
hids::init || exit 1
hids::load_config

# Load the detection modules (Module 5, alerting, lives inside core.sh).
source "$HIDS_HOME/modules/health.sh"
source "$HIDS_HOME/modules/users.sh"
source "$HIDS_HOME/modules/process_net.sh"
source "$HIDS_HOME/modules/file_integrity.sh"
source "$HIDS_HOME/modules/correlate.sh"
source "$HIDS_HOME/modules/self_integrity.sh"
source "$HIDS_HOME/lib/notify.sh"

# Note where the JSON log currently ends so we can summarise THIS run only.
before=0
[[ -f "$HIDS_JSON_LOG" ]] && before="$(wc -l < "$HIDS_JSON_LOG")"

hids::log info "HIDS run started on $HIDS_HOSTNAME"

# Each module answers one question about the host.
hids::module_health
hids::module_users
hids::module_process_net
hids::module_file_integrity
# Correlation runs LAST: it reads the findings the modules just wrote this run
# and decides whether together they form a single multi-stage attack chain.
hids::module_correlate "$before"

# Self-integrity runs FIRST: verify the tool's own scripts are untampered
# before we trust anything the detection modules report this run.
hids::module_self_integrity

hids::log info "HIDS run finished"

# Notification hook: summarise this run and alert a human if anything serious
# fired. Runs after detection + correlation so it sees the full picture.
hids::notify "$before"

# --- Per-run summary: count only the findings added during this run ---
echo
echo "===== RUN SUMMARY ($(date --iso-8601=seconds)) ====="
if [[ -f "$HIDS_JSON_LOG" ]]; then
  new_findings="$(tail -n +"$((before+1))" "$HIDS_JSON_LOG")"
  if [[ -n "$new_findings" ]]; then
    printf '%s\n' "$new_findings" | jq -r '.severity' | sort | uniq -c \
      | awk '{printf "  %-10s %s\n", $2, $1}'
    total="$(printf '%s\n' "$new_findings" | grep -c .)"
    echo "  ---------------"
    echo "  total      $total finding(s) this run"
  else
    echo "  no findings — system matches baseline"
  fi
fi
echo "Human log: $HIDS_LOG"
echo "JSON log:  $HIDS_JSON_LOG"

