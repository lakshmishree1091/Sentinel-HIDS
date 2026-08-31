#!/usr/bin/env bash
# modules/correlate.sh — Correlation engine (Sentinel-HIDS signature feature)
#
# The four detection modules each report findings in ISOLATION. This module
# runs LAST and looks at all of THIS run's findings together, asking a
# different question: taken as a group, do they tell one attack story?
#
# It assigns each finding a risk score by severity and raises ONE combined
# "attack chain" CRITICAL alert only when BOTH are true:
#   (a) total score >= threshold      (enough weight), AND
#   (b) >= 2 DIFFERENT modules fired   (enough breadth).
#
# Rule (b) is the heart of it: a genuine intrusion touches multiple parts of
# the system (a process AND a port AND a file). Requiring two distinct modules
# stops a single event — e.g. useradd rewriting both /etc/passwd and
# /etc/shadow (two findings, one module, one action) — from masquerading as a
# multi-stage chain.

# hids::module_correlate <run_start_line>
#   run_start_line = the JSON log's line count captured BEFORE this run began,
#   so we read only the findings appended during this run.
hids::module_correlate() {
  local run_start="${1:-0}"
  [[ -f "$HIDS_JSON_LOG" ]] || return 0

  # Slice out just this run's findings (everything after run_start).
  local this_run
  this_run="$(tail -n +"$((run_start + 1))" "$HIDS_JSON_LOG")"
  [[ -z "$this_run" ]] && return 0            # nothing fired — nothing to correlate

  local score=0 sev mod fid tac pts
  local -A seen_modules=()                    # set: which modules fired
  local -A seen_tactics=()                    # set: which ATT&CK tactics appeared
  local contributors=""                       # list of finding ids that scored

  # ONE jq pass turns each JSON finding into tab-separated fields; the loop
  # then aggregates in pure bash (no jq call inside the loop).
  while IFS=$'\t' read -r sev mod fid tac; do
    case "$sev" in
      critical) pts=10 ;;
      high)     pts=5  ;;
      medium)   pts=2  ;;
      low)      pts=1  ;;
      *)        pts=0  ;;
    esac
    score=$(( score + pts ))
    [[ -n "$mod" ]] && seen_modules["$mod"]=1
    [[ -n "$tac" && "$tac" != "null" ]] && seen_tactics["$tac"]=1
    contributors+="${fid} "
  done < <(printf '%s\n' "$this_run" | jq -r '[.severity, .module, .finding, .attack_tactic] | @tsv')

  local module_count="${#seen_modules[@]}"

  # A chain needs BOTH weight (score) AND breadth (distinct modules).
  if (( score >= ${CORRELATE_SCORE_MIN:-10} )) && (( module_count >= ${CORRELATE_MODULES_MIN:-2} )); then
    local contrib_csv tactics_csv modules_csv
    contrib_csv="$(printf '%s' "$contributors"        | sed 's/ *$//' | tr ' ' ',')"
    tactics_csv="$(printf '%s ' "${!seen_tactics[@]}" | sed 's/ *$//' | tr ' ' ',')"
    modules_csv="$(printf '%s ' "${!seen_modules[@]}" | sed 's/ *$//' | tr ' ' ',')"

    # Emit through the same single output path as every other finding, so the
    # chain alert lands in the human log, the JSON log, and the terminal. Its
    # attack_technique/tactic are intentionally blank: a correlation is a
    # meta-finding spanning several techniques, not a single one — the details
    # object carries the specifics instead.
    hids::emit_finding module=correlation severity=critical finding=attack_chain \
      description="Attack chain detected (score $score across $module_count modules): $contrib_csv — multi-stage activity, likely post-exploitation" \
      deviation=true \
      details="$(jq -nc \
                  --argjson score "$score" \
                  --argjson modules "$module_count" \
                  --arg contributors "$contrib_csv" \
                  --arg module_list "$modules_csv" \
                  --arg tactics "$tactics_csv" \
                  '{score:$score, module_count:$modules, contributors:$contributors, modules:$module_list, tactics:$tactics}')"
  fi
}