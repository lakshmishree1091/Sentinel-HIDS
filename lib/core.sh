#!/usr/bin/env bash
#
# lib/core.sh — Shared library for the Bash HIDS
# -----------------------------------------------
# This file is the CONTRACT for the whole project. It is the ONLY place that
# writes output (human log, JSON log, terminal). Modules never format their own
# output — they collect data and hand a finding to hids::emit_finding().
#
# Freeze the JSON schema below on Day 1. Every module builds against it.
#
# Dependencies: bash 4+, jq, coreutils. (jq is checked in hids::init.)
#
# Source this from every module:   source "$HIDS_HOME/lib/core.sh"; hids::init
#
# ---------------------------------------------------------------------------
# FROZEN FINDING SCHEMA (one JSON object per line in findings.jsonl):
# {
#   "timestamp":         "2026-08-24T14:03:21+00:00",  # ISO 8601
#   "hostname":          "web-prod-01",
#   "module":            "health|users|process|network|file_integrity",
#   "severity":          "info|low|medium|high|critical",
#   "finding":           "short_machine_id",           # stable identifier
#   "description":       "human-readable sentence",
#   "attack_technique":  "T1548",                        # MITRE ATT&CK ID or ""
#   "attack_tactic":     "privilege-escalation",         # or ""
#   "baseline_deviation": true,                           # bool
#   "details":           { ... }                          # module-specific object
# }
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# hids::init — set defaults, create dirs, verify dependencies.
# Call once at the top of your entry script (and any standalone module).
# ---------------------------------------------------------------------------
hids::init() {
  # HIDS_HOME defaults to the repo root (one level up from this lib/ dir).
  : "${HIDS_HOME:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
  : "${HIDS_LOG_DIR:=$HIDS_HOME/logs}"
  : "${HIDS_LOG:=$HIDS_LOG_DIR/hids.log}"            # human-readable operational log
  : "${HIDS_JSON_LOG:=$HIDS_LOG_DIR/findings.jsonl}" # structured findings for ELK
  : "${HIDS_BASELINE_DB:=$HIDS_HOME/baseline/baseline.db}"
  : "${HIDS_HOSTNAME:=$(hostname)}"
  : "${HIDS_COLOR:=1}"                                # set 0 to disable terminal colour

  mkdir -p "$HIDS_LOG_DIR" "$(dirname "$HIDS_BASELINE_DB")"

  # jq does all our JSON escaping — hand-rolling JSON in bash is how you get
  # broken output the moment a value contains a quote. Fail loud if it's missing.
  if ! command -v jq >/dev/null 2>&1; then
    echo "FATAL: jq is required but not installed (apt-get install jq)" >&2
    return 1
  fi
}

# ---------------------------------------------------------------------------
# hids::load_config — source an optional key=value config file so thresholds
# live outside the script. Call after hids::init. Silently no-ops if absent.
# ---------------------------------------------------------------------------
hids::load_config() {
  local cfg="${1:-${HIDS_CONFIG:-$HIDS_HOME/config/hids.conf}}"
  if [[ -f "$cfg" ]]; then
    # shellcheck disable=SC1090
    source "$cfg"
  fi
}

# ---------------------------------------------------------------------------
# _hids::colour — map a severity to an ANSI colour code (internal helper).
# ---------------------------------------------------------------------------
_hids::colour() {
  case "$1" in
    critical) printf '\033[1;31m' ;;  # bold red
    high)     printf '\033[0;31m' ;;  # red
    medium)   printf '\033[0;33m' ;;  # yellow
    low)      printf '\033[0;36m' ;;  # cyan
    *)        printf '\033[0m'    ;;  # reset / info
  esac
}

# ---------------------------------------------------------------------------
# hids::log — write an OPERATIONAL message (not a finding) to the human log
# and to stderr. Use for the tool's own status/errors, e.g. "baseline created".
# Usage: hids::log <severity> <message...>
# ---------------------------------------------------------------------------
hids::log() {
  local severity="$1"; shift
  local msg="$*"
  local ts; ts="$(date --iso-8601=seconds)"
  # Persist to the human log.
  printf '%s [%s] %s\n' "$ts" "${severity^^}" "$msg" >> "$HIDS_LOG"
  # Echo to stderr, coloured if enabled and attached to a terminal.
  if [[ "$HIDS_COLOR" == "1" && -t 2 ]]; then
    printf '%s%s [%s]\033[0m %s\n' "$(_hids::colour "$severity")" "$ts" "${severity^^}" "$msg" >&2
  else
    printf '%s [%s] %s\n' "$ts" "${severity^^}" "$msg" >&2
  fi
}

# ---------------------------------------------------------------------------
# hids::emit_finding — THE single output path for detections.
# Accepts key=value pairs so callers can't get positional order wrong.
#
# Required: module, severity, finding, description
# Optional: technique (ATT&CK ID), tactic, deviation (true/false), details (JSON)
#
# Example:
#   hids::emit_finding \
#     module=health severity=high finding=load_spike \
#     description="1-min load 12.4 exceeds baseline 2.1" \
#     technique=T1499 tactic=impact deviation=true \
#     details='{"load1":12.4,"baseline":2.1}'
# ---------------------------------------------------------------------------
hids::emit_finding() {
  local module="" severity="info" finding="" description=""
  local technique="" tactic="" deviation="false" details="{}"
  local kv key val

  # Parse key=value arguments (first '=' splits; values may contain '=').
  for kv in "$@"; do
    key="${kv%%=*}"; val="${kv#*=}"
    case "$key" in
      module)      module="$val" ;;
      severity)    severity="$val" ;;
      finding)     finding="$val" ;;
      description) description="$val" ;;
      technique)   technique="$val" ;;
      tactic)      tactic="$val" ;;
      deviation)   deviation="$val" ;;
      details)     details="$val" ;;
      *) hids::log warn "emit_finding: ignoring unknown key '$key'" ;;
    esac
  done

  # Validate severity against the allowed set; default to info if unknown.
  case "$severity" in
    info|low|medium|high|critical) : ;;
    *) hids::log warn "emit_finding: bad severity '$severity', using info"; severity="info" ;;
  esac

  # Normalise deviation to a strict JSON boolean.
  [[ "$deviation" == "true" ]] && deviation="true" || deviation="false"

  # Guard the details field: must be valid JSON or we fall back to {}.
  if ! printf '%s' "$details" | jq -e . >/dev/null 2>&1; then
    hids::log warn "emit_finding: details not valid JSON, using {}"
    details="{}"
  fi

  local ts; ts="$(date --iso-8601=seconds)"

  # Build the finding with jq so every string is safely escaped.
  local json
  json="$(jq -c -n \
    --arg ts "$ts" \
    --arg host "$HIDS_HOSTNAME" \
    --arg module "$module" \
    --arg severity "$severity" \
    --arg finding "$finding" \
    --arg description "$description" \
    --arg technique "$technique" \
    --arg tactic "$tactic" \
    --argjson deviation "$deviation" \
    --argjson details "$details" \
    '{timestamp:$ts, hostname:$host, module:$module, severity:$severity,
      finding:$finding, description:$description,
      attack_technique:$technique, attack_tactic:$tactic,
      baseline_deviation:$deviation, details:$details}')"

  # 1) Structured line for ELK ingestion.
    # 1) Structured line for the JSON log — HASH-CHAINED for tamper-evidence.
  #    Each entry embeds prev_hash = sha256 of the ENTIRE previous JSON line.
  #    Deleting or editing any past line changes its hash, which breaks the
  #    link in every line after it — so tampering can't be hidden, only exposed.
  local prev_hash="GENESIS"                      # first-ever entry has no parent
  if [[ -s "$HIDS_JSON_LOG" ]]; then
    prev_hash="$(tail -n 1 "$HIDS_JSON_LOG" | sha256sum | awk '{print $1}')"
  fi
  # Fold prev_hash into this entry (jq keeps the JSON valid and escaped).
  json="$(printf '%s' "$json" | jq -c --arg ph "$prev_hash" '. + {prev_hash:$ph}')"
  printf '%s\n' "$json" >> "$HIDS_JSON_LOG"
  # 2) Human-readable line in the operational log.
  printf '%s [%s] (%s) %s\n' "$ts" "${severity^^}" "$module" "$description" >> "$HIDS_LOG"
  # 3) Coloured terminal output so critical findings jump out during a run.
  if [[ "$HIDS_COLOR" == "1" && -t 1 ]]; then
    printf '%s[%s]\033[0m %-14s %s\n' "$(_hids::colour "$severity")" "${severity^^}" "$module" "$description"
  else
    printf '[%s] %-14s %s\n' "${severity^^}" "$module" "$description"
  fi
}

# ===========================================================================
# BASELINE STORE
# ---------------------------------------------------------------------------
# A tiny key<TAB>value database. Modules record "normal" on first run and
# compare against it afterwards, so thresholds don't have to be hardcoded.
# Keep keys simple (no tabs/newlines). Values are single-line strings.
# ===========================================================================

# hids::is_first_run — true (exit 0) if no baseline has been recorded yet.
hids::is_first_run() {
  [[ ! -s "$HIDS_BASELINE_DB" ]]
}

# hids::baseline_get <key> — print stored value; exit 1 if key is absent.
hids::baseline_get() {
  local key="$1"
  [[ -f "$HIDS_BASELINE_DB" ]] || return 1
  awk -F'\t' -v k="$key" '$1==k {print $2; f=1} END{ exit(f?0:1) }' "$HIDS_BASELINE_DB"
}

# hids::baseline_has <key> — exit 0 if the key exists in the baseline.
hids::baseline_has() {
  hids::baseline_get "$1" >/dev/null 2>&1
}

# hids::baseline_set <key> <value> — insert or update a baseline entry.
hids::baseline_set() {
  local key="$1" val="$2" tmp
  tmp="$(mktemp)"
  # Copy every line whose key differs, then append the new value (upsert).
  if [[ -f "$HIDS_BASELINE_DB" ]]; then
    awk -F'\t' -v k="$key" '$1!=k' "$HIDS_BASELINE_DB" > "$tmp"
  fi
  printf '%s\t%s\n' "$key" "$val" >> "$tmp"
  mv "$tmp" "$HIDS_BASELINE_DB"
}

# hids::baseline_new_items <key>
# Reads a newline-separated list of CURRENT items on stdin.
#   - First time this <key> is seen: records the list, prints nothing
#     (learning mode — no alerts on the very first run).
#   - Every run after: prints only the items NOT in the recorded baseline,
#     i.e. the new arrivals a module should alert on.
# Used by the user, network, and SUID checks so "new thing appeared" is
# one shared function instead of duplicated logic.
hids::baseline_new_items() {
  local key="$1" sorted_current
  sorted_current="$(sed '/^$/d' | sort -u)"
  if hids::baseline_has "$key"; then
    local baseline
    baseline="$(hids::baseline_get "$key" | tr ' ' '\n' | sed '/^$/d' | sort -u)"
    # comm -13 prints lines only in the second input (the new items).
        comm -13 <(printf '%s\n' "$baseline" | LC_ALL=C sort -u) <(printf '%s\n' "$sorted_current" | LC_ALL=C sort -u)
  else
    # Store as a single space-joined line; items must not contain spaces.
    hids::baseline_set "$key" "$(printf '%s ' $sorted_current | sed 's/ *$//')"
    hids::log info "baseline recorded: $key ($(printf '%s\n' "$sorted_current" | grep -c .) items)"
  fi
}
# ---------------------------------------------------------------------------
# hids::verify_chain — re-walk findings.jsonl and confirm the hash chain is
# intact. For each line, recompute the sha256 of the PREVIOUS line and check
# it matches the prev_hash this line recorded. Any mismatch = tampering, and
# we report the exact line where the chain broke.
# Exit 0 = intact, 1 = broken/tampered, 2 = no log yet.
# ---------------------------------------------------------------------------
hids::verify_chain() {
  local log="${1:-$HIDS_JSON_LOG}"
  if [[ ! -s "$log" ]]; then
    echo "verify: no findings log at $log (nothing to check)"
    return 2
  fi

  local lineno=0 expected="GENESIS" prev_line="" claimed actual ok=1
  while IFS= read -r line; do
    lineno=$((lineno + 1))
    # What THIS line claims its parent's hash was.
    claimed="$(printf '%s' "$line" | jq -r '.prev_hash // "MISSING"')"
    # What the parent's hash ACTUALLY is (recomputed now).
    if (( lineno == 1 )); then
      actual="GENESIS"
    else
      actual="$(printf '%s\n' "$prev_line" | sha256sum | awk '{print $1}')"
    fi
    if [[ "$claimed" != "$actual" ]]; then
      echo "verify: CHAIN BROKEN at line $lineno"
      echo "  expected prev_hash: $actual"
      echo "  recorded prev_hash: $claimed"
      echo "  → a line at or before $lineno was deleted or modified."
      ok=0
      break
    fi
    prev_line="$line"
  done < "$log"

  if (( ok == 1 )); then
    echo "verify: chain intact — all $lineno entries verified, no tampering detected."
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# Guard against being executed directly — this file is meant to be sourced.
# ---------------------------------------------------------------------------
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "lib/core.sh is a library. Source it from a module; don't run it directly." >&2
  exit 1
fi
