#!/usr/bin/env bash
# scorecard.sh — Detection Coverage Scorecard (Sentinel-HIDS, Phase 3)
#
# Runs the benign attack battery, then measures how many of the emulated
# MITRE ATT&CK techniques actually produced a detection this run, and prints
# a coverage score: "Detected X of Y (NN%)". Turns "it detects lots of
# attacks" into a measurable, provable number.
set -uo pipefail

HIDS_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export HIDS_HOME
source "$HIDS_HOME/lib/core.sh"
hids::init || exit 1
hids::load_config

# --- The attack battery: MITRE technique ID | human label ---
# Each maps to one action simulate_attack.sh performs.
battery=(
  "T1136|New user account created (persistence)"
  "T1036|Process running from /tmp (defense evasion)"
  "T1571|New listening port / backdoor (command & control)"
  "T1565|Sensitive file modified: /etc/passwd, /etc/shadow (impact)"
  "T1083|Honeypot canary tripped (discovery)"
)

echo "==================================================================="
echo " Sentinel-HIDS — Detection Coverage Scorecard"
echo "==================================================================="
echo

# 1) Clean slate, then settle to a quiet baseline so every technique can fire.
echo "[*] Resetting to a clean baseline..."
"$HIDS_HOME/simulate_attack.sh" --cleanup >/dev/null 2>&1
"$HIDS_HOME/hids.sh"                       >/dev/null 2>&1

# 2) Mark where the log ends, run the attack, then the detection pass.
before=0
[[ -f "$HIDS_JSON_LOG" ]] && before="$(wc -l < "$HIDS_JSON_LOG")"

echo "[*] Running benign attack battery..."
"$HIDS_HOME/simulate_attack.sh" >/dev/null 2>&1

echo "[*] Running detection pass..."
"$HIDS_HOME/hids.sh"            >/dev/null 2>&1
echo

# 3) Collect the technique IDs that fired during the detection pass.
fired="$(tail -n +"$((before + 1))" "$HIDS_JSON_LOG" 2>/dev/null \
          | jq -r '.attack_technique // empty' | grep -E '^T[0-9]+' | sort -u)"

# 4) Score each battery technique: fired = detected, else missed.
detected=0
total="${#battery[@]}"
printf '  %-7s %-52s %s\n' "MITRE" "Technique" "Result"
printf '  %-7s %-52s %s\n' "-----" "---------" "------"
for entry in "${battery[@]}"; do
  tid="${entry%%|*}"; label="${entry#*|}"
  if printf '%s\n' "$fired" | grep -qx "$tid"; then
    printf '  %-7s %-52s \033[0;32mDETECTED\033[0m\n' "$tid" "$label"
    detected=$((detected + 1))
  else
    printf '  %-7s %-52s \033[0;31mMISSED\033[0m\n' "$tid" "$label"
  fi
done

# 5) Headline number.
pct=$(( total > 0 ? detected * 100 / total : 0 ))
echo
echo "  -----------------------------------------------------------------"
printf '  COVERAGE: detected %d of %d techniques (%d%%)\n' "$detected" "$total" "$pct"
echo "  -----------------------------------------------------------------"
echo

# 6) Leave the machine clean.
"$HIDS_HOME/simulate_attack.sh" --cleanup >/dev/null 2>&1
"$HIDS_HOME/hids.sh"                       >/dev/null 2>&1
echo "[i] Battery = techniques the simulator emulates. Growing it (incl."
echo "    techniques the tool might MISS) is the next step, and makes the"
echo "    number even more credible."
