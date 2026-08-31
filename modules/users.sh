#!/usr/bin/env bash
# modules/users.sh — Module 2: User Activity
# Answers: who has been active, and does anything look off?
# Data sources: /etc/passwd, /var/log/btmp (via lastb).

# hids::module_users — detect new accounts, hidden root-equivalents, brute force.
hids::module_users() {
  # --- New user accounts (baseline diff of /etc/passwd usernames) ---
  local new_users u
  new_users="$(cut -d: -f1 /etc/passwd | hids::baseline_new_items users_list)"
  while read -r u; do
    [[ -z "$u" ]] && continue
    hids::emit_finding module=users severity=high finding=new_user \
      description="New user account '$u' not present in baseline" \
      technique=T1136 tactic=persistence deviation=true \
      details="$(jq -nc --arg u "$u" '{user:$u}')"
  done <<< "$new_users"

  # --- Any non-root account with UID 0 is a root-equivalent backdoor ---
  local root_dupes
  root_dupes="$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)"
  while read -r u; do
    [[ -z "$u" ]] && continue
    hids::emit_finding module=users severity=critical finding=uid0_account \
      description="Non-root account '$u' has UID 0 (root-equivalent)" \
      technique=T1548 tactic=privilege-escalation deviation=true \
      details="$(jq -nc --arg u "$u" '{user:$u}')"
  done <<< "$root_dupes"

  # --- Failed login bursts (needs read access to /var/log/btmp, i.e. root) ---
  if command -v lastb >/dev/null 2>&1; then
    local failed
    # count data lines from lastb; empty/no-access safely yields 0
    failed="$(lastb 2>/dev/null | grep -cE '^[a-zA-Z]' || echo 0)"
    if [[ "$failed" =~ ^[0-9]+$ ]] && (( failed > ${FAILED_LOGIN_THRESHOLD:-10} )); then
      hids::emit_finding module=users severity=medium finding=failed_logins \
        description="$failed failed login attempts recorded (threshold ${FAILED_LOGIN_THRESHOLD:-10})" \
        technique=T1110 tactic=credential-access \
        details="$(jq -nc --argjson n "$failed" '{failed_count:$n}')"
    fi
  fi
}
