#!/usr/bin/env bash
# modules/file_integrity.sh — Module 4: File Integrity
# Answers: has anything important been changed?
# Data sources: sha256sum of watched files, find for SUID bits, the canary file.

# hids::module_file_integrity — hash-watch sensitive files, plant/check the
# honeypot canary, and baseline the set of SUID binaries.
hids::module_file_integrity() {
  local f hash key stored

  # --- Watched sensitive files: baseline their hash, alert on change ---
  for f in "${WATCH_FILES[@]}"; do
    [[ -e "$f" ]] || continue
    hash="$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
    [[ -z "$hash" ]] && continue
    key="filehash:$f"
    if hids::baseline_has "$key"; then
      stored="$(hids::baseline_get "$key")"
      if [[ "$hash" != "$stored" ]]; then
        hids::emit_finding module=file_integrity severity=high finding=file_modified \
          description="Watched file $f changed since baseline" \
          technique=T1565 tactic=impact deviation=true \
          details="$(jq -nc --arg f "$f" '{file:$f}')"
        hids::baseline_set "$key" "$hash"    # re-baseline so we alert once, not forever
      fi
    else
      hids::baseline_set "$key" "$hash"       # first sighting: just learn it
    fi
  done

  # --- Honeypot canary: any change at all is a high-confidence intrusion ---
  if [[ -n "${CANARY_FILE:-}" ]]; then
    # Plant it with believable fake contents if it doesn't exist yet.
    if [[ ! -e "$CANARY_FILE" ]]; then
      mkdir -p "$(dirname "$CANARY_FILE")" 2>/dev/null
      cat > "$CANARY_FILE" 2>/dev/null <<'DECOY'
# backup SSH keys - DO NOT DELETE
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQZfakeDECOYkeyDOnotUSE root@backup
DECOY
      chmod 600 "$CANARY_FILE" 2>/dev/null
      hids::log info "planted canary: $CANARY_FILE"
    fi
    local chash ckey cstored
    chash="$(sha256sum "$CANARY_FILE" 2>/dev/null | awk '{print $1}')"
    ckey="canary:$CANARY_FILE"
    if hids::baseline_has "$ckey"; then
      cstored="$(hids::baseline_get "$ckey")"
      if [[ "$chash" != "$cstored" ]]; then
        hids::emit_finding module=file_integrity severity=critical finding=canary_tripped \
          description="Honeypot canary $CANARY_FILE was touched — high-confidence intrusion" \
          technique=T1083 tactic=discovery deviation=true \
          details="$(jq -nc --arg f "$CANARY_FILE" '{canary:$f}')"
        hids::baseline_set "$ckey" "$chash"
      fi
    else
      hids::baseline_set "$ckey" "$chash"
    fi
  fi

  # --- SUID/SGID binaries: baseline the set, alert on new non-whitelisted ones ---
  local suid new_suid s wl_file
  suid="$(find / -xdev -perm -4000 -type f 2>/dev/null | sort -u)"   # -xdev = don't cross mounts
  wl_file="$(mktemp)"
  printf '%s\n' "${SUID_WHITELIST[@]:-}" | sort -u > "$wl_file"
  # comm -23 keeps SUID paths that are NOT in the whitelist
    suid="$(comm -23 <(printf '%s\n' "$suid" | sort -u) <(sort -u "$wl_file"))"
  rm -f "$wl_file"
  new_suid="$(printf '%s\n' "$suid" | hids::baseline_new_items suid_binaries)"
  while read -r s; do
    [[ -z "$s" ]] && continue
    hids::emit_finding module=file_integrity severity=critical finding=new_suid \
      description="New SUID binary $s (not whitelisted, not in baseline)" \
      technique=T1548 tactic=privilege-escalation deviation=true \
      details="$(jq -nc --arg f "$s" '{path:$f}')"
  done <<< "$new_suid"
}
