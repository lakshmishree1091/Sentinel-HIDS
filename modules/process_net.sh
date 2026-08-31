#!/usr/bin/env bash
# modules/process_net.sh — Module 3: Process & Network Audit
# Answers: is anything running or listening that shouldn't be?
# Data sources: /proc/[pid]/exe and /proc/[pid]/cmdline, ss (or netstat).

# hids::module_process_net — flag suspicious processes and unexpected listeners.
hids::module_process_net() {
  local pid exe d owner cmd

  # --- Walk every process via /proc; no special tools needed ---
  for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    # /proc/<pid>/exe is a symlink to the running binary on disk
    exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null)" || continue
    [[ -z "$exe" ]] && continue

    # Running from a world-writable temp dir is a classic malware tell
    for d in "${SUSPICIOUS_DIRS[@]:-/tmp /var/tmp /dev/shm}"; do
      if [[ "$exe" == "$d/"* ]]; then
        owner="$(stat -c '%U' "/proc/$pid" 2>/dev/null)"
        cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
        hids::emit_finding module=process severity=high finding=suspicious_exec \
          description="PID $pid ($owner) running from $exe" \
          technique=T1036 tactic=defense-evasion \
          details="$(jq -nc --argjson pid "$pid" --arg exe "$exe" --arg owner "$owner" --arg cmd "$cmd" \
                     '{pid:$pid,exe:$exe,owner:$owner,cmdline:$cmd}')"
      fi
    done

    # An exe symlink ending in "(deleted)" means the binary was unlinked
    # after launch — common for in-memory / fileless malware.
    if readlink "/proc/$pid/exe" 2>/dev/null | grep -q '(deleted)'; then
      hids::emit_finding module=process severity=high finding=deleted_exe \
        description="PID $pid is running from a deleted executable" \
        technique=T1620 tactic=defense-evasion \
        details="$(jq -nc --argjson pid "$pid" '{pid:$pid}')"
    fi
  done

  # --- Listening ports vs baseline ---
  local ports new_ports p
  if command -v ss >/dev/null 2>&1; then
    # -t tcp -u udp -l listening -n numeric -H no header; column 5 is Local Address:Port
    ports="$(ss -tulnH 2>/dev/null | awk '{print $5}' | sed 's/.*://' | grep -E '^[0-9]+$' | sort -un)"
  else
    ports="$(netstat -tuln 2>/dev/null | awk 'NR>2{print $4}' | sed 's/.*://' | grep -E '^[0-9]+$' | sort -un)"
  fi
  new_ports="$(printf '%s\n' "$ports" | hids::baseline_new_items listening_ports)"
  while read -r p; do
    [[ -z "$p" ]] && continue
    hids::emit_finding module=network severity=high finding=new_listener \
      description="New listening port $p not present in baseline" \
      technique=T1571 tactic=command-and-control deviation=true \
      details="$(jq -nc --argjson port "$p" '{port:$port}')"
  done <<< "$new_ports"
}
