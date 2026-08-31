#!/usr/bin/env bash
# modules/health.sh — Module 1: System Health
# Answers: is this system healthy right now?
# Data sources: /proc/loadavg, /proc/meminfo, df. Thresholds come from config.

# hids::module_health — run all health checks and emit findings for problems.
hids::module_health() {
  # --- 1-minute load average vs CPU core count ---
  local cores load1 limit
  cores="$(nproc 2>/dev/null || echo 1)"
  load1="$(awk '{print $1}' /proc/loadavg)"                       # first field = 1-min load
  limit="$(awk -v c="$cores" -v m="${HEALTH_LOAD_PER_CORE:-2.0}" 'BEGIN{print c*m}')"
  # awk exits 0 (success) when the load exceeds the per-core limit
  if awk -v l="$load1" -v lim="$limit" 'BEGIN{exit !(l>lim)}'; then
    hids::emit_finding module=health severity=high finding=load_high \
      description="1-min load $load1 exceeds limit $limit (${cores} cores)" \
      technique=T1499 tactic=impact \
      details="$(jq -nc --argjson l "$load1" --argjson lim "$limit" --argjson c "$cores" \
                 '{load1:$l,limit:$lim,cores:$c}')"
  fi

  # --- Available memory as a percentage of total ---
  local memtotal memavail mempct
  memtotal="$(awk '/^MemTotal:/{print $2}' /proc/meminfo)"        # kB
  memavail="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)"    # kB
  mempct="$(awk -v a="$memavail" -v t="$memtotal" 'BEGIN{printf "%.1f",(a/t)*100}')"
  if awk -v p="$mempct" -v min="${HEALTH_MEM_MIN_AVAIL_PCT:-10}" 'BEGIN{exit !(p<min)}'; then
    hids::emit_finding module=health severity=medium finding=mem_low \
      description="Available memory ${mempct}% below ${HEALTH_MEM_MIN_AVAIL_PCT:-10}% threshold" \
      details="$(jq -nc --argjson p "$mempct" '{avail_pct:$p}')"
  fi

  # --- Disk usage per real filesystem (skip tmpfs/devtmpfs) ---
  local pct mount
  while read -r pct mount; do
    pct="${pct%\%}"                                                # strip trailing %
    if [[ "$pct" =~ ^[0-9]+$ ]] && (( pct > ${HEALTH_DISK_MAX_PCT:-90} )); then
      hids::emit_finding module=health severity=medium finding=disk_full \
        description="Filesystem $mount at ${pct}% (threshold ${HEALTH_DISK_MAX_PCT:-90}%)" \
        details="$(jq -nc --arg m "$mount" --argjson p "$pct" '{mount:$m,used_pct:$p}')"
    fi
  done < <(df -P -x tmpfs -x devtmpfs -x iso9660 -x squashfs -x overlay 2>/dev/null | awk 'NR>1{print $5, $6}')
}
