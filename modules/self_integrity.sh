#!/usr/bin/env bash
# modules/self_integrity.sh — Self-Integrity Check (Sentinel-HIDS)
#
# Answers the demo question: "How would an attacker evade you?"
# A common move is to DISABLE or BLIND the security tool itself — edit a
# detection module so it stops reporting, or neuter the alerting library.
# This module fingerprints Sentinel's OWN scripts on the first run and alerts
# (CRITICAL) if any of them changes afterwards, so tampering with the tool is
# itself a high-confidence detection.
#
# MITRE: T1562 (Impair Defenses) — modifying/disabling security tooling.
#
# HONEST LIMITATION: an attacker who edits THIS file first could suppress its
# own alert ("who watches the watcher"). Mitigations: the tamper-evident
# hash-chained log (Phase 2b) and running from read-only media. Worth saying
# out loud in the demo.

# hids::module_self_integrity — hash Sentinel's scripts, alert on any change.
hids::module_self_integrity() {
  # The scripts that make up the tool itself (paths relative to HIDS_HOME).
  # NOTE: we hash CODE only, not config/hids.conf — tuning a threshold is a
  # legitimate edit and shouldn't cry "tampering".
  local scripts=(
    "hids.sh"
    "lib/core.sh"
    "modules/health.sh"
    "modules/users.sh"
    "modules/process_net.sh"
    "modules/file_integrity.sh"
    "modules/correlate.sh"
    "modules/self_integrity.sh"
  )

  local rel path hash key stored
  for rel in "${scripts[@]}"; do
    path="$HIDS_HOME/$rel"
    [[ -f "$path" ]] || continue
    hash="$(sha256sum "$path" 2>/dev/null | awk '{print $1}')"
    [[ -z "$hash" ]] && continue
    key="selfhash:$rel"
    if hids::baseline_has "$key"; then
      stored="$(hids::baseline_get "$key")"
      if [[ "$hash" != "$stored" ]]; then
        hids::emit_finding module=self_integrity severity=critical finding=self_modified \
          description="Sentinel script $rel was modified since baseline — possible tool tampering" \
          technique=T1562 tactic=defense-evasion deviation=true \
          details="$(jq -nc --arg f "$rel" '{script:$f}')"
        hids::baseline_set "$key" "$hash"    # re-baseline: alert once per change
      fi
    else
      hids::baseline_set "$key" "$hash"       # first sighting: just learn it
    fi
  done
}