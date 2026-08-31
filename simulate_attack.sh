#!/usr/bin/env bash
# simulate_attack.sh — LAB ONLY. Performs benign, reversible actions that your
# HIDS is built to detect, so you can demo it. Every action has a matching
# cleanup. Do NOT run this on a production machine.
#
#   sudo ./simulate_attack.sh            # run the simulation
#   sudo ./simulate_attack.sh --cleanup  # undo everything
#
# Recommended demo flow:
#   ./hids.sh                     # run 1: learns baseline, plants canary
#   sudo ./simulate_attack.sh     # play the attacker
#   ./hids.sh                     # run 2: alerts fire
#   sudo ./simulate_attack.sh --cleanup
set -uo pipefail

HIDS_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Pull CANARY_FILE from the same config the HIDS uses.
# shellcheck source=/dev/null
[[ -f "$HIDS_HOME/config/hids.conf" ]] && source "$HIDS_HOME/config/hids.conf"

CANARY_FILE="${CANARY_FILE:-/root/.ssh/backup_keys}"
EVIL_BIN="/tmp/definitely_not_malware"
LISTEN_PORT=4444
FAKE_USER="hacker"
PID_FILE="/tmp/.hids_sim_listener.pid"

banner() { echo "=== $* ==="; }

# do_simulate — perform the four benign "attacker" actions.
do_simulate() {
  banner "LAB ATTACK SIMULATION (benign, reversible)"

  # 1) Trip the honeypot canary — attacker snooping for secrets.
  if [[ -e "$CANARY_FILE" ]]; then
    echo "exfiltrated $(date)" >> "$CANARY_FILE"
    echo "[+] Tripped canary: $CANARY_FILE"
  else
    echo "[!] Canary $CANARY_FILE missing — run ./hids.sh once first to plant it."
  fi

  # 2) Open a backdoor-style listener on port 4444.
  if command -v nc >/dev/null 2>&1; then
    nc -lnp "$LISTEN_PORT" >/dev/null 2>&1 &
  else
    python3 -c "import socket,time;s=socket.socket();s.setsockopt(1,2,1);s.bind(('0.0.0.0',$LISTEN_PORT));s.listen(1);time.sleep(3600)" &
  fi
  echo $! > "$PID_FILE"
  echo "[+] Opened listener on port $LISTEN_PORT (pid $(cat "$PID_FILE"))"

    # 3) Run a process from /tmp — malware-style location.
  #    We copy bash, NOT a coreutils tool: coreutils is a multi-call binary
  #    that refuses to run under an unknown filename, so a renamed /bin/sleep
  #    dies instantly and never shows up as a running process. bash runs no
  #    matter what it's called. The 'sleep 3600; true' keeps bash resident
  #    (the trailing ';true' stops bash from replacing itself with sleep),
  #    so /proc/<pid>/exe stays pointed at the /tmp path our module hunts for.
  rm -f "$EVIL_BIN" 2>/dev/null
  if cp /bin/bash "$EVIL_BIN" 2>/dev/null; then
    "$EVIL_BIN" -c 'sleep 3600; true' &
    echo "[+] Ran process from $EVIL_BIN (pid $!)"
  fi

  # 4) Create a rogue user account (needs root).
  if [[ "$(id -u)" -eq 0 ]]; then
    if useradd -M "$FAKE_USER" 2>/dev/null; then
      echo "[+] Created user '$FAKE_USER'"
    else
      echo "[!] User '$FAKE_USER' already exists (fine)"
    fi
  else
    echo "[!] Not root — skipping user creation (use sudo to include it)"
  fi

  echo
  echo "Now run ./hids.sh and watch the alerts fire."
}

# do_cleanup — reverse every action above.
do_cleanup() {
  banner "CLEANUP — reverting simulation"
  if [[ -f "$PID_FILE" ]]; then
    kill "$(cat "$PID_FILE")" 2>/dev/null && echo "[+] Killed listener"
    rm -f "$PID_FILE"
  fi
  pkill -f "$EVIL_BIN" 2>/dev/null
  rm -f "$EVIL_BIN" && echo "[+] Removed $EVIL_BIN"
  if [[ "$(id -u)" -eq 0 ]]; then
    userdel "$FAKE_USER" 2>/dev/null && echo "[+] Removed user '$FAKE_USER'"
  fi
  echo "[i] The canary keeps its tampered state; ./hids.sh re-baselines it after alerting once."
  echo "[+] Cleanup complete."
}

case "${1:-}" in
  --cleanup) do_cleanup ;;
  *)         do_simulate ;;
esac
