# Bash HIDS

A Host Intrusion Detection System written in pure Bash. It watches a single
Linux machine across five areas, learns what "normal" looks like on first run,
and alerts on anything that deviates from that baseline. Findings are written
to a human-readable log and a structured JSON log.

## What it checks

| Module | Question it answers | Example detections |
|--------|---------------------|--------------------|
| System health | Is the machine healthy right now? | Load spike, low memory, full disk |
| User activity | Who's active, does anything look off? | New account, UID-0 backdoor, failed-login bursts |
| Process & network | Is anything running/listening it shouldn't? | Process from `/tmp`, deleted exe, new listening port |
| File integrity | Has anything important changed? | Modified `/etc/passwd`, new SUID binary, canary tripped |
| Alerting | What's worth flagging, and how loudly? | Severity levels, JSON + human logs |

## Requirements

- Linux (tested on Ubuntu), Bash 4+
- `jq` — `sudo apt-get install -y jq`
- Standard tools: `awk`, `sed`, `find`, `sha256sum`, `ss` (from `iproute2`)

## Layout

```
hids/
├── hids.sh                 # run this — the main entry point
├── simulate_attack.sh      # lab-only demo trigger (+ --cleanup)
├── lib/core.sh             # shared library: logging, JSON, baseline
├── modules/                # the five detection modules
├── config/hids.conf        # thresholds, watchlists, whitelists
├── baseline/baseline.db    # auto-created: the learned "normal" state
└── logs/                   # auto-created
    ├── hids.log            # human-readable log
    └── findings.jsonl      # one JSON finding per line
```

## Usage

```bash
sudo apt-get install -y jq        # one-time
chmod +x hids.sh simulate_attack.sh

sudo ./hids.sh                     # first run: learns baseline, stays quiet
sudo ./hids.sh                     # later runs: alert on anything new
```

Run as root (or `sudo`) so the tool can read `/var/log/btmp`, hash
root-owned files, and scan every process.

## Reading the output

Terminal output shows each finding with a colour-coded severity, followed by a
per-run summary counting findings by severity. The same findings are appended to:

- **`logs/hids.log`** — `TIMESTAMP [SEVERITY] (module) description`
- **`logs/findings.jsonl`** — structured JSON, one object per line

Query the JSON with `jq` (no dashboard needed):

```bash
# only critical findings
jq 'select(.severity=="critical")' logs/findings.jsonl

# count findings by module
jq -r '.module' logs/findings.jsonl | sort | uniq -c

# just the descriptions of high/critical findings
jq -r 'select(.severity=="high" or .severity=="critical") | .description' logs/findings.jsonl
```

Each finding carries a MITRE ATT&CK technique/tactic tag where relevant.

## Customising

Edit `config/hids.conf` — no need to touch the scripts:

- `HEALTH_LOAD_PER_CORE`, `HEALTH_MEM_MIN_AVAIL_PCT`, `HEALTH_DISK_MAX_PCT` — health thresholds
- `WATCH_FILES` — sensitive files to hash and watch
- `CANARY_FILE` — the honeypot decoy (auto-planted if missing)
- `SUID_WHITELIST` — known-good SUID binaries to ignore
- `SUSPICIOUS_DIRS` — directories a process should never run from

To forget the learned baseline and re-learn from scratch, delete
`baseline/baseline.db` and run again.

## Running automatically

The tool is one-shot by design; schedule it with a **systemd timer** (chosen
over cron for `Persistent=true`, which catches up missed runs, and for resource
limits). Create two unit files in `/etc/systemd/system/`:

`hids.service`
```ini
[Unit]
Description=Bash HIDS scan
[Service]
Type=oneshot
ExecStart=/opt/hids/hids.sh
```

`hids.timer`
```ini
[Unit]
Description=Run Bash HIDS every 10 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
Persistent=true
[Install]
WantedBy=timers.target
```

Then:
```bash
sudo systemctl enable --now hids.timer
systemctl list-timers hids.timer      # confirm it's scheduled
```

## Demo

```bash
sudo ./hids.sh                    # 1. learn baseline, plant canary
sudo ./simulate_attack.sh         # 2. play the attacker
sudo ./hids.sh                    # 3. alerts fire
sudo ./simulate_attack.sh --cleanup
```

## Notes / limitations

- Detection is **periodic**, not real-time: it catches changes between runs.
  A file that is read and reverted between two runs may be missed. Real-time
  file/read monitoring needs `auditd` or `inotify` — a good "future work" point.
- The baseline learns whatever state exists on first run, so run it first on a
  known-clean machine.
