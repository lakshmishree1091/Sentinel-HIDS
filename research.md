# HIDS Research

> Complete this **before writing code**. It is a reviewed deliverable.
> For each area: what did we find, *where* did we find it, and what design
> decision did it lead to? The "Design decision" lines are what the reviewers
> care about most — fill them in.

---

## 0. What separates a good monitoring tool from a bad one?

Study the reference tools and find what they have in common.

- **Wazuh** — Open-source security platform, forked from OSSEC in 2015. Agent-based:
  a lightweight agent on each host collects log data, file-integrity events, rootkit
  indicators, and config-assessment results and ships them to a central manager. The
  manager analyses them with rules and decoders, assigns severity, maps findings to
  MITRE ATT&CK, and feeds a dashboard for search and triage. Design idea worth stealing:
  *local collection, structured analysis, visual triage* — which is why we output JSON
  (the format a platform like this ingests) and tag findings with ATT&CK IDs.

- **OSSEC** — The original open-source HIDS and Wazuh's ancestor. Log analysis,
  file-integrity checking, rootkit detection, and "active response" (it can act on a
  finding, e.g. block an IP). A decoder-plus-rules engine turns raw events into
  classified, severity-rated alerts. Design idea: *don't dump raw data — decode it and
  rate it* so the operator sees meaning, not noise. Drove our severity tiers.

- **Auditd** — The Linux kernel's audit daemon. Not a full HIDS — it's the low-level,
  rule-driven framework that records syscalls and events (file access, exec, user
  actions) to `/var/log/audit/audit.log` in real time. Design idea: *kernel-level,
  real-time capture.* This is exactly the real-time file-*access* detection our periodic
  tool can't do — a `cat` of a file between two of our runs is invisible to us but caught
  by auditd. (Our honest limitation, and our top future-work item.)

- **Tripwire** — The classic file-integrity monitor. On setup it builds a baseline
  database of file hashes/attributes, then each run compares current state to that
  baseline and reports exactly what changed — and it cryptographically *signs* the
  baseline so an attacker can't quietly edit it. Design idea: *baseline plus deviation
  detection, with the baseline itself protected from tampering.* This is exactly the
  model our file-integrity module uses (hash on first run, alert on change).

**Common design choices we noticed:**
- Compare against a known-good **baseline**, not hardcoded absolute values (Tripwire's
  whole model; OSSEC/Wazuh file integrity). → drove our baseline-drift approach.
- **Structured, searchable output** rather than prose logs (Wazuh ships structured
  events to a dashboard). → drove our JSON output, which we query with `jq`.
- **Severity levels and classification** so the operator sees what matters. → drove our
  info/low/medium/high/critical tiers.
- **Real-time capture** where it counts (auditd at the syscall level). → the gap in our
  periodic design, and a future-work item.
- **Tamper-resistance** — the tool protects its own integrity (Tripwire signs its DB).
  → future work: hash our own scripts, append-only logs.
- **Noise reduction** — whitelists and tuning so the tool doesn't cry wolf. → drove our
  SUID whitelist and the honeypot canary (zero-false-positive by design).

**Our takeaway / how it shaped our design:**

A bad monitoring tool floods you until you stop reading it — the real enemy is alert
fatigue, not missing data. A good one produces *signal*: it establishes context (a
baseline) instead of firing on raw numbers, classifies findings by severity so they can
be triaged, outputs a structured format that can be stored and searched, is tunable so
false positives stay low, and can be trusted — it protects its own integrity and doesn't
fail silently. Collecting data is the easy 20%; deciding what's worth an alert is the 80%
that matters. We built toward that with baseline-relative detection, severity tiers, a
SUID whitelist, and a honeypot canary for high-confidence alerts. We keep our output as
structured JSON so it *could* feed a platform like Wazuh's Elastic dashboards later,
while staying pure Bash for this project.

---

## 1. System Health

*Question: is this system healthy right now?*

**Where Linux exposes it**
- Commands: `uptime`, `top`, `vmstat`, `free -m`, `df -h`, `iostat`, `mpstat`, `ps`
- `/proc` files:
  - `/proc/loadavg` — 1/5/15-min load averages
  - `/proc/meminfo` — total/free/available memory, swap
  - `/proc/stat` — CPU time counters (compute % over an interval)
  - `/proc/uptime` — uptime + idle time
  - `/proc/vmstat` — paging/swap activity
  - `/proc/[pid]/stat` — per-process CPU/memory

**What "normal" vs "abnormal" looks like**
- Load average relative to CPU core count (`nproc`) —
- Memory / swap pressure —
- Disk usage % per mount —

**Thresholds worth alerting on (or baseline-relative):**

**Design decision:**

---

## 2. User Activity

*Question: who has been active, and does anything look off?*

**How Linux records logins (who / when / from where)**
- Commands: `who`, `w`, `last`, `lastb`, `lastlog`, `id`, `getent passwd`
- Files:
  - `/var/log/wtmp` — successful login history (read with `last`)
  - `/var/log/btmp` — failed login attempts (read with `lastb`) → brute force
  - `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL) — auth events, sudo
  - `/etc/passwd` — accounts; `/etc/shadow` — password hashes; `/etc/sudoers` — sudo rights
  - `~/.bash_history` — command history

**What looks suspicious on a server only we manage**
- New account, especially UID 0 (check `awk -F: '$3==0' /etc/passwd`) —
- Logins from unexpected IPs / at odd hours —
- Bursts of failed logins (btmp) —
- Unexpected sudo usage —

**Design decision:**

---

## 3. Processes

*Question: is anything running that shouldn't be?*

**Full picture of what's running**
- Commands: `ps aux`, `ps -ef`, `pstree -p`, `top`, `lsof`
- `/proc/[pid]/` — live, no special tools needed:
  - `exe` — symlink to the binary (if it shows `(deleted)`, the on-disk file is gone → red flag)
  - `cmdline` — full command line as launched
  - `cwd` — working directory
  - `status` — UID/GID, parent PID, state
  - `environ` — environment variables

**What makes a process suspicious (beyond its name)**
- Running from `/tmp`, `/dev/shm`, `/var/tmp` —
- Deleted executable on disk (masquerading) —
- Owned by an unexpected user / running as root —
- High CPU/mem with no legitimate reason —
- No controlling terminal —

**Design decision:**

---

## 4. Network

*Question: is anything listening or connecting that shouldn't be?*

**How to see ports and connections**
- Commands: `ss -tulpn` (preferred), `netstat -tulpn`, `lsof -i`
- Files: `/proc/net/tcp`, `/proc/net/udp` (hex addresses/ports)

**Red flags**
- Unexpected listening port (compare to baseline of known-good ports) —
- Outbound connection to an unknown IP (possible C2 / call-home) —
- A listener on a high port owned by a non-service user (reverse shell) —

**Design decision:**

---

## 5. File Integrity

*Question: has anything important been touched that shouldn't have been?*

**Sensitive files (any unexpected change = investigate)**
- `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/*`
- `/etc/crontab`, `/etc/cron.*`, per-user crontabs
- `/root/.ssh/authorized_keys`, `~/.ssh/authorized_keys`
- `/etc/ssh/sshd_config`
- `~/.bashrc`, `~/.profile`, `/etc/ld.so.preload`

**How to detect change**
- Hashing: `sha256sum` a watchlist, store hashes, re-hash and diff (baseline)
- Recent modification: `find <path> -mtime -1`, `-newer <ref>`, `stat`
- Attributes/perms: `stat`, `getfacl`, `lsattr`

**Dangerous permission configurations**
- World-writable files/dirs: `find / -perm -0002 -type f`
- SUID/SGID binaries: `find / -perm -4000 -o -perm -2000` (whitelist the known-good set)
- Writable files owned by root but editable by others —

**Design decision (how we establish baseline + detect deviation):**

---

## 6. Logging & Alerting

*Question: what's worth flagging, and how do we communicate it?*

**Where Linux stores logs by default**
- `/var/log/syslog` (Debian) / `/var/log/messages` (RHEL) — general system
- `/var/log/auth.log` / `/var/log/secure` — authentication
- `/var/log/kern.log` — kernel
- `journalctl` — systemd journal (query with `-u`, `--since`, `-p`)

**What format professional tools use, and why format matters**
- Structured (JSON) vs prose. Why it matters:
  - Machine-parseable → can be ingested, indexed, and queried (this is why our
    output is JSON and why we ship it to Elasticsearch/Kibana).
- Our finding schema (frozen in `lib/core.sh`): timestamp, hostname, module,
  severity, finding, description, attack_technique, attack_tactic,
  baseline_deviation, details.

**Flood vs trust — avoiding alert fatigue**
- Severity levels (info / low / medium / high / critical) —
- Baseline-relative alerting instead of alerting on every value —
- Whitelists for known-good processes / ports / SUID binaries —

**Design decision:**

---

## Appendix — quick command reference we'll reuse

| Need | Command |
|------|---------|
| Load average | `cat /proc/loadavg` |
| CPU cores | `nproc` |
| Memory | `free -m` / `cat /proc/meminfo` |
| Disk | `df -h` |
| Logins | `last` / `who` / `w` |
| Failed logins | `lastb` |
| Listening ports | `ss -tulpn` |
| Running processes | `ps aux` |
| SUID binaries | `find / -perm -4000 2>/dev/null` |
| Hash a file | `sha256sum <file>` |
| Recently modified | `find <path> -mtime -1` |
