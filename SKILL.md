---
name: personal-security-guardian
description: "Zero-trust server security monitoring and data protection for OpenClaw. Detects unauthorized ports, suspicious processes, repo changes, and delivers real-time alerts via Telegram."
metadata:
  {
    "openclaw":
      {
        "emoji": "🔐",
        "requires": { "bins": ["python3", "ss", "ps", "git"] },
      },
  }
---

# Personal Security Guardian Skill

Your server and data deserve zero-trust protection. This skill continuously monitors for unauthorized changes and alerts you instantly.

## Core Rules (Zero-Trust Operating Model)

### Golden Rules

1. **Trust Nothing by Default** — All network activity, running processes, and git changes require baseline approval
2. **Alert First, Ask Later** — Suspicious deviations trigger Telegram notifications immediately
3. **Baseline is Source of Truth** — Only approved baselines (signed by you) represent "normal"
4. **Immutable Audit Trail** — Security log is append-only; no deletions or modifications
5. **Incident Response is Mandatory** — Every alert requires investigation and documented action

### What We Monitor

- **Network Ports** — All listening TCP/UDP ports (unexpected = potential compromise)
- **Running Processes** — All processes by UID/GID (orphaned/unknown = red flag)
- **Git Repositories** — Unexpected commits, branch changes, modified history (tampering indicator)
- **File Integrity** — (Optional) checksums of critical configs
- **OpenClaw Audit** — (Optional) integration with OpenClaw system logs

## Monitoring Checklist

### Before Risky Work

- [ ] Capture baseline: `python ~/.openclaw/skills/public/personal-security-guardian/scripts/personal_security_monitor.py`
- [ ] Review security log for recent activity
- [ ] Confirm no unexpected alerts in last 24h

### During/After Work

- [ ] Run monitor again
- [ ] Compare baseline diffs — approve legitimate changes only
- [ ] Document what changed and why in security log
- [ ] Check Telegram alerts (if any)

### Weekly Maintenance

- [ ] Review security log
- [ ] Rotate baselines if OS/network changes occurred
- [ ] Update this checklist with new threats

## Alert Workflow

### Alert Triggered (New Listening Port, Unknown Process, Repo Change)

```
1. Monitor detects deviation from baseline
2. Logs event to references/security-log.md with timestamp
3. Sends Telegram alert: [SECURITY] <type> <details>
4. Awaits your investigation
```

### You Receive Alert

```
1. Investigate: "Is this expected?"
2. If YES: Approve baseline update + document reason in security log
3. If NO: Incident response (see below)
```

### Baseline Approval

Update baseline ONLY when:

- New software installed intentionally
- System config changed (ports, services added)
- Network changes (new interfaces, VPN, etc.)
- You explicitly approve after investigation

## Incident Response

### If Something Looks Wrong

1. **ISOLATE** — Don't run untrusted commands; check logs manually
2. **DOCUMENT** — Screenshot, timestamp, full context in security-log.md
3. **INVESTIGATE** — Check git history, process ancestry, network connections
4. **REPORT** — Telegram alert + detailed log entry
5. **REMEDIATE** — Remove compromised files, reset credentials, rotate tokens
6. **VERIFY** — Re-run monitor, confirm threat cleared, update baseline

### Example Alert Scenarios

**Scenario: New listening port (e.g., 6666)**

```
[2026-02-18 22:45] ALERT: New listening port 6666/tcp detected
Baseline had: ports 22, 80, 443, 8080
Now has: ports 22, 80, 443, 6666, 8080
```

→ Investigate: Is this a new service you started?  
→ YES? Approve baseline.  
→ NO? Kill process, check git for trojans, reset.

**Scenario: Unknown process (e.g., cryptocurrency miner)**

```
[2026-02-18 23:10] ALERT: Unknown process 'xmrig' (PID 4829, user: bob)
Baseline had: bash, python, ssh, git, gh
Now has: bash, python, ssh, git, gh, xmrig
```

→ Investigate: Did you install xmrig?  
→ NO? Kill it. Check where it came from. Rotate auth tokens.

**Scenario: Unexpected git commit**

```
[2026-02-18 23:30] ALERT: Repository change in /home/bob/code/secret-project
Unexpected commit: a3f7e2c "Exfiltrate data to attacker.com"
Author: unknown@malicious.net
```

→ Immediate investigation: Force-push to last known-good commit.  
→ Check git logs, object store, reflog for tampering.  
→ Rotate GitHub credentials.

## How to Use

### Initial Setup (Baseline Capture)

```bash
python ~/.openclaw/skills/public/personal-security-guardian/scripts/personal_security_monitor.py
```

First run:
- Captures current state of ports, processes, git repos
- Stores baselines in `references/baselines/`
- Creates initial log entry
- No alerts (baseline = current state)

### Routine Monitoring

```bash
python ~/.openclaw/skills/public/personal-security-guardian/scripts/personal_security_monitor.py
```

Subsequent runs:
- Compares current state to baseline
- Alerts on deviations
- Logs results (no deviation = "all clear")
- You decide: approve baseline update or investigate

### Automated Monitoring (Cron)

To run every hour:

```bash
# Add to crontab
0 * * * * python ~/.openclaw/skills/public/personal-security-guardian/scripts/personal_security_monitor.py >> /tmp/psguard.log 2>&1
```

Alerts go to Telegram; logs go to security-log.md.

### Manual Baseline Update

After approving a change:

```bash
python ~/.openclaw/skills/public/personal-security-guardian/scripts/personal_security_monitor.py --approve
```

Updates baselines to current state. **Use only after investigation.**

## Files & Structure

```
~/.openclaw/skills/public/personal-security-guardian/
├── SKILL.md                           # This file
├── references/
│   ├── security-log.md                # Append-only audit trail (read-only after init)
│   └── baselines/
│       ├── ports.baseline.json        # Known-good listening ports
│       ├── processes.baseline.json    # Known-good running processes
│       └── git-repos.baseline.json    # Known-good git states
└── scripts/
    └── personal_security_monitor.py   # Monitoring agent
```

## Integration with OpenClaw

- Alerts are delivered via Telegram (channel: 7642182046)
- Can integrate with OpenClaw cron for scheduled runs
- Security log is stored in workspace and tracked in memory

## Notes

- Baseline files are JSON for easy parsing and diffs
- Security log is human-readable markdown (append-only)
- Monitor script handles errors gracefully; never silently fails
- All timestamps are UTC
- No remote exfiltration of data (alerts stay local via Telegram)

---

**Your data. Your rules. Zero trust, always.**
