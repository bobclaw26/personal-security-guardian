# Personal Security Guardian

Zero-trust security monitoring for OpenClaw. Continuously monitors network ports, running processes, and git repository integrity. Detects unauthorized changes and alerts immediately.

## Quick Start

```bash
python scripts/personal_security_monitor.py
```

**First run:** Captures baselines for ports, processes, and git repos.  
**Subsequent runs:** Compares current state to baselines and alerts on deviations.

## Key Features

- 🔍 **Network Monitoring** — Detect unexpected listening ports
- 🔎 **Process Monitoring** — Alert on unknown/suspicious processes
- 🔐 **Git Integrity** — Detect tampering or unexpected commits
- 📱 **Telegram Alerts** — Instant notifications for security events
- 📝 **Append-Only Audit Log** — Immutable security trail
- ✅ **Zero-Trust Model** — Trust nothing by default, approve intentional changes

## File Structure

```
personal-security-guardian/
├── SKILL.md                     # Full documentation
├── scripts/
│   └── personal_security_monitor.py    # Monitoring agent
└── references/
    ├── security-log.md          # Append-only audit trail
    └── baselines/               # Known-good baselines (JSON)
```

## Usage

### Monitor for Deviations

```bash
python scripts/personal_security_monitor.py
```

### Approve Legitimate Changes

After reviewing a deviation and confirming it's intentional:

```bash
python scripts/personal_security_monitor.py --approve
```

Updates baselines to current state.

### Schedule Monitoring

Add to crontab for hourly checks:

```bash
0 * * * * python ~/.openclaw/skills/public/personal-security-guardian/scripts/personal_security_monitor.py
```

## Integration

Alerts are sent to Telegram (configured user). Security log is stored in the skill directory and tracked in memory.

---

**Your data. Your rules. Zero trust, always.**
