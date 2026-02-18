#!/usr/bin/env python3
"""
Personal Security Guardian Monitor

Continuously monitors:
- Listening network ports (ss -tulpen)
- Running processes (ps aux)
- Git repository states (git status -sb)

Compares to known-good baselines and alerts on deviations.
Logs all results to references/security-log.md (append-only).
Sends Telegram alerts if --target is configured.
"""

import os
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

# Config
SCRIPT_DIR = Path(__file__).parent.parent
BASELINES_DIR = SCRIPT_DIR / "references" / "baselines"
SECURITY_LOG = SCRIPT_DIR / "references" / "security-log.md"
TELEGRAM_TARGET = "7642182046"  # Default; can be overridden

# Ensure directories exist
BASELINES_DIR.mkdir(parents=True, exist_ok=True)


def log_event(event_type: str, details: str, status: str = "OK", action: str = ""):
    """Append event to security-log.md with timestamp."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    entry = f"""
### [{timestamp}] {event_type}

**Event Type:** {event_type}  
**Details:** {details}  
**Status:** {status}  
**Action:** {action or "(none)"}
"""
    
    with open(SECURITY_LOG, "a") as f:
        f.write(entry + "\n")
    
    print(f"[LOG] {event_type}: {status}")


def send_telegram_alert(alert_text: str):
    """Send alert to Telegram (if available)."""
    try:
        # Use OpenClaw message tool via subprocess if available
        cmd = [
            "openclaw", "message", "send",
            "--to", TELEGRAM_TARGET,
            "--message", f"[SECURITY ALERT]\n{alert_text}"
        ]
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        if result.returncode == 0:
            print(f"[ALERT SENT] {alert_text[:50]}...")
        else:
            print(f"[ALERT FAILED] Could not send via OpenClaw: {result.stderr.decode()}")
    except Exception as e:
        print(f"[ALERT FAILED] {e}")


def get_listening_ports():
    """Get all listening TCP/UDP ports via ss -tulpen."""
    try:
        result = subprocess.run(
            ["ss", "-tulpen"],
            capture_output=True,
            text=True,
            check=True
        )
        
        ports = {}
        for line in result.stdout.split("\n"):
            if not line.strip() or "LISTEN" not in line:
                continue
            
            parts = line.split()
            for part in parts:
                if ":" in part and "/" in part:  # e.g., "0.0.0.0:22/tcp"
                    addr_port = part.split("/")[0]
                    proto = part.split("/")[1]
                    port = addr_port.split(":")[-1]
                    key = f"{port}/{proto.upper()}"
                    ports[key] = True
        
        return sorted(ports.keys())
    except Exception as e:
        log_event("PORTS_CHECK", f"Failed to read ports: {e}", "ERROR", "Manual review required")
        return []


def get_running_processes():
    """Get running processes (command + user + pid) via ps aux."""
    try:
        result = subprocess.run(
            ["ps", "aux"],
            capture_output=True,
            text=True,
            check=True
        )
        
        processes = {}
        for idx, line in enumerate(result.stdout.split("\n")):
            if not line.strip() or idx == 0:  # Skip header
                continue
            parts = line.split(None, 10)  # Split into ~11 fields
            if len(parts) < 11:
                continue
            
            try:
                user, pid, cmd = parts[0], parts[1], parts[10]
                pid = int(pid)  # Validate it's an integer
                key = f"{user}:{cmd.split()[0]}"  # e.g., "bob:python"
                processes[key] = pid
            except (ValueError, IndexError):
                continue
        
        return sorted(processes.keys())
    except Exception as e:
        log_event("PROCESSES_CHECK", f"Failed to read processes: {e}", "ERROR", "Manual review required")
        return []


def get_git_repos():
    """Scan common git directories and capture status."""
    git_repos = {}
    
    # Common locations
    search_paths = [
        Path.home(),
        Path.home() / "code",
        Path.home() / "projects",
        Path.home() / ".openclaw",
    ]
    
    for base_path in search_paths:
        if not base_path.exists():
            continue
        
        # Find .git directories
        for git_dir in base_path.rglob(".git"):
            repo_path = git_dir.parent
            try:
                result = subprocess.run(
                    ["git", "-C", str(repo_path), "status", "-sb"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                # Also get last commit hash
                result_hash = subprocess.run(
                    ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    status = result.stdout.strip()
                    last_commit = result_hash.stdout.strip() if result_hash.returncode == 0 else "unknown"
                    git_repos[str(repo_path)] = {
                        "status": status,
                        "last_commit": last_commit[:8]
                    }
            except Exception as e:
                print(f"[GIT] Error reading {repo_path}: {e}")
    
    return git_repos


def save_baseline(name: str, data):
    """Save baseline to JSON file."""
    baseline_file = BASELINES_DIR / f"{name}.baseline.json"
    with open(baseline_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[BASELINE] Saved {baseline_file}")


def load_baseline(name: str):
    """Load baseline from JSON file."""
    baseline_file = BASELINES_DIR / f"{name}.baseline.json"
    if not baseline_file.exists():
        return None
    
    with open(baseline_file, "r") as f:
        return json.load(f)


def compare_baselines():
    """Run full monitoring check."""
    print("\n=== Personal Security Guardian Monitor ===\n")
    
    # Get current state
    ports_now = get_listening_ports()
    procs_now = get_running_processes()
    repos_now = get_git_repos()
    
    # Load baselines
    ports_baseline = load_baseline("ports") or []
    procs_baseline = load_baseline("processes") or []
    repos_baseline = load_baseline("git-repos") or {}
    
    # First run: no baseline yet
    if not ports_baseline and not procs_baseline and not repos_baseline:
        print("[INIT] First run — creating baselines...\n")
        save_baseline("ports", ports_now)
        save_baseline("processes", procs_now)
        save_baseline("git-repos", repos_now)
        log_event(
            "BASELINE_INIT",
            f"Captured {len(ports_now)} ports, {len(procs_now)} processes, {len(repos_now)} repos",
            "OK",
            "Baselines stored and ready for monitoring"
        )
        print(f"\n✓ Baselines initialized!")
        print(f"  Ports: {len(ports_now)}")
        print(f"  Processes: {len(procs_now)}")
        print(f"  Git Repos: {len(repos_now)}")
        return
    
    # Subsequent runs: check for deviations
    alerts = []
    
    # Check ports
    ports_new = set(ports_now) - set(ports_baseline)
    ports_gone = set(ports_baseline) - set(ports_now)
    if ports_new or ports_gone:
        details = ""
        if ports_new:
            details += f"NEW: {', '.join(sorted(ports_new))}. "
        if ports_gone:
            details += f"GONE: {', '.join(sorted(ports_gone))}."
        alert = f"Network Ports Changed: {details}"
        alerts.append(alert)
        log_event("PORTS_DEVIATION", details, "ALERT", "User investigation required")
    
    # Check processes
    procs_new = set(procs_now) - set(procs_baseline)
    procs_gone = set(procs_baseline) - set(procs_now)
    if procs_new or procs_gone:
        details = ""
        if procs_new:
            details += f"NEW: {', '.join(sorted(list(procs_new)[:5]))}. "
        if procs_gone:
            details += f"GONE: {', '.join(sorted(list(procs_gone)[:5]))}."
        alert = f"Processes Changed: {details}"
        alerts.append(alert)
        log_event("PROCESSES_DEVIATION", details, "ALERT", "User investigation required")
    
    # Check git repos
    for repo_path, repo_state in repos_now.items():
        baseline_state = repos_baseline.get(repo_path)
        if baseline_state is None:
            # New repo
            alert = f"New Git Repo Detected: {repo_path}"
            alerts.append(alert)
            log_event("GIT_NEW_REPO", repo_path, "ALERT", "User approval needed")
        elif baseline_state.get("last_commit") != repo_state.get("last_commit"):
            # Unexpected commit
            alert = f"Git Repo Changed: {repo_path}\nOld: {baseline_state.get('last_commit')}\nNew: {repo_state.get('last_commit')}"
            alerts.append(alert)
            log_event("GIT_UNEXPECTED_COMMIT", f"{repo_path}: commit mismatch", "ALERT", "Immediate review required")
        elif "modified" in repo_state.get("status", "") or "ahead" in repo_state.get("status", ""):
            if "modified" in baseline_state.get("status", "") or "ahead" in baseline_state.get("status", ""):
                pass  # Expected state
            else:
                alert = f"Git Repo Status Changed: {repo_path}\nStatus: {repo_state.get('status')}"
                alerts.append(alert)
                log_event("GIT_STATUS_CHANGE", f"{repo_path}: {repo_state.get('status')}", "ALERT", "Review needed")
    
    # Report
    if alerts:
        print(f"\n⚠️  {len(alerts)} DEVIATION(S) DETECTED:\n")
        for alert in alerts:
            print(f"  - {alert}\n")
            send_telegram_alert(alert)
        
        print("\n→ Review security-log.md for details")
        print("→ Investigate and approve baseline updates when ready")
    else:
        print("\n✓ All clear — no deviations from baseline")
        log_event("MONITORING_CYCLE", "No deviations detected", "OK", "System secure")


def approve_baseline():
    """Update baselines to current state."""
    print("\n=== Approving Baseline Updates ===\n")
    
    ports_now = get_listening_ports()
    procs_now = get_running_processes()
    repos_now = get_git_repos()
    
    save_baseline("ports", ports_now)
    save_baseline("processes", procs_now)
    save_baseline("git-repos", repos_now)
    
    log_event(
        "BASELINE_UPDATE_APPROVED",
        f"Updated {len(ports_now)} ports, {len(procs_now)} processes, {len(repos_now)} repos",
        "OK",
        "Baselines are now current state"
    )
    print("\n✓ Baselines updated and approved!")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--approve":
        approve_baseline()
    else:
        compare_baselines()


if __name__ == "__main__":
    main()
