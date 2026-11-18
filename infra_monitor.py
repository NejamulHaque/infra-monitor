#!/usr/bin/env python3

import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

# 1. Configuration Targets & Thresholds
ENDPOINTS = [
    {
        "name": "Portfolio Frontend",
        "url": "https://nejamulhaque.vercel.app",
        "timeout": 10,
        "retries": 1,
        "cold_start_aware": False,
    },
    {
        "name": "Irus AI Health API",
        "url": "https://irus-ai.onrender.com/health",
        "timeout": 35,          # Allows Render free-tier cold start (~15-30s)
        "retries": 1,
        "cold_start_aware": True,
    },
]
LATENCY_THRESHOLD_MS = 2000.0
DISK_THRESHOLD_PERCENT = 85.0
AUTH_LOG_PATH = "/var/log/auth.log"
SSH_FAIL_THRESHOLD = 5
REPORT_FILE = "infra_report.json"


# 2. HTTP Endpoint Health & Latency Check (with Cold-Start Retry Awareness)
def check_endpoints(endpoints: list[dict]) -> tuple[list[dict], str]:
    results = []
    worst_severity = "OK"  # OK < DEGRADED < CRITICAL

    for target in endpoints:
        name = target["name"]
        url = target["url"]
        timeout = target.get("timeout", 10)
        retries = target.get("retries", 1)
        cold_start_aware = target.get("cold_start_aware", False)

        last_error = ""
        recovered = False

        for attempt in range(retries + 1):
            start = time.perf_counter()
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "SRE-InfraMonitor/1.1"}
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    status_code = resp.getcode()
                    latency_ms = round((time.perf_counter() - start) * 1000, 2)
                    is_2xx = 200 <= status_code < 300

                    if is_2xx and latency_ms <= LATENCY_THRESHOLD_MS:
                        state = "HEALTHY"
                    elif is_2xx:
                        state = "DEGRADED"
                        if worst_severity == "OK":
                            worst_severity = "DEGRADED"
                    else:
                        state = "CRITICAL"
                        worst_severity = "CRITICAL"

                    entry = {
                        "service": name,
                        "url": url,
                        "status_code": status_code,
                        "latency_ms": latency_ms,
                        "attempts": attempt + 1,
                        "state": state,
                    }
                    if state == "DEGRADED" and cold_start_aware:
                        entry["note"] = "High latency consistent with serverless/Render cold start"

                    results.append(entry)
                    recovered = True
                    break

            except (urllib.error.URLError, TimeoutError, Exception) as exc:
                last_error = str(exc)
                if attempt < retries:
                    time.sleep(2)

        if not recovered:
            latency_ms = round((time.perf_counter() - start) * 1000, 2)
            worst_severity = "CRITICAL"
            results.append({
                "service": name,
                "url": url,
                "status_code": 0,
                "latency_ms": latency_ms,
                "attempts": retries + 1,
                "state": "DOWN",
                "error": last_error,
            })

    return results, worst_severity


# 3. Local Disk Utilization Check
def check_disk_usage(path: str = "/") -> tuple[dict, str]:
    total, used, free = shutil.disk_usage(path)
    used_percent = round((used / total) * 100, 2)
    is_critical = used_percent >= DISK_THRESHOLD_PERCENT

    return {
        "mount": path,
        "total_gb": round(total / (1024**3), 2),
        "used_gb": round(used / (1024**3), 2),
        "free_gb": round(free / (1024**3), 2),
        "used_percent": used_percent,
        "state": "CRITICAL" if is_critical else "OK",
    }, ("CRITICAL" if is_critical else "OK")


# 4. Security Log Parser (SSH Brute-Force Correlation)
def audit_ssh_logs(log_path: str = AUTH_LOG_PATH) -> tuple[dict, str]:
    if not os.path.exists(log_path):
        return {
            "log_path": log_path,
            "state": "SKIPPED",
            "reason": "Log file not present on host (e.g., macOS or CI runner)",
            "flagged_ips": {},
        }, "OK"

    failed_pattern = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
    ip_counts: dict[str, int] = {}

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                match = failed_pattern.search(line)
                if match:
                    ip = match.group(1)
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
    except PermissionError:
        return {
            "log_path": log_path,
            "state": "PERMISSION_DENIED",
            "reason": "Run with sudo or read permissions on /var/log/auth.log",
            "flagged_ips": {},
        }, "OK"

    flagged = {
        ip: count for ip, count in ip_counts.items() if count >= SSH_FAIL_THRESHOLD
    }
    return {
        "log_path": log_path,
        "total_unique_failed_ips": len(ip_counts),
        "flagged_ips": flagged,
        "state": "ALERT" if flagged else "CLEAN",
    }, ("CRITICAL" if flagged else "OK")


# 5. Automated SRE Root-Cause Triage Engine
def generate_incident_triage(
    endpoints: list[dict], disk: dict, ssh_audit: dict
) -> list[dict]:
    findings = []

    for ep in endpoints:
        if ep["state"] == "DOWN":
            findings.append({
                "component": ep["service"],
                "severity": "CRITICAL",
                "probable_cause": f"Endpoint unreachable or exceeded timeout ({ep.get('error', 'unknown')}).",
                "recommended_action": "Verify upstream container status, DNS resolution, or Render/Vercel deployment logs.",
            })
        elif ep["state"] == "DEGRADED":
            findings.append({
                "component": ep["service"],
                "severity": "WARNING",
                "probable_cause": f"Response succeeded ({ep['status_code']}) but latency ({ep['latency_ms']}ms) breached {LATENCY_THRESHOLD_MS}ms SLO.",
                "recommended_action": "Check container cold-start spin-up or enable scheduled keep-warm health pings.",
            })

    if disk["state"] == "CRITICAL":
        findings.append({
            "component": f"Disk ({disk['mount']})",
            "severity": "CRITICAL",
            "probable_cause": f"Disk usage at {disk['used_percent']}% (>= {DISK_THRESHOLD_PERCENT}% threshold).",
            "recommended_action": "Prune unused Docker images/volumes (`docker system prune -af`) and rotate `/var/log`.",
        })

    if ssh_audit["state"] == "ALERT":
        findings.append({
            "component": "SSH Auth Guard",
            "severity": "CRITICAL",
            "probable_cause": f"Detected {len(ssh_audit['flagged_ips'])} IP(s) exceeding {SSH_FAIL_THRESHOLD} failed SSH logins.",
            "recommended_action": "Enforce `iptables` DROP rules via sentinel-daemon and verify PasswordAuthentication is disabled.",
        })

    return findings


# 6. Orchestrator & Exit Code Handler
def main() -> int:
    endpoint_results, ep_sev = check_endpoints(ENDPOINTS)
    disk_result, disk_sev = check_disk_usage("/")
    ssh_result, ssh_sev = audit_ssh_logs()

    severities = {ep_sev, disk_sev, ssh_sev}
    if "CRITICAL" in severities:
        overall_status = "CRITICAL"
    elif "DEGRADED" in severities:
        overall_status = "DEGRADED"
    else:
        overall_status = "OK"

    triage_notes = generate_incident_triage(endpoint_results, disk_result, ssh_result)

    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "overall_status": overall_status,
        "endpoints": endpoint_results,
        "disk": disk_result,
        "ssh_security_audit": ssh_result,
        "incident_triage": triage_notes,
    }

    with open(REPORT_FILE, "w", encoding="utf-8") as out:
        json.dump(report, out, indent=2)

    print(json.dumps(report, indent=2))
    # Exit 0 on OK or DEGRADED cold start; exit 1 only on genuine CRITICAL outage
    return 1 if overall_status == "CRITICAL" else 0


if __name__ == "__main__":
    sys.exit(main())
