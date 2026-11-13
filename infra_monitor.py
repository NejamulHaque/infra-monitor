#!/usr/bin/env python3
"""
infra_monitor.py — Lightweight SRE Health, Resource & Auth Log Monitor
Checks HTTP endpoint latency/status, disk utilization thresholds, and parses
Linux authentication logs for SSH brute-force attempts into SIEM-ready JSON.
"""

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
    {"name": "Portfolio Frontend", "url": "https://nejamulhaque.vercel.app"},
    {"name": "Irus AI Health API", "url": "https://irus-ai.onrender.com/health"},
]
LATENCY_THRESHOLD_MS = 2000.0
DISK_THRESHOLD_PERCENT = 85.0
AUTH_LOG_PATH = "/var/log/auth.log"
SSH_FAIL_THRESHOLD = 5
REPORT_FILE = "infra_report.json"


# 2. HTTP Endpoint Health & Latency Check
def check_endpoints(endpoints: list[dict]) -> tuple[list[dict], bool]:
    results = []
    has_critical = False

    for target in endpoints:
        name = target["name"]
        url = target["url"]
        start = time.perf_counter()
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "SRE-InfraMonitor/1.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                status_code = resp.getcode()
                latency_ms = round((time.perf_counter() - start) * 1000, 2)
                healthy = (200 <= status_code < 300) and (
                    latency_ms <= LATENCY_THRESHOLD_MS
                )
                if not healthy:
                    has_critical = True

                results.append({
                    "service": name,
                    "url": url,
                    "status_code": status_code,
                    "latency_ms": latency_ms,
                    "state": "HEALTHY" if healthy else "DEGRADED",
                })
        except (urllib.error.URLError, TimeoutError, Exception) as exc:
            latency_ms = round((time.perf_counter() - start) * 1000, 2)
            has_critical = True
            results.append({
                "service": name,
                "url": url,
                "status_code": 0,
                "latency_ms": latency_ms,
                "state": "DOWN",
                "error": str(exc),
            })

    return results, has_critical


# 3. Local Disk Utilization Check
def check_disk_usage(path: str = "/") -> tuple[dict, bool]:
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
    }, is_critical


# 4. Security Log Parser (SSH Brute-Force Correlation)
def audit_ssh_logs(log_path: str = AUTH_LOG_PATH) -> tuple[dict, bool]:
    if not os.path.exists(log_path):
        return {
            "log_path": log_path,
            "state": "SKIPPED",
            "reason": "Log file not present on host (e.g., macOS or CI runner)",
            "flagged_ips": {},
        }, False

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
        }, False

    flagged = {
        ip: count for ip, count in ip_counts.items() if count >= SSH_FAIL_THRESHOLD
    }
    return {
        "log_path": log_path,
        "total_unique_failed_ips": len(ip_counts),
        "flagged_ips": flagged,
        "state": "ALERT" if flagged else "CLEAN",
    }, bool(flagged)


# 5. Orchestrator & Exit Code Handler
def main() -> int:
    endpoint_results, ep_crit = check_endpoints(ENDPOINTS)
    disk_result, disk_crit = check_disk_usage("/")
    ssh_result, ssh_crit = audit_ssh_logs()

    overall_critical = ep_crit or disk_crit or ssh_crit

    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "overall_status": "CRITICAL" if overall_critical else "OK",
        "endpoints": endpoint_results,
        "disk": disk_result,
        "ssh_security_audit": ssh_result,
    }

    with open(REPORT_FILE, "w", encoding="utf-8") as out:
        json.dump(report, out, indent=2)

    print(json.dumps(report, indent=2))
    return 1 if overall_critical else 0


if __name__ == "__main__":
    sys.exit(main())
