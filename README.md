# `infra-monitor` — Zero-Dependency SRE Health & Security Monitor

A lightweight, zero-dependency Python 3 Site Reliability Engineering (SRE) and DevSecOps monitoring tool that audits live HTTP endpoint availability and round-trip latency, monitors disk utilization thresholds, and parses Linux authentication logs (`/var/log/auth.log`) for SSH brute-force attacks—exporting normalized, SIEM-ready JSON reports (`infra_report.json`) with POSIX exit codes for automated CI/CD and cron alerting.

[![Scheduled Monitor](https://github.com/NejamulHaque/infra-monitor/actions/workflows/monitor.yml/badge.svg)](https://github.com/NejamulHaque/infra-monitor/actions/workflows/monitor.yml)
![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Stdlib%20Only)-00FF9D?logoColor=black)

---

## 🏗️ Architecture & Execution Flow

<pre lang="mermaid">
flowchart LR
    A[GitHub Actions Cron / Linux systemd] -->|Triggers Every 6h| B[infra_monitor.py]
    B --> C[HTTP Health & Latency Probe<br/>urllib.request + perf_counter]
    B --> D[Disk Utilization Auditor<br/>shutil.disk_usage]
    B --> E[SSH Auth Log Parser<br/>re + O1 IP Hash Map]
    C --> F{Threshold / Health<br/>Breach?}
    D --> F
    E --> F
    F -->|All Healthy| G[Write infra_report.json<br/>Exit Code 0]
    F -->|Degraded / Alert| H[Write infra_report.json<br/>Exit Code 1]
    G --> I[Upload GitHub Actions Artifact]
    H --> I

    style B fill:#00E5FF,stroke:#00E5FF,color:#000
    style G fill:#00FF9D,stroke:#00FF9D,color:#000
    style H fill:#FF6B6B,stroke:#FF6B6B,color:#000
</pre>

---

## ✨ Key Engineering Features

* **Zero External Dependencies:** Built exclusively using Python's standard library (`urllib.request`, `shutil`, `re`, `json`, `time`, `sys`), allowing immediate execution on minimal Linux servers, bastion hosts, and stripped-down containers without `pip install` overhead.
* **High-Resolution Latency Profiling:** Uses `time.perf_counter()` to measure exact HTTP round-trip latency in milliseconds (`ms`) and flags endpoints exceeding `2000.0 ms` or returning non-`2xx` status codes.
* **Memory-Safe Streaming Log Correlation:** Streams `/var/log/auth.log` line-by-line with regex extraction and $O(1)$ dictionary aggregation to detect IP addresses exceeding `5` failed SSH login attempts—gracefully skipping on macOS or ephemeral CI runners where `/var/log/auth.log` is absent.
* **CI/CD & Cron Native Exit Codes:** Exits with POSIX status `0` when all checks pass and `1` when any endpoint is `DOWN`/`DEGRADED`, disk usage crosses `85%`, or SSH brute-force thresholds trigger.
* **Automated GitHub Actions Scheduling:** Includes `.github/workflows/monitor.yml` to run automated checks every 6 hours (`0 */6 * * *`) and persist `infra_report.json` via `actions/upload-artifact@v4` (`if: always()`).

---

## 📂 Repository Structure

```text
infra-monitor/
├── .github/
│   └── workflows/
│       └── monitor.yml       # Scheduled 6-hour cron & manual workflow_dispatch pipeline
├── infra_monitor.py          # Core SRE endpoint, disk & SSH security auditing engine
└── README.md                 # Documentation, architecture & sample JSON schema
```

---

## 🚀 Quick Start & Local Usage

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/NejamulHaque/infra-monitor.git](https://github.com/NejamulHaque/infra-monitor.git)
   cd infra-monitor
   ```

2. **Run the Monitor:**
   ```bash
   chmod +x infra_monitor.py
   python3 infra_monitor.py
   ```
   *(Optional: Run with `sudo python3 infra_monitor.py` on Ubuntu/Debian servers to grant read access to `/var/log/auth.log`.)*

3. **Inspect the Generated Report & Exit Code:**
   ```bash
   echo "Exit Code: $?"
   cat infra_report.json
   ```

---

## ⚙️ Threshold Configuration

Default thresholds at the top of `infra_monitor.py` can be tuned to match your SLA requirements:

| Parameter | Default Value | Description |
| :--- | :--- | :--- |
| `ENDPOINTS` | Portfolio + Irus AI `/health` | List of target service names and HTTPS URLs to probe |
| `LATENCY_THRESHOLD_MS` | `2000.0` | Maximum acceptable HTTP response time before marking `DEGRADED` |
| `DISK_THRESHOLD_PERCENT` | `85.0` | Root filesystem (`/`) utilization threshold before marking `CRITICAL` |
| `AUTH_LOG_PATH` | `/var/log/auth.log` | Path to Linux SSH authentication log file |
| `SSH_FAIL_THRESHOLD` | `5` | Minimum failed SSH password attempts per IP to trigger `ALERT` |

---

## 📄 Sample JSON Output (`infra_report.json`)

```json
{
  "timestamp_utc": "2026-11-13T10:00:00.142857+00:00",
  "overall_status": "OK",
  "endpoints": [
    {
      "service": "Portfolio Frontend",
      "url": "[https://nejamulhaque.vercel.app](https://nejamulhaque.vercel.app)",
      "status_code": 200,
      "latency_ms": 184.32,
      "state": "HEALTHY"
    },
    {
      "service": "Irus AI Health API",
      "url": "[https://irus-ai.onrender.com/health](https://irus-ai.onrender.com/health)",
      "status_code": 200,
      "latency_ms": 412.65,
      "state": "HEALTHY"
    }
  ],
  "disk": {
    "mount": "/",
    "total_gb": 72.0,
    "used_gb": 28.44,
    "free_gb": 43.56,
    "used_percent": 39.5,
    "state": "OK"
  },
  "ssh_security_audit": {
    "log_path": "/var/log/auth.log",
    "total_unique_failed_ips": 2,
    "flagged_ips": {},
    "state": "CLEAN"
  }
}
```

---

## 👤 Author

**Nejamul Haque** — DevOps, SRE & DevSecOps Engineer  
🌐 [Portfolio](https://nejamulhaque.vercel.app) · 💼 [LinkedIn](https://www.linkedin.com/in/nejamulhaque) · 🐙 [GitHub](https://github.com/NejamulHaque)
