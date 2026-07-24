# 🐳 docker-monitor

> Multi-engine Docker container security audit platform with real-time runtime threat monitoring, web dashboard, and CI/CD integration.

**Test Status**: ✅ All 17 tests passing (Verified) | **Vulnerability Scan**: ✅ Trivy / Dockle / Syft / Grype supported

---

## What is this?

**docker-monitor** is an automated container security audit platform that builds, scans, and compares a vulnerable Flask image against a hardened one. It uses multiple scanning engines and runs a continuous runtime threat engine that monitors live containers for anomalous behavior using both a rule-based heuristic system and an Isolation Forest ML model.

---

## Features

- **Multi-engine scanning** — Trivy, Dockle, Syft, Grype
- **CVE deduplication** — results unified by CVE ID across engines
- **Real-time runtime monitoring** — anomaly detection via rule-based scoring (CPU, RAM, Network) combined with a pre-trained ML anomaly detector
- **Prometheus metrics endpoint** — expose dashboard and runtime metrics at `/metrics` (no authentication required for scrapers)
- **Web dashboard** — Flask + Chart.js UI with live metrics and historical data (secured with mandatory authentication)
- **CI/CD integration** — GitHub Actions and GitLab CI pipelines
- **Standalone executable distribution** — A pre-packaged single binary generated via PyInstaller
- **Cloud CVE sync & Offline Mode** — Enrichment of vulnerability data using OSV.dev (with failure resiliency and an air-gapped `--offline` option)

---

## Known Issues & Limitations (Verified)
While the project is fully functional, it has the following known caveats:
- **NumPy 2.5 Deprecation**: The `joblib` package used for ML loading raises deprecation warnings on NumPy >= 2.5. We have pinned `numpy<2.5.0` to ensure stability.
- **Standalone binary dependencies**: The standalone executable built by `build.sh` does not bundle Docker itself, so the host machine must still have the Docker daemon installed and running.
- **Hardened Image CVEs**: Despite OS-level patching, the hardened Python 3.12 slim image still retains 6 upstream critical CVEs that are unpatched in Debian repositories as of the latest build (compared to 74 in the vulnerable image).

---

## Setup & First Run

**Prerequisites:**
- Docker daemon running locally
- Python 3.10+
- (Optional but recommended) Security tools: `trivy`, `dockle`, `syft`, `grype` installed locally.

**1. Clone and Install:**
```bash
git clone https://github.com/noble6/docker-monitor.git
cd docker-monitor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**2. Setup Authentication (Required):**
The dashboard requires strict authentication. Set the credentials in your environment:
```bash
export DASHBOARD_AUTH_USER="admin"
export DASHBOARD_AUTH_PASSWORD="strongpassword123"
```

**3. Start the Platform via Docker Compose:**
```bash
docker-compose up -d
```
This starts the Vulnerable App (port 5001), Hardened App (port 5002), and the Dashboard (port 8080).

**4. Access the Dashboard:**
Navigate to `http://localhost:8080`.
Log in using the credentials you defined in Step 2. From the control panel, you can run security audits, trigger runtime threat snapshots, and view historical logs.

**5. Metrics & Prometheus Scrape:**
You can scrape metrics unauthenticated at `http://localhost:8080/metrics`.
**Scrape config example:**
```yaml
scrape_configs:
  - job_name: 'docker-monitor'
    static_configs:
      - targets: ['localhost:8080']
```
**Exposed Metrics:**
- `container_risk_score`: Container risk score (gauge, labeled by container name)
- `container_anomaly_score`: Container AI anomaly score (gauge, labeled by container name)
- `cve_count`: Count of CVEs per scan (gauge, labeled by severity)
- `audit_runs_total`: Total number of audit runs triggered
- `dashboard_auth_failures_total`: Total dashboard auth failures

**6. Offline / Air-gapped Mode:**
For environments without outbound internet access, you can disable the live OSV.dev sync and rely solely on the local `cve_cache.json` file.
Simply set the environment variable:
```bash
export OFFLINE_MODE=true
```
When enabled, live fetching is skipped and any CVE not in the local cache will default to `UNKNOWN` severity. To refresh the cache, you can copy an updated `cve_cache.json` from a connected machine to the deployment directory.

---

## Architecture Components

- `audit.py` — Multi-engine static vulnerability scanner.
- `realtime_threat_engine.py` — Runtime container threat monitor that polls the Docker API.
- `ai_security_model.py` — Houses the rule-based risk scorer and the Isolation Forest ML model for anomaly detection.
- `cloud_cve.py` — Fetches live vulnerability context from OSV.dev.
- `db.py` — Manages the SQLite database (`runtime/docker_monitor.db`) for persisting audit and event history.
- `dashboard/app.py` — The Flask-based web dashboard.
- `build.sh` — Script to package the dashboard into a standalone binary using PyInstaller.
- `k8s/` — Kubernetes deployment manifests for comparison.

---

## Development & Testing

Run the full pytest suite (from within the virtual environment):
```bash
PYTHONPATH=. pytest tests/ -v
```

---

## License

MIT License — Copyright (c) 2026 noble6 (DeAd_SeC)
