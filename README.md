# docker-monitor

> Multi-engine Docker container security audit platform with real-time runtime threat monitoring, web dashboard, and CI/CD integration.

**Test Status**:  All 17 tests passing (Verified) | **Vulnerability Scan**:  Trivy / Dockle / Syft / Grype supported

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


## Policy-as-Code (OPA) Integration

This project integrates **Open Policy Agent (OPA)** directly into the CI pipeline to enforce container security standards automatically. It doesn't just report issues—it fails the build if security policies are violated.

### How it works in the pipeline
1. The CI pipeline runs `audit.py`.
2. `audit.py` performs its usual multi-engine vulnerability scan and container structure inspection.
3. The resulting aggregated JSON report is fed into `policy_evaluator.py`, which invokes the `opa` CLI against our `.rego` policies.
4. If violations are detected, the OPA evaluator outputs them, flags the build as `FAILED`, and causes `audit.py` to exit non-zero, immediately failing the CI/CD job.
5. The policy results are then surfaced on the CyberSec Dashboard for visibility.

### How to add a new Rego policy
All policies are defined in `policies/security.rego`. To add a new rule:
1. Open `policies/security.rego`.
2. Add a new `violations[msg]` block. 
3. The input format maps directly to `reports/latest_multi_engine_summary.json`. 
4. Check for exception overrides (e.g. `not is_exception(image_key, "my_new_rule")`).
5. Assign a descriptive violation message to `msg`.

Example:
```rego
violations[msg] {
    some image_key
    image_data := input[image_key]
    not is_exception(image_key, "deny_alpine")
    
    # Custom rule logic
    startswith(image_data.config.Image, "alpine")
    msg := sprintf("[%s] deny_alpine: Alpine images are restricted", [image_key])
}
```

### Exceptions File (`policy-exceptions.yml`)
You can suppress specific rules for specific images without ignoring the whole policy engine. 
Edit `policy-exceptions.yml` to specify the exception, a documented reason, and an expiry date.

```yaml
exceptions:
  hardened:
    deny_no_resource_limits:
      reason: "Resource limits are managed externally by Kubernetes."
      expiry: "2030-01-01"
```

### Worked Example: CI Pipeline Failure

Below is an actual CI execution log showing the pipeline actively failing due to non-compliant container configurations:

```text
=== Policy-as-Code Evaluation (OPA) ===
CI Build Failed: Policy violations detected!
 - [hardened] deny_critical_cve: Contains 6 critical CVEs
 - [hardened] deny_latest_tag: Image uses the ':latest' tag (flask-app-hardened:latest)
 - [hardened] deny_latest_tag: Image uses the ':latest' tag (hardened-image:latest)
 - [hardened] deny_latest_tag: Image uses the ':latest' tag (test-hardened-image:latest)
 - [vulnerable] deny_latest_tag: Image uses the ':latest' tag (docker-monitor-vuln:latest)
 - [vulnerable] deny_latest_tag: Image uses the ':latest' tag (flask-app-vulnerable:latest)
 - [vulnerable] deny_latest_tag: Image uses the ':latest' tag (vulnerable-image:latest)
 - [vulnerable] deny_no_resource_limits: No resource limits defined in configuration
 - [vulnerable] deny_root_user: Container runs as root (no User directive)
```

## Production Deployment & TLS

When deploying the CyberSec Control Center in a production environment, you must not use the default Flask development server. Instead, use a production WSGI server like **Gunicorn** and run it behind a reverse proxy like **Nginx** to handle TLS termination.

### Why Reverse Proxy for TLS?
We implement TLS termination at the reverse proxy (Nginx) rather than inside the application (Flask/Gunicorn) because it is the industry standard for Python web applications. Nginx is highly optimized for SSL handshakes, provides robust protection against slow-client attacks, efficiently handles static files, and cleanly separates application logic from transport security.

### 1. Environment Configuration
First, copy the `.env.example` file to `.env` and set secure credentials:
```bash
cp .env.example .env
```
Ensure you have set:
* `SECRET_KEY`: A secure random string for signing session cookies and CSRF tokens.
* `APP_ENV=production`: Enforces security constraints and disables debug features.
* `DASHBOARD_AUTH_USER` & `DASHBOARD_AUTH_PASSWORD`: Required for dashboard access.

### 2. Running with Gunicorn
Start the application using Gunicorn (binding to `127.0.0.1` so it is not exposed directly):
```bash
source .venv/bin/activate
pip install gunicorn
gunicorn -w 4 -b 127.0.0.1:8080 dashboard.app:app
```

### 3. Nginx TLS Configuration
Here is an example Nginx configuration that terminates TLS (HTTPS on port 443) and forwards requests to the Gunicorn backend. It also explicitly redirects all plain HTTP requests (port 80) to HTTPS, ensuring that traffic is never served in the clear.

```nginx
server {
    listen 80;
    server_name dashboard.example.com;

    # Redirect all plain HTTP requests to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name dashboard.example.com;

    ssl_certificate /etc/letsencrypt/live/dashboard.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dashboard.example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    
    # HSTS to enforce TLS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Exposed Metrics
* `policy_violations_active`: (Gauge) Current active OPA policy violations by rule. Tracks current security state rather than total historical occurrences.

## Logging
All core components (Dashboard, Real-time Engine, Audit Script) use structured JSON logging.
- **Format:** JSON lines containing timestamp, level, logger name, message, and extra fields (e.g., event type, user, IP).
- **Location:** Logs are stored in `logs/security_monitor.log`.
- **Rotation Policy:** The log file rotates automatically at 10MB, keeping the last 5 backups (`RotatingFileHandler`).
- **Tailing Logs:** You can monitor logs using `tail -f logs/security_monitor.log | jq` to pretty-print the JSON.
- **Security:** No secrets or plaintext passwords are ever logged. Authentication failures log the username and IP only.

## Backup & Restore (Database Durability)
The system uses SQLite in `WAL` (Write-Ahead Logging) mode to ensure high concurrency and durability. However, for robust data protection, periodic backups are required.

### Backing up the Database
Do NOT simply `cp docker_monitor.db`. Instead, use the provided script which safely snapshots the database via the SQLite backup API:
```bash
./backup_db.sh
```
This creates a timestamped backup in the `backups/` directory. You can run this via `cron` safely while the application is writing.

### Restoring the Database
To restore from a backup:
```bash
./restore_db.sh backups/docker_monitor_YYYYMMDD_HHMMSS.db
```
### Production Assessment: SQLite vs Postgres
Currently, SQLite in WAL mode is sufficient for this application. The primary write workloads are:
1. Periodic audit run summaries (infrequent, low volume).
2. Real-time threat engine logging (poll frequency of 15-60 seconds, appending lightweight threat metrics).
SQLite can easily handle hundreds of concurrent reads and thousands of sequential writes per second. Since our write volume is extremely low (a few records per minute), migrating to **PostgreSQL is NOT currently necessary** and would only add operational overhead. SQLite will scale comfortably up to several gigabytes of historical data for this specific use case.
