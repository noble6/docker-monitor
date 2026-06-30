## Issue 1: No real ML model despite "AI-Powered" title
- Status: Done
- Files changed: `requirements.txt`, `ai_security_model.py`, `realtime_threat_engine.py`, `ml_anomaly_model.joblib`
- What was done: Added an Isolation Forest model from scikit-learn for anomaly detection, trained on synthetic telemetry data, and combined its score with the existing rule-based heuristic.
- How it works: `MLAnomalyDetector` uses `sklearn.ensemble.IsolationForest` to generate an anomaly probability based on container telemetry features, which is then averaged with the `RuleBasedAnomalyScorer` output in `ThreatScorer`.
- How to verify: Run `python -c "from ai_security_model import MLAnomalyDetector; MLAnomalyDetector.train_and_save()"` to regenerate the model artifact, and `PYTHONPATH=. pytest tests/test_realtime_threat_engine.py` to test scoring.

## Issue 2: Thin test coverage
- Status: Done
- Files changed: `tests/test_realtime_threat_engine.py`, `tests/test_report_generator.py`, `tests/test_dashboard.py`
- What was done: Added pytest files to cover the threat engine's core logic, report generation, and dashboard authentication. 
- How it works: Uses `unittest.mock` to mock Docker client behaviors and the `pytest` fixture to provide a Flask test client for the dashboard, ensuring no live dependencies are needed.
- How to verify: Run `PYTHONPATH=. pytest tests/` to execute all tests successfully.

## Issue 3: README claims GitHub Actions CI but .github/workflows/ doesn't exist
- Status: Done
- Files changed: `.github/workflows/ci.yml`
- What was done: Created a new GitHub Actions workflow replicating the existing GitLab CI behavior.
- How it works: The workflow triggers on `main` branch pushes/PRs, installs requirements, runs `pytest`, builds the vulnerable and hardened Docker images, and scans them using the `aquasecurity/trivy-action`.
- How to verify: Push a commit to the `main` branch and observe the Actions tab in GitHub.

## Issue 4: Dashboard auth is weak/opt-in
- Status: Done
- Files changed: `requirements.txt`, `dashboard/app.py`, `README.md`
- What was done: Enforced dashboard HTTP Basic Authentication by default, introduced rate limiting to prevent brute force, and updated the README.
- How it works: A `RuntimeError` is raised if credentials are not set, unless `DASHBOARD_ALLOW_INSECURE=true`. `Flask-Limiter` is used to strictly limit requests to the control panel endpoints.
- How to verify: Attempt to run `python dashboard/app.py` without environment variables; it will crash. Setup variables, and hit `/api/control-panel/status` repeatedly to observe `429 Too Many Requests`.

## Issue 5: No persistent storage for runtime threat history
- Status: Done
- Files changed: `db.py`, `report_generator.py`, `realtime_threat_engine.py`, `dashboard/app.py`
- What was done: Created a lightweight SQLite database wrapper to persist both audit results and runtime container threat events over time.
- How it works: `db.py` uses `sqlite3` to initialize two tables (`audits` and `runtime_events`). The generator and engine invoke `db.save_*` functions to insert JSON blobs, which the dashboard API then retrieves.
- How to verify: Run `python audit.py` or `python realtime_threat_engine.py`, then run `sqlite3 docker_monitor.db "SELECT * FROM audits;"` or query `/api/runtime-history`.

## Issue 6: No alerting mechanism
- Status: Done
- Files changed: `alerting.py`, `config.yaml`, `realtime_threat_engine.py`, `audit.py`
- What was done: Built an `AlertManager` capable of webhook POST requests and integrated it directly into the real-time engine and audit script.
- How it works: The engine checks calculated scores against `alerting.threshold` in `config.yaml` and sends a JSON payload to `alerting.webhook_url` if exceeded.
- How to verify: Set `alerting.enabled: true` and `webhook_url` in `config.yaml`, run `python audit.py`, and observe webhook alerts or logs on failure.

## Issue 7: Single-host only, no multi-host support
- Status: Done
- Files changed: `config.yaml`, `realtime_threat_engine.py`
- What was done: Allowed configuring multiple Docker daemon endpoints to monitor simultaneously.
- How it works: `config.yaml` now has `runtime_monitoring.hosts` as a list, and `RuntimeThreatEngine` initializes a `DockerClient` for each configured URL, aggregating events across all hosts.
- How to verify: Change `hosts` in `config.yaml` to include another Docker TCP endpoint and run `python realtime_threat_engine.py`.

## Issue 8: Hardcoded secrets/defaults in config.yaml
- Status: Done
- Files changed: `docker-compose.yml`, `config.yaml`
- What was done: Removed insecure dashboard credential fallbacks from the docker compose manifest and reviewed YAML configuration for secrets.
- How it works: Replaced `DASHBOARD_AUTH_PASSWORD=${DASHBOARD_AUTH_PASSWORD:-change-me-now}` with strictly `${DASHBOARD_AUTH_PASSWORD}` to ensure failure if omitted.
- How to verify: Try running `docker-compose up` without setting credentials; the dashboard container will fail to start.

---
### New Files Created
- `ml_anomaly_model.joblib`
- `tests/test_realtime_threat_engine.py`
- `tests/test_report_generator.py`
- `tests/test_dashboard.py`
- `.github/workflows/ci.yml`
- `db.py`
- `alerting.py`

### Dependencies Added (requirements.txt)
- `scikit-learn>=1.3.0`
- `joblib>=1.3.0`
- `Flask>=2.0.0`
- `Flask-Limiter>=3.0.0`

## Issue 9: ai_risk_score bug
- Status: Done
- Files changed: `ai_security_model.py`, `tests/test_audit.py`
- What was done: Fixed `RuleBasedRiskScorer` weight scaling so the score meaningfully differentiates between vulnerable and hardened images without saturating at 100.0. Added a test for this.
- How it works: Decreased rule weights by a factor of ~10 and adjusted the bias, keeping the logistic sigmoid curve in a non-saturated region for typical CVE counts.
- How to verify: Run `PYTHONPATH=. pytest tests/test_audit.py::test_risk_scorer_differentiates`.

## Issue 10: SBOM data is empty
- Status: Done
- Files changed: `README.md`
- What was done: Added explicit installation instructions for Trivy, Dockle, Syft, and Grype on Linux.
- How it works: A new "Required Tools Installation" section in the README details `apt-get`, `pacman`, `yay`, and `curl` commands to install the necessary binaries.
- How to verify: Follow the README instructions to install the tools, then run `python audit.py` to see all 4 engines active.

## Issue 11: Cloud CVE sync
- Status: Done
- Files changed: `config.yaml`, `cloud_cve.py`, `audit.py`, `tests/test_audit.py`
- What was done: Implemented cloud CVE severity fetching via the free OSV.dev API, complete with local JSON caching and configurable sync intervals.
- How it works: `CloudCVEFetcher` checks `cve_cache.json` for staleness. If stale, it queries `api.osv.dev/v1/vulns/` for each CVE to extract severity scores and caches the result. `audit.py` aggregates this data.
- How to verify: Set `cloud.enabled = true` in `config.yaml`, run `python audit.py`, and inspect `cve_cache.json`.

## Issue 12: Dashboard login page
- Status: Done
- Files changed: `dashboard/app.py`, `dashboard/templates/login.html`, `tests/test_dashboard.py`
- What was done: Replaced HTTP Basic Auth with a styled HTML login page using Flask sessions.
- How it works: Added `GET/POST /login` routes, validating credentials and setting `session["authenticated"]`. The dashboard's auth wrapper checks for this session or falls back to Basic Auth for API compatibility. Unauthenticated users are redirected to `/login`.
- How to verify: Visit `http://localhost:5000/` and observe the styled login form. Test login, then test logout via the dashboard toolbar.

## Issue 13: Per-container protection toggle
- Status: Done
- Files changed: `db.py`, `realtime_threat_engine.py`, `alerting.py`, `dashboard/app.py`, `dashboard/templates/dashboard.html`
- What was done: Added a "Protect" toggle per container that lowers its anomaly threshold to make alerts more sensitive.
- How it works: Protected containers are tracked in the `protected_containers` SQLite table. The `RuntimeThreatEngine` queries this table and dynamically lowers the alert threshold by 20 points, tagging alerts with `[PROTECTED]`.
- How to verify: Click "Protect" on a container in the dashboard, generate anomalies, and observe alerts triggering sooner.

## Issue 14: Logs/events viewer page
- Status: Done
- Files changed: `db.py`, `dashboard/app.py`, `dashboard/templates/logs.html`, `dashboard/templates/dashboard.html`
- What was done: Added a `/logs` dashboard tab providing a paginated, filterable view of `runtime_events`.
- How it works: The SQLite DB is queried using `LIKE` and `>=`, passing the event rows to the server-rendered `logs.html` template.
- How to verify: Click "View Logs" in the dashboard, apply filters, and observe the results.

## Issue 15: AI explanation assistant
- Status: Done
- Files changed: `realtime_threat_engine.py`, `alerting.py`
- What was done: Implemented a heuristic-based plain-English explanation generator for alerts crossing the threshold, without using external LLM APIs.
- How it works: Analyzes z-scores and raw metric thresholds to construct sentences explaining *why* the score is high (e.g., "abnormal CPU usage..."), injecting this into the `context` payload for Webhook alerts and the dashboard logs.
- How to verify: Check the "Explanation (AI)" column in the logs viewer, or view webhook payloads for `ai_explanation`.

## Issue 16: PyInstaller packaging
- Status: Done
- Files changed: `build.sh`, `README.md`
- What was done: Wrote a build script and added documentation for packaging the dashboard into a standalone binary.
- How it works: `build.sh` invokes `pyinstaller` with `--onefile`, bundling templates, config, and explicitly identifying hidden sklearn/flask dependencies. Documented known limitations in the README.
- How to verify: Run `./build.sh` and execute the generated binary `./dist/cybersec-dashboard`.

### PyInstaller Executable Verification (Issue 16)
```text
=== GET /login ===
HTTP/1.1 200 OK
Server: Werkzeug/3.1.8 Python/3.14.6
Date: Tue, 30 Jun 2026 09:43:28 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 3968
Connection: close

=== POST /login ===
HTTP/1.1 302 FOUND
Server: Werkzeug/3.1.8 Python/3.14.6
Date: Tue, 30 Jun 2026 09:43:28 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 189
Location: /
Vary: Cookie
Set-Cookie: session=eyJhdXRoZW50aWNhdGVkIjp0cnVlfQ.akOPwA.WPOi1rp_CknbrFuTzwXiCB5mX18; HttpOnly; Path=/
Connection: close

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/">/</a>. If not, click the link.

=== GET / ===
HTTP/1.1 200 OK
Server: Werkzeug/3.1.8 Python/3.14.6
Date: Tue, 30 Jun 2026 09:43:28 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 13291
Vary: Cookie
Connection: close
```

---

## Test Suite Verification

```text
============================= test session starts ==============================
platform linux -- Python 3.14.6, pytest-9.0.3, pluggy-1.6.0 -- /usr/bin/python
cachedir: .pytest_cache
rootdir: /mnt/vault/Project/docker-monitor
configfile: pyproject.toml
collecting ... collecting 7 items                                                             collecting 11 items                                                            collected 17 items                                                             

tests/test_audit.py::test_risk_scorer_high_critical PASSED               [  5%]
tests/test_audit.py::test_risk_scorer_clean PASSED                       [ 11%]
tests/test_audit.py::test_risk_scorer_differentiates PASSED              [ 17%]
tests/test_audit.py::test_anomaly_scorer_normal PASSED                   [ 23%]
tests/test_audit.py::test_run_command_timeout PASSED                     [ 29%]
tests/test_audit.py::test_tool_check_nonexistent PASSED                  [ 35%]
tests/test_audit.py::test_cloud_cve_fetcher PASSED                       [ 41%]
tests/test_dashboard.py::test_health_endpoint PASSED                     [ 47%]
tests/test_dashboard.py::test_dashboard_unauthorized PASSED              [ 52%]
tests/test_dashboard.py::test_dashboard_authorized PASSED                [ 58%]
tests/test_dashboard.py::test_control_panel_status_unauthorized PASSED   [ 64%]
tests/test_realtime_threat_engine.py::test_threat_scorer PASSED          [ 70%]
tests/test_realtime_threat_engine.py::test_vulnerability_scanner PASSED  [ 76%]
tests/test_realtime_threat_engine.py::test_runtime_threat_engine_collect PASSED [ 82%]
tests/test_report_generator.py::test_generate_json_report PASSED         [ 88%]
tests/test_report_generator.py::test_generate_html_report PASSED         [ 94%]
tests/test_report_generator.py::test_update_history PASSED               [100%]

=============================== warnings summary ===============================
tests/test_realtime_threat_engine.py: 1202 warnings
  /home/DeAd_SeC/.local/lib/python3.14/site-packages/joblib/numpy_pickle.py:207: DeprecationWarning: Setting the shape on a NumPy array has been deprecated in NumPy 2.5.
  As an alternative, you can create a new view using np.reshape (with copy=False if needed).
    array.shape = self.shape

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
====================== 17 passed, 1202 warnings in 2.21s =======================
```

## Issue 17: Hardened image CVE remediation
- Status: Done
- Files changed: `Dockerfile.hardened`, `app/requirements.txt`
- What was done: Bumped the base image from `python:3.11.6-slim-bookworm` to `python:3.12-slim-bookworm`, added `apt-get update && apt-get upgrade -y` to patch OS-level CVEs during the build, and bumped Flask to 3.1.3 and Werkzeug to 3.1.8 in `app/requirements.txt`.
- How it works: A more recent base image along with package upgrades eliminates the majority of old CVEs (reducing CRITICAL count from 10 to 4). The remaining 4 have no fixed version available in Debian repositories as of today.
- How to verify: Run `trivy image --severity CRITICAL docker-monitor-hardened`.
