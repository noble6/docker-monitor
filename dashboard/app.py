"""Security Audit Dashboard web application."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from functools import wraps
from hmac import compare_digest
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, render_template, request, send_file
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))
from logger import setup_logger

logger = setup_logger("dashboard")


DASHBOARD_DIR = Path(__file__).resolve().parent


def detect_project_root() -> Path:
    """Detect project root across local and containerized execution."""
    candidates: List[Path] = []

    env_root = os.getenv("PROJECT_ROOT")
    if env_root:
        candidates.append(Path(env_root).expanduser().resolve())

    candidates.extend([
        DASHBOARD_DIR.parent.resolve(),
        DASHBOARD_DIR.resolve(),
        Path.cwd().resolve(),
    ])

    if hasattr(sys, '_MEIPASS'):
        return Path(sys._MEIPASS)

    for candidate in candidates:
        if (candidate / "audit.py").exists() and (candidate / "realtime_threat_engine.py").exists():
            return candidate

    raise RuntimeError(
        "Unable to detect project root. Set PROJECT_ROOT to the directory containing "
        "audit.py and realtime_threat_engine.py"
    )


PROJECT_ROOT = detect_project_root()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from realtime_threat_engine import RuntimeThreatEngine


from flask import Flask, jsonify, render_template, request, send_file, session, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from prometheus_client import generate_latest, Gauge, Counter, CONTENT_TYPE_LATEST
from flask_wtf.csrf import CSRFProtect

RISK_SCORE_GAUGE = Gauge("container_risk_score", "Container risk score", ["container_name"])
ANOMALY_SCORE_GAUGE = Gauge("container_anomaly_score", "Container AI anomaly score", ["container_name"])
CVE_GAUGE = Gauge("cve_count", "Count of CVEs per scan", ["severity"])
AUDIT_RUNS = Counter("audit_runs_total", "Total number of audit runs triggered")
AUTH_FAILURES = Counter("dashboard_auth_failures_total", "Total dashboard auth failures")
POLICY_VIOLATIONS = Gauge("policy_violations_active", "Current active OPA policy violations", ["rule"])

if hasattr(sys, '_MEIPASS'):
    template_folder = os.path.join(sys._MEIPASS, 'dashboard', 'templates')
    static_folder = os.path.join(sys._MEIPASS, 'dashboard', 'static')
else:
    template_folder = str(DASHBOARD_DIR / "templates")
    static_folder = str(DASHBOARD_DIR / "static")

app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)

# Security & Session Configuration
env_secret = os.getenv("SECRET_KEY")
if not env_secret and os.getenv("APP_ENV") == "production":
    raise RuntimeError("SECRET_KEY environment variable is required in production!")
app.secret_key = env_secret or "cybersec-dev-secret-key-change-me"

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

REPORTS_DIR = PROJECT_ROOT / "reports"
RUNTIME_DIR = PROJECT_ROOT / "runtime"
AI_MODEL_FILE = PROJECT_ROOT / "ai_security_model.py"
CONTAINER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

REPORTS_DIR.mkdir(exist_ok=True)
RUNTIME_DIR.mkdir(exist_ok=True)

CONTROL_USER = os.getenv("DASHBOARD_AUTH_USER", "")
CONTROL_PASSWORD = os.getenv("DASHBOARD_AUTH_PASSWORD", "")
ALLOW_INSECURE = os.getenv("DASHBOARD_ALLOW_INSECURE", "").lower() == "true"

# Allow skipping auth during tests
if not app.config.get("TESTING", False):
    if not ALLOW_INSECURE and not (CONTROL_USER and CONTROL_PASSWORD):
        raise RuntimeError("Dashboard authentication credentials not configured! Set DASHBOARD_AUTH_USER and DASHBOARD_AUTH_PASSWORD env vars, or DASHBOARD_ALLOW_INSECURE=true for local dev.")

CONTROL_AUTH_ENABLED = bool(CONTROL_USER and CONTROL_PASSWORD)


def run_command(
    command: List[str],
    cwd: Path = PROJECT_ROOT,
    env_overrides: Optional[Dict[str, str]] = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command safely with shell disabled."""
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)

    return subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def _unauthorized_response():
    AUTH_FAILURES.inc()
    if request.path == "/" or request.path.startswith("/reports/"):
        return redirect(url_for("login"))
    return (
        jsonify({"success": False, "error": "Authentication required for dashboard control actions"}),
        401,
        {"WWW-Authenticate": 'Basic realm="Docker Security Dashboard"'},
    )


def _is_authorized() -> bool:
    if not CONTROL_AUTH_ENABLED:
        return True
        
    if session.get("authenticated"):
        return True

    auth = request.authorization
    if not auth or (auth.type or "").lower() != "basic":
        return False

    return compare_digest(auth.username or "", CONTROL_USER) and compare_digest(auth.password or "", CONTROL_PASSWORD)


def require_dashboard_auth(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if _is_authorized():
            return view_func(*args, **kwargs)
        return _unauthorized_response()

    return wrapper

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        user = request.form.get("username", "")
        pwd = request.form.get("password", "")
        if compare_digest(user, CONTROL_USER) and compare_digest(pwd, CONTROL_PASSWORD):
            from flask import session
            session["authenticated"] = True
            logger.info("Successful login", extra={"extra_fields": {"event": "login_success", "user": user, "ip": request.remote_addr}})
            return redirect(url_for("index"))
        AUTH_FAILURES.inc()
        logger.warning("Failed login attempt", extra={"extra_fields": {"event": "login_failure", "user": user, "ip": request.remote_addr}})
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("authenticated", None)
    return redirect(url_for("login"))


def list_containers() -> List[Dict[str, Any]]:
    """Return active Docker containers using docker CLI."""
    if not shutil.which("docker"):
        return []

    result = run_command(["docker", "ps", "--format", "{{json .}}"])
    if result.returncode != 0:
        return []

    containers: List[Dict[str, Any]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            containers.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return containers


def tool_status() -> Dict[str, bool]:
    """Collect available security tool status."""
    tools = ["docker", "trivy", "dockle", "syft", "grype", "python"]
    return {tool: bool(shutil.which(tool)) for tool in tools}


def runtime_engine_instance() -> RuntimeThreatEngine:
    """Create runtime engine instance for on-demand report generation."""
    return RuntimeThreatEngine(config_path=str(PROJECT_ROOT / "config.yaml"))


def runtime_summary_by_container(name: str):
    data = load_runtime_findings()
    for item in data.get("findings", []):
        if item.get("name") == name:
            return item
    return None


def load_latest_report():
    """Load the latest audit report from history."""
    history_file = REPORTS_DIR / "audit_history.json"

    if history_file.exists():
        with open(history_file, "r", encoding="utf-8") as f:
            history = json.load(f)
            if history:
                return history[-1]

    return None


def load_history():
    """Load complete historical audit data from DB, falling back to JSON if empty."""
    try:
        import db
        db_history = db.get_audit_history()
        if db_history:
            return db_history
    except Exception:
        pass

    history_file = REPORTS_DIR / "audit_history.json"
    if history_file.exists():
        with open(history_file, "r", encoding="utf-8") as f:
            return json.load(f)

    return []


def load_runtime_findings():
    """Load latest runtime threat findings."""
    runtime_file = RUNTIME_DIR / "runtime_threats_latest.json"

    if runtime_file.exists():
        with open(runtime_file, "r", encoding="utf-8") as f:
            return json.load(f)

    return {
        "generated_at": None,
        "summary": {
            "containers_monitored": 0,
            "critical_alerts": 0,
            "high_alerts": 0,
            "medium_alerts": 0,
            "low_alerts": 0,
        },
        "findings": [],
    }


@app.route("/logs")
@require_dashboard_auth
def logs_view():
    """Logs and events viewer page."""
    try:
        import db
        container = request.args.get("container", "")
        min_score = request.args.get("min_score", "")
        min_score_val = int(min_score) if min_score.isdigit() else None
        page = int(request.args.get("page", 1))
        limit = 50
        offset = (page - 1) * limit
        
        events = db.get_runtime_events(container_name=container, min_score=min_score_val, limit=limit, offset=offset)
        for e in events:
            if isinstance(e.get("data"), str):
                try:
                    e["data"] = json.loads(e["data"])
                except:
                    e["data"] = {}
        return render_template("logs.html", events=events, container=container, min_score=min_score, page=page)
    except Exception as e:
        return f"Error loading logs: {e}", 500

@app.route("/")
@require_dashboard_auth
@limiter.limit("10 per minute")
def index():
    """Main dashboard page."""
    report = load_latest_report()
    runtime = load_runtime_findings()
    
    multi_file = REPORTS_DIR / "latest_multi_engine_summary.json"
    policy_data = {}
    if multi_file.exists():
        try:
            with open(multi_file, "r", encoding="utf-8") as f:
                audit_data = json.load(f)
                policy_data = audit_data.get("policy_evaluations", {})
        except Exception:
            pass
            
    return render_template(
        "dashboard.html",
        report=report,
        runtime=runtime,
        policy_data=policy_data,
    )


@app.route("/api/latest")
@require_dashboard_auth
def api_latest():
    """API endpoint for latest report."""
    report = load_latest_report()
    if report:
        return jsonify(report)
    return jsonify({"error": "No reports available"}), 404


@app.route("/api/history")
@require_dashboard_auth
def api_history():
    """API endpoint for historical data."""
    return jsonify(load_history())

@app.route("/api/runtime-history")
@require_dashboard_auth
def api_runtime_history():
    """API endpoint for runtime threat history from DB."""
    try:
        import db
        return jsonify(db.get_runtime_history())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/trends")
@require_dashboard_auth
def api_trends():
    """API endpoint for trend analysis."""
    history = load_history()

    if not history:
        return jsonify({"error": "No historical data"}), 404

    trends = {
        "dates": [],
        "vulnerable_size": [],
        "hardened_size": [],
        "vulnerable_vulns": [],
        "hardened_vulns": [],
    }

    for entry in history:
        timestamp = entry.get("timestamp", "")
        if timestamp:
            trends["dates"].append(timestamp[:10])

        comp = entry.get("comparison", {})
        trends["vulnerable_size"].append(float(comp.get("size_vulnerable_mb", 0)))
        trends["hardened_size"].append(float(comp.get("size_hardened_mb", 0)))
        trends["vulnerable_vulns"].append(comp.get("vuln_vulnerable", 0))
        trends["hardened_vulns"].append(comp.get("vuln_hardened", 0))

    return jsonify(trends)


@app.route("/api/runtime-threats")
@require_dashboard_auth
def api_runtime_threats():
    """API endpoint for latest runtime threat findings."""
    return jsonify(load_runtime_findings())


@app.route("/api/control-panel/status")
@require_dashboard_auth
@limiter.limit("10 per minute")
def api_control_panel_status():
    """Control panel status summary for security tooling and outputs."""
    runtime_file = RUNTIME_DIR / "runtime_threats_latest.json"
    runtime_exists = runtime_file.exists()
    return jsonify(
        {
            "timestamp": datetime.now().isoformat(),
            "tools": tool_status(),
            "runtime_output_exists": runtime_exists,
            "runtime_output_path": str(runtime_file),
            "runtime_generated_at": load_runtime_findings().get("generated_at") if runtime_exists else None,
            "containers_running": len(list_containers()),
            "ai_model_loaded": AI_MODEL_FILE.exists(),
            "vuln_monitor_enabled": True,
            "control_auth_enabled": CONTROL_AUTH_ENABLED,
        }
    )


@app.route("/api/control-panel/containers")
@require_dashboard_auth
@limiter.limit("10 per minute")
def api_control_panel_containers():
    """List running containers for control panel management."""
    containers = list_containers()
    try:
        import db
        protected = db.get_protected_containers()
        for c in containers:
            if c.get("ID") and c["ID"][:12] in protected:
                c["is_protected"] = True
    except Exception:
        pass
    return jsonify({"containers": containers})


@app.route("/api/control-panel/runtime/snapshot", methods=["POST"])
@require_dashboard_auth
@limiter.limit("10 per minute")
def api_control_panel_runtime_snapshot():
    """Trigger a one-shot runtime threat snapshot."""
    command = [sys.executable, "realtime_threat_engine.py"]
    result = run_command(command, env_overrides={"RUNTIME_MONITOR_MODE": "once"})
    return (
        jsonify(
            {
                "success": result.returncode == 0,
                "command": " ".join(command),
                "stdout": result.stdout[-2000:],
                "stderr": result.stderr[-2000:],
                "exit_code": result.returncode,
            }
        ),
        200 if result.returncode == 0 else 500,
    )


@app.route("/api/control-panel/audit/run", methods=["POST"])
@require_dashboard_auth
@limiter.limit("10 per minute")
def api_control_panel_run_audit():
    """Trigger a security audit run from the control panel."""
    command = [sys.executable, "audit.py"]
    result = run_command(command)
    if result.returncode == 0:
        AUDIT_RUNS.inc()
    return (
        jsonify(
            {
                "success": result.returncode == 0,
                "command": " ".join(command),
                "stdout": result.stdout[-3000:],
                "stderr": result.stderr[-3000:],
                "exit_code": result.returncode,
            }
        ),
        200 if result.returncode == 0 else 500,
    )


@app.route("/api/control-panel/container-action", methods=["POST"])
@require_dashboard_auth
@limiter.limit("10 per minute")
def api_control_panel_container_action():
    """Apply start/stop/restart actions to a container."""
    data = request.get_json(silent=True) or {}
    container = (data.get("container") or "").strip()
    action = data.get("action")

    if action not in {"start", "stop", "restart"}:
        return jsonify({"success": False, "error": "Invalid action"}), 400
    if not container:
        return jsonify({"success": False, "error": "Container is required"}), 400
    if not CONTAINER_NAME_RE.fullmatch(container):
        return jsonify({"success": False, "error": "Invalid container name"}), 400

    command = ["docker", action, container]
    result = run_command(command)
    return (
        jsonify(
            {
                "success": result.returncode == 0,
                "container": container,
                "action": action,
                "stdout": result.stdout[-2000:],
                "stderr": result.stderr[-2000:],
                "exit_code": result.returncode,
            }
        ),
        200 if result.returncode == 0 else 500,
    )

@app.route("/api/control-panel/protect/<container_id>", methods=["POST"])
@require_dashboard_auth
def api_control_panel_protect(container_id):
    try:
        import db
        container_name = request.json.get("container_name", container_id) if request.json else container_id
        db.protect_container(container_id, container_name)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/control-panel/unprotect/<container_id>", methods=["POST"])
@require_dashboard_auth
def api_control_panel_unprotect(container_id):
    try:
        import db
        db.unprotect_container(container_id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/runtime-threats/alerts")
@require_dashboard_auth
def api_runtime_alerts():
    """Only high-priority runtime alerts with CVE+fix context."""
    runtime = load_runtime_findings()
    return jsonify(runtime.get("alerts", []))


@app.route("/api/runtime-threats/container/<name>")
@require_dashboard_auth
def api_runtime_container_detail(name):
    """Container-level runtime detail including CVEs and suggested fixes."""
    item = runtime_summary_by_container(name)
    if item:
        return jsonify(item)
    return jsonify({"error": "container not found"}), 404


@app.route("/api/control-panel/report/runtime", methods=["POST"])
@require_dashboard_auth
@limiter.limit("10 per minute")
def api_control_panel_runtime_report():
    """Generate runtime security report on-demand (json/txt)."""
    payload = request.get_json(silent=True) or {}
    fmt = payload.get("format", "json")
    if fmt not in {"json", "txt"}:
        return jsonify({"success": False, "error": "format must be json or txt"}), 400

    runtime = load_runtime_findings()
    if not runtime.get("generated_at"):
        return jsonify({"success": False, "error": "no runtime findings available"}), 404

    try:
        engine = runtime_engine_instance()
        path = engine.generate_report(runtime, fmt=fmt)
        return jsonify({"success": True, "format": fmt, "path": str(path)})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.route("/reports/<path:filename>")
@require_dashboard_auth
@limiter.limit("10 per minute")
def download_report(filename):
    """Download report files from reports directory only."""
    reports_root = REPORTS_DIR.resolve()
    requested = (reports_root / filename).resolve()

    if reports_root not in requested.parents or not requested.is_file():
        return jsonify({"error": "File not found"}), 404

    return send_file(requested, as_attachment=True)


@app.route("/metrics")
def metrics():
    """Prometheus metrics endpoint."""
    runtime = load_runtime_findings()
    for finding in runtime.get("findings", []):
        cname = finding.get("name", "unknown")
        RISK_SCORE_GAUGE.labels(container_name=cname).set(finding.get("score", 0))
        ANOMALY_SCORE_GAUGE.labels(container_name=cname).set(finding.get("ai_anomaly_score", 0.0))
        
    summary = runtime.get("summary", {})
    CVE_GAUGE.labels(severity="critical").set(summary.get("total_cve_critical", 0))
    CVE_GAUGE.labels(severity="high").set(summary.get("total_cve_high", 0))
    
    multi_file = REPORTS_DIR / "latest_multi_engine_summary.json"
    if multi_file.exists():
        try:
            with open(multi_file, "r", encoding="utf-8") as f:
                audit_data = json.load(f)
                policy_eval = audit_data.get("policy_evaluations", {})
                violations = policy_eval.get("violations", [])
                
                # Reset all to 0 to prevent stale metrics
                POLICY_VIOLATIONS.labels(rule="deny_root_user").set(0)
                POLICY_VIOLATIONS.labels(rule="deny_no_resource_limits").set(0)
                POLICY_VIOLATIONS.labels(rule="deny_critical_cve").set(0)
                POLICY_VIOLATIONS.labels(rule="deny_latest_tag").set(0)

                for v in violations:
                    if "deny_root_user" in v:
                        POLICY_VIOLATIONS.labels(rule="deny_root_user").inc()
                    elif "deny_no_resource_limits" in v:
                        POLICY_VIOLATIONS.labels(rule="deny_no_resource_limits").inc()
                    elif "deny_critical_cve" in v:
                        POLICY_VIOLATIONS.labels(rule="deny_critical_cve").inc()
                    elif "deny_latest_tag" in v:
                        POLICY_VIOLATIONS.labels(rule="deny_latest_tag").inc()
        except Exception:
            pass
            
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}


@app.route("/health")
def health():
    """Health check endpoint."""
    import db
    db_ok = db.check_connection()
    version = "2.0.0"
    try:
        with open(PROJECT_ROOT / "VERSION") as f:
            version = f.read().strip()
    except Exception:
        pass
        
    if not db_ok:
        return jsonify({"status": "unhealthy", "error": "DB connection failed", "timestamp": datetime.now().isoformat(), "version": version}), 500
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat(), "version": version})


@app.errorhandler(Exception)
def handle_exception(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e.get_response()
    # Log unhandled exceptions with traceback
    logger.error("Unhandled exception", exc_info=e, extra={"extra_fields": {"event": "unhandled_exception", "path": request.path}})
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": str(e)}), 500
    return "Internal Server Error", 500

if __name__ == "__main__":
    REPORTS_DIR.mkdir(exist_ok=True)
    RUNTIME_DIR.mkdir(exist_ok=True)
    
    import signal
    import sys
    
    def handle_sigterm(*args):
        logger.info("Received SIGTERM, initiating graceful shutdown...", extra={"extra_fields": {"event": "graceful_shutdown"}})
        # Waitress natively shuts down on SIGTERM so this is just for logging
        sys.exit(0)
        
    signal.signal(signal.SIGTERM, handle_sigterm)
    
    port = int(os.getenv("PORT", "8080"))
    debug_enabled = os.getenv("FLASK_DEBUG", "0") == "1"
    
    if os.environ.get("FLASK_ENV") == "production":
        logger.info("Starting Waitress production server", extra={"extra_fields": {"event": "server_start"}})
        from waitress import serve
        serve(app, host="0.0.0.0", port=port)
    else:
        logger.info("Starting Flask development server", extra={"extra_fields": {"event": "server_start"}})
        app.run(host="0.0.0.0", port=port, debug=debug_enabled)
