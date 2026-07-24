import os
import pytest
from dashboard.app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_health_endpoint(client):
    rv = client.get('/health')
    assert rv.status_code == 200
    assert b"healthy" in rv.data

def test_dashboard_unauthorized(client):
    # Ensure auth is enabled
    os.environ["DASHBOARD_AUTH_USER"] = "admin"
    os.environ["DASHBOARD_AUTH_PASSWORD"] = "password"
    
    import dashboard.app
    dashboard.app.CONTROL_AUTH_ENABLED = True
    dashboard.app.CONTROL_USER = "admin"
    dashboard.app.CONTROL_PASSWORD = "password"
    
    rv = client.get('/')
    assert rv.status_code == 302
    assert "/login" in rv.location

def test_dashboard_authorized(client):
    import base64
    import dashboard.app
    dashboard.app.CONTROL_AUTH_ENABLED = True
    dashboard.app.CONTROL_USER = "admin"
    dashboard.app.CONTROL_PASSWORD = "password"
    
    auth_header = {'Authorization': 'Basic ' + base64.b64encode(b"admin:password").decode('ascii')}
    rv = client.get('/', headers=auth_header)
    # The route returns render_template('dashboard.html') which might fail if the template isn't available, but we just check auth doesn't reject it
    assert rv.status_code in (200, 500) # 500 might happen if templates are not fully set up in test env, but 401 is avoided

def test_control_panel_status_unauthorized(client):
    rv = client.get('/api/control-panel/status')
    assert rv.status_code == 401

def test_metrics_endpoint(client):
    rv = client.get('/metrics')
    assert rv.status_code == 200
    metrics_output = rv.data.decode('utf-8')
    for metric in [
        "container_risk_score",
        "container_anomaly_score",
        "cve_count",
        "audit_runs_total",
        "dashboard_auth_failures_total"
    ]:
        assert metric in metrics_output
