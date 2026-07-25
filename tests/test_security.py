import os
import pytest
from importlib import reload
import dashboard.app as app_module
from flask_wtf.csrf import generate_csrf
from dashboard.app import app as flask_app

@pytest.fixture
def client():
    # Force CSRF to be enabled during testing for security tests
    flask_app.config['WTF_CSRF_ENABLED'] = True
    flask_app.config['TESTING'] = True
    with flask_app.test_client() as client:
        yield client

from prometheus_client import REGISTRY

def test_missing_secret_key_in_production(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("DASHBOARD_AUTH_USER", "admin")
    monkeypatch.setenv("DASHBOARD_AUTH_PASSWORD", "password")

    # Clear prometheus registry so reload doesn't fail on duplicate metrics
    collectors = list(REGISTRY._collector_to_names.keys())
    for collector in collectors:
        REGISTRY.unregister(collector)

    with pytest.raises(RuntimeError, match="SECRET_KEY environment variable is required in production"):
        reload(app_module)

def test_login_cookie_flags(client):
    # conftest.py sets testuser and testpass123
    
    # We must first get the page to generate the CSRF token
    response_get = client.get("/login")
    assert response_get.status_code == 200
    
    # Extract CSRF token from the form
    html = response_get.data.decode("utf-8")
    import re
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    csrf_token = match.group(1) if match else ""
    
    import dashboard.app
    dashboard.app.CONTROL_USER = "admin"
    dashboard.app.CONTROL_PASSWORD = "password"
    
    response = client.post("/login", data={
        "username": "admin",
        "password": "password",
        "csrf_token": csrf_token
    })
    
    # We expect a redirect to / upon successful login
    assert response.status_code == 302
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) > 0
    session_cookie = cookies[0]
    
    assert "Secure" in session_cookie
    assert "HttpOnly" in session_cookie
    assert "SameSite=Lax" in session_cookie

def test_csrf_rejection_on_state_change(client):
    # Missing CSRF token in POST request to an API endpoint
    response = client.post("/api/control-panel/audit/run")
    
    # CSRF failure should result in 400 Bad Request from Flask-WTF
    assert response.status_code == 400
    assert b"The CSRF token is missing" in response.data or b"The CSRF session token is missing" in response.data
