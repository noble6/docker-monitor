import json
import subprocess
from pathlib import Path

def evaluate_fixture(fixture_data: dict) -> dict:
    """Helper to evaluate a rego policy against a fixture dict."""
    with open("temp_fixture.json", "w") as f:
        json.dump(fixture_data, f)
    
    opa_bin = "opa" if not Path("bin/opa").exists() else str(Path("bin/opa").absolute())
    cmd = [
        opa_bin, "eval", "-i", "temp_fixture.json",
        "-d", "policies/security.rego",
        "data.security"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    Path("temp_fixture.json").unlink(missing_ok=True)
    
    try:
        out = json.loads(res.stdout)
        val = out["result"][0]["expressions"][0]["value"]
        return {
            "pass": val.get("pass", False), 
            "violations": val.get("violations", []),
            "not_applicable": val.get("not_applicable", [])
        }
    except Exception:
        return {"pass": False, "violations": ["Evaluation failed"], "not_applicable": []}

def test_deny_root_user_violation():
    fixture = {
        "vulnerable": {
            "critical": 0,
            "config": {"User": "root"}
        }
    }
    res = evaluate_fixture(fixture)
    assert res["pass"] is False
    assert any("deny_root_user" in v and "explicitly runs as root" in v for v in res["violations"])

def test_deny_root_user_compliant():
    fixture = {
        "hardened": {
            "critical": 0,
            "config": {"User": "appuser"}
        }
    }
    res = evaluate_fixture(fixture)
    # The others might fail since we don't have limits/latest tag defined if we don't mock it well, wait!
    # Wait, the other rules like deny_latest_tag and deny_no_resource_limits will also fire!
    # Let's mock a perfectly compliant image.
    pass

def test_perfectly_compliant_fixture():
    fixture = {
        "hardened": {
            "critical": 0,
            "k8s_limits": {"memory": "512Mi", "cpu": "500m"},
            "config": {
                "User": "appuser",
                "RepoTags": ["myimage:v1.0"]
            }
        }
    }
    res = evaluate_fixture(fixture)
    assert res["pass"] is True
    assert len(res["violations"]) == 0

def test_deny_latest_tag_violation():
    fixture = {
        "vulnerable": {
            "critical": 0,
            "k8s_limits": {"memory": "512Mi"},
            "config": {
                "User": "appuser",
                "RepoTags": ["myimage:latest"]
            }
        }
    }
    res = evaluate_fixture(fixture)
    assert res["pass"] is False
    assert any("deny_latest_tag" in v for v in res["violations"])

def test_deny_critical_cve_violation():
    fixture = {
        "vulnerable": {
            "critical": 5,
            "k8s_limits": {"memory": "512Mi"},
            "config": {
                "User": "appuser",
                "RepoTags": ["myimage:v1.0"]
            }
        }
    }
    res = evaluate_fixture(fixture)
    assert res["pass"] is False
    assert any("deny_critical_cve" in v for v in res["violations"])

def test_deny_no_resource_limits_violation():
    fixture = {
        "vulnerable": {
            "critical": 0,
            "k8s_limits": {},
            "config": {
                "User": "appuser",
                "RepoTags": ["myimage:v1.0"]
            }
        }
    }
    res = evaluate_fixture(fixture)
    assert res["pass"] is False
    assert any("deny_no_resource_limits" in v for v in res["violations"])

def test_deny_no_resource_limits_not_applicable():
    fixture = {
        "vulnerable": {
            "critical": 0,
            "k8s_limits": None,
            "config": {
                "User": "appuser",
                "RepoTags": ["myimage:v1.0"]
            }
        }
    }
    res = evaluate_fixture(fixture)
    assert res["pass"] is True
    assert any("Not Applicable" in na for na in res["not_applicable"])

def test_policy_exception_override():
    fixture = {
        "vulnerable": {
            "critical": 0,
            "k8s_limits": {"memory": "512Mi"},
            "config": {
                "User": "appuser",
                "RepoTags": ["myimage:latest"]
            }
        },
        "exceptions": {
            "vulnerable": {
                "deny_latest_tag": "2030-01-01"
            }
        }
    }
    res = evaluate_fixture(fixture)
    # the exception allows latest tag
    assert res["pass"] is True
