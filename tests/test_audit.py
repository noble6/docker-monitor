import pytest
import subprocess
from audit import check_tool_installed, run_command
from ai_security_model import RuleBasedRiskScorer, RuleBasedAnomalyScorer

def test_risk_scorer_high_critical():
    scorer = RuleBasedRiskScorer()
    score = scorer.score({"critical": 50})
    assert score > 80

def test_risk_scorer_clean():
    scorer = RuleBasedRiskScorer()
    score = scorer.score({"critical": 0, "high": 0, "medium": 0, "low": 0, "fatal": 0, "warn": 0, "engine_coverage": 4})
    assert score < 30

def test_risk_scorer_differentiates():
    scorer = RuleBasedRiskScorer()
    hardened = scorer.score({"critical": 10, "high": 44})
    vulnerable = scorer.score({"critical": 13, "high": 97})
    assert vulnerable > hardened
    assert hardened > 0
    assert vulnerable < 100

def test_anomaly_scorer_normal():
    scorer = RuleBasedAnomalyScorer()
    score = scorer.score({"cpu": 1, "memory": 1, "network_total": 1, "pids": 1, "restart_count": 0, "cpu_z": 0.1, "memory_z": 0.1, "network_z": 0.1, "pid_z": 0.1})
    assert score < 30

def test_run_command_timeout(monkeypatch):
    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get('timeout', 120))
    monkeypatch.setattr(subprocess, "run", mock_run)
    result = run_command(["sleep", "200"])
    assert result.returncode == -1
    assert "TimeoutExpired" in result.stderr

def test_tool_check_nonexistent():
    assert check_tool_installed("nonexistent_tool_xyz") is False

def test_cloud_cve_fetcher(monkeypatch):
    from cloud_cve import CloudCVEFetcher
    import requests
    
    class MockResponse:
        status_code = 200
        def json(self):
            return {"vulns": [{"id": "CVE-2021-44228"}], "severity": [{"type": "CVSS_V3", "score": "CRITICAL"}]}
            
    def mock_get(*args, **kwargs):
        return MockResponse()
        
    monkeypatch.setattr(requests, "get", mock_get)
    fetcher = CloudCVEFetcher({"cloud": {"enabled": True}})
    fetcher.cache_file = type('obj', (object,), {'exists': lambda: False, 'stat': lambda: type('obj', (object,), {'st_mtime': 0})})() # disable cache logic for test
    # Monkeypatch the methods to avoid writing file
    monkeypatch.setattr(fetcher, "_is_cache_stale", lambda: True)
    monkeypatch.setattr(fetcher, "load_cache", lambda: {})
    monkeypatch.setattr(fetcher, "save_cache", lambda d: None)
    
    result = fetcher.fetch_severity(["CVE-2021-44228"])
    assert "CVE-2021-44228" in result
    assert result["CVE-2021-44228"] == "CRITICAL"

def test_cloud_cve_offline_mode(monkeypatch):
    import requests
    from cloud_cve import CloudCVEFetcher
    
    def mock_get(*args, **kwargs):
        raise requests.exceptions.ConnectionError("Mocked network error")
        
    monkeypatch.setattr(requests, "get", mock_get)
    monkeypatch.setenv("OFFLINE_MODE", "true")
    
    fetcher = CloudCVEFetcher({"cloud": {"enabled": True}})
    
    monkeypatch.setattr(fetcher, "load_cache", lambda: {"CVE-1234": "HIGH"})
    monkeypatch.setattr(fetcher, "_is_cache_stale", lambda: True)
    
    result = fetcher.fetch_severity(["CVE-1234", "CVE-9999"])
    assert "CVE-1234" in result
    assert result["CVE-1234"] == "HIGH"
    assert result["CVE-9999"] == "UNKNOWN"
