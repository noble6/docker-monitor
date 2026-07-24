import os
import sys
import time
from pathlib import Path
from multiprocessing import Process
import requests

PROJECT_ROOT = Path("/mnt/vault/Project/docker-monitor")
sys.path.insert(0, str(PROJECT_ROOT))

os.environ["DASHBOARD_AUTH_USER"] = "admin"
os.environ["DASHBOARD_AUTH_PASSWORD"] = "password"
os.environ["DASHBOARD_ALLOW_INSECURE"] = "false"
os.environ["PYTHONNOUSERSITE"] = "1"

def run_app():
    from dashboard.app import app
    app.run(host="0.0.0.0", port=8080, use_reloader=False)

if __name__ == "__main__":
    p = Process(target=run_app)
    p.start()
    time.sleep(3)
    
    requests.post('http://localhost:8080/login', data={'username': 'admin', 'password': 'wrongpassword'})
    
    session = requests.Session()
    session.post('http://localhost:8080/login', data={'username': 'admin', 'password': 'password'})
    
    session.post('http://localhost:8080/api/control-panel/audit/run')
    time.sleep(3)
    
    res = requests.get('http://localhost:8080/metrics')
    print("=== METRICS OUTPUT ===")
    print(res.text)
    print("======================")
    
    p.terminate()
