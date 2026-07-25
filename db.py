import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

import os
PROJECT_ROOT = Path(os.environ.get("PROJECT_ROOT", Path(__file__).resolve().parent))
DB_PATH = PROJECT_ROOT / "runtime" / "docker_monitor.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            data JSON NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS runtime_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            container_name TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            score INTEGER NOT NULL,
            ai_score REAL NOT NULL,
            cve_critical INTEGER NOT NULL,
            data JSON NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS protected_containers (
            container_id TEXT PRIMARY KEY,
            container_name TEXT NOT NULL,
            protected_since TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def is_container_protected(container_id: str) -> bool:
    if not DB_PATH.exists():
        return False
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM protected_containers WHERE container_id = ?", (container_id,))
    res = cursor.fetchone()
    conn.close()
    return bool(res)

def get_protected_containers() -> List[str]:
    if not DB_PATH.exists():
        return []
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT container_id FROM protected_containers")
    res = [r[0] for r in cursor.fetchall()]
    conn.close()
    return res

def protect_container(container_id: str, container_name: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO protected_containers (container_id, container_name, protected_since) VALUES (?, ?, ?)", (container_id, container_name, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def unprotect_container(container_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM protected_containers WHERE container_id = ?", (container_id,))
    conn.commit()
    conn.close()

def save_audit(data: Dict[str, Any]):
    timestamp = data.get("timestamp", datetime.now().isoformat())
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO audits (timestamp, data) VALUES (?, ?)", (timestamp, json.dumps(data)))
    conn.commit()
    conn.close()

def save_runtime_event(event: Dict[str, Any]):
    timestamp = event.get("timestamp", datetime.now().isoformat())
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO runtime_events (timestamp, container_name, risk_level, score, ai_score, cve_critical, data) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (timestamp, event.get("container", ""), event.get("risk_level", "low"), event.get("runtime_score", 0), event.get("ai_anomaly_score", 0.0), event.get("cve_critical", 0), json.dumps(event))
    )
    conn.commit()
    conn.close()

def get_audit_history() -> List[Dict[str, Any]]:
    if not DB_PATH.exists():
        return []
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT data FROM audits ORDER BY timestamp ASC")
    rows = cursor.fetchall()
    conn.close()
    return [json.loads(row[0]) for row in rows]

def get_runtime_history() -> List[Dict[str, Any]]:
    if not DB_PATH.exists():
        return []
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT data FROM runtime_events ORDER BY timestamp DESC LIMIT 1000")
    rows = cursor.fetchall()
    conn.close()
    return [json.loads(row[0]) for row in rows]

def get_runtime_events(container_name: str = None, min_score: int = None, limit: int = 100, offset: int = 0):
    if not DB_PATH.exists():
        return []
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = "SELECT * FROM runtime_events WHERE 1=1"
    params = []
    
    if container_name:
        query += " AND container_name LIKE ?"
        params.append(f"%{container_name}%")
        
    if min_score is not None:
        query += " AND score >= ?"
        params.append(min_score)
        
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

# Initialize DB on import
init_db()

def check_connection() -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        conn.close()
        return True
    except Exception:
        return False
