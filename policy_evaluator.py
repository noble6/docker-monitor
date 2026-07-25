#!/usr/import/env python3
"""OPA Policy Evaluator wrapper."""

import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

logger = logging.getLogger("policy")

def check_opa_installed() -> bool:
    return shutil.which("opa") is not None or Path("bin/opa").exists()

def get_opa_binary() -> str:
    if Path("bin/opa").exists():
        return str(Path("bin/opa").absolute())
    return "opa"

def load_exceptions(exceptions_file: str) -> dict:
    if not yaml or not Path(exceptions_file).exists():
        return {}
    try:
        with open(exceptions_file, "r") as f:
            data = yaml.safe_load(f)
            return data.get("exceptions", {})
    except Exception as e:
        logger.error(f"Failed to load exceptions: {e}")
        return {}

def evaluate_policies(report_file: str, exceptions_file: str = "policy-exceptions.yml") -> dict:
    if not check_opa_installed():
        logger.error("OPA binary not found. Cannot evaluate policies.")
        return {"pass": False, "violations": ["OPA engine unavailable"]}

    if not Path(report_file).exists():
        logger.error(f"Report file {report_file} not found.")
        return {"pass": False, "violations": ["Missing report file"]}

    with open(report_file, "r") as f:
        scan_data = json.load(f)

    exceptions = load_exceptions(exceptions_file)
    scan_data["exceptions"] = exceptions

    # Write combined input to temp file
    temp_input = Path("opa_input.json")
    with open(temp_input, "w") as f:
        json.dump(scan_data, f)

    cmd = [
        get_opa_binary(),
        "eval",
        "-i", str(temp_input),
        "-d", "policies/security.rego",
        "data.security"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    temp_input.unlink(missing_ok=True)
    
    if result.returncode != 0:
        logger.error(f"OPA evaluation failed: {result.stderr}")
        return {"pass": False, "violations": ["OPA execution error"]}

    try:
        opa_output = json.loads(result.stdout)
        if not opa_output.get("result"):
            return {"pass": False, "violations": ["No evaluation result from OPA"]}
        
        # OPA eval returns {"result": [{"expressions": [{"value": {"pass": true, "violations": [...]}}]}]}
        value = opa_output["result"][0]["expressions"][0]["value"]
        passed = value.get("pass", False)
        violations = value.get("violations", [])
        not_applicable = value.get("not_applicable", [])
        return {"pass": passed, "violations": violations, "not_applicable": not_applicable}
    except Exception as e:
        logger.error(f"Failed to parse OPA output: {e}")
        return {"pass": False, "violations": ["Failed to parse policy results"], "not_applicable": []}

if __name__ == "__main__":
    report = "reports/latest_multi_engine_summary.json"
    res = evaluate_policies(report)
    
    if res.get("not_applicable"):
        print("Policies Not Applicable:")
        for na in res["not_applicable"]:
            print(f"- {na}")
        print()

    if res["violations"]:
        print("Policy Violations Found:")
        for v in res["violations"]:
            print(f"- {v}")
    
    if not res["pass"]:
        sys.exit(1)
    else:
        print("All policies passed successfully.")
        sys.exit(0)
