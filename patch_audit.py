import re

with open("audit.py", "r") as f:
    code = f.read()

helper = """
def load_or_run_tool(tool_name: str, image_name: str, command: list[str], output_file: str) -> tuple[str, int]:
    base_img = image_name.split(':')[0]
    ci_file = f"{tool_name}-{base_img}.json"
    import os
    if os.path.exists(ci_file):
        with open(ci_file, 'r') as f:
            return f.read(), 1
    
    if not check_tool_installed(tool_name):
        logger.warning(f"{tool_name} not found")
        return "", 0
        
    result = run_command(command)
    _append_report(output_file, f"{tool_name.capitalize()} - {image_name}", result.stdout, result.stderr)
    if result.returncode != 0 or not result.stdout.strip():
        return "", 1 # Engine ran but failed/no output
    return result.stdout, 1
"""

# Insert helper before scan_trivy
code = code.replace("def scan_trivy(", helper + "\ndef scan_trivy(")

# Update scan_trivy
trivy_old = """    if not check_tool_installed("trivy"):
        logger.warning("Trivy not found")
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 0, "cves_by_severity": empty_cves}

    result = run_command(["trivy", "image", "--format", "json", image_name])
    _append_report(output_file, f"Trivy - {image_name}", result.stdout, result.stderr)
    if result.returncode != 0 or not result.stdout.strip():
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 1, "cves_by_severity": empty_cves}

    data = json.loads(result.stdout)"""

trivy_new = """    stdout, enabled = load_or_run_tool("trivy", image_name, ["trivy", "image", "--format", "json", image_name], output_file)
    if not enabled:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 0, "cves_by_severity": empty_cves}
    if not stdout.strip():
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "engine_enabled": 1, "cves_by_severity": empty_cves}

    try:
        data = json.loads(stdout)
    except:
        data = {}"""

code = code.replace(trivy_old, trivy_new)

# Update scan_dockle
dockle_old = """    if not check_tool_installed("dockle"):
        logger.warning("Dockle not found")
        return {"fatal": 0, "warn": 0, "engine_enabled": 0}

    result = run_command(["dockle", "-f", "json", image_name])
    _append_report(output_file, f"Dockle - {image_name}", result.stdout, result.stderr)

    fatal = warn = 0
    try:
        data = json.loads(result.stdout) if result.stdout else {}"""

dockle_new = """    stdout, enabled = load_or_run_tool("dockle", image_name, ["dockle", "-f", "json", image_name], output_file)
    if not enabled:
        return {"fatal": 0, "warn": 0, "engine_enabled": 0}

    fatal = warn = 0
    try:
        data = json.loads(stdout) if stdout else {}"""
code = code.replace(dockle_old, dockle_new)

# Update scan_syft
syft_old = """    if not check_tool_installed("syft"):
        logger.warning("Syft not found")
        return {"packages": 0, "engine_enabled": 0}

    result = run_command(["syft", "packages", "-o", "json", image_name])
    _append_report(output_file, f"Syft - {image_name}", result.stdout, result.stderr)
    
    pkgs = 0
    if result.returncode == 0 and result.stdout:
        try:
            data = json.loads(result.stdout)"""

syft_new = """    stdout, enabled = load_or_run_tool("syft", image_name, ["syft", "packages", "-o", "json", image_name], output_file)
    if not enabled:
        return {"packages": 0, "engine_enabled": 0}

    pkgs = 0
    if stdout:
        try:
            data = json.loads(stdout)"""
code = code.replace(syft_old, syft_new)

# Update scan_grype
grype_old = """    empty_cves = {"CRITICAL": set(), "HIGH": set(), "MEDIUM": set(), "LOW": set()}
    if not check_tool_installed("grype"):
        logger.warning("Grype not found")
        return empty_cves, 0

    result = run_command(["grype", image_name, "-o", "json"])
    _append_report(output_file, f"Grype - {image_name}", result.stdout, result.stderr)

    if result.returncode != 0 or not result.stdout.strip():
        return empty_cves, 1

    try:
        data = json.loads(result.stdout)"""

grype_new = """    empty_cves = {"CRITICAL": set(), "HIGH": set(), "MEDIUM": set(), "LOW": set()}
    stdout, enabled = load_or_run_tool("grype", image_name, ["grype", image_name, "-o", "json"], output_file)
    if not enabled:
        return empty_cves, 0

    if not stdout.strip():
        return empty_cves, 1

    try:
        data = json.loads(stdout)"""
code = code.replace(grype_old, grype_new)

# Write back
with open("audit.py", "w") as f:
    f.write(code)
