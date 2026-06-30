#!/bin/bash
set -e

echo "Building CyberSec Dashboard with PyInstaller..."

# Ensure pyinstaller is installed
if ! command -v pyinstaller &> /dev/null; then
    echo "Installing PyInstaller..."
    pip install --break-system-packages pyinstaller
fi

# PyInstaller might have trouble with sklearn or docker SDK depending on the host OS
# We use --hidden-import to help it along
pyinstaller --name cybersec-dashboard \
    --onefile \
    --paths="." \
    --add-data "dashboard/templates:dashboard/templates" \
    --add-data "config.yaml:." \
    --add-data "ml_anomaly_model.joblib:." \
    --add-data "*.py:." \
    --hidden-import="sklearn.ensemble._forest" \
    --hidden-import="sklearn.tree._classes" \
    --hidden-import="sklearn.utils._typedefs" \
    --hidden-import="sklearn.neighbors._partition_nodes" \
    --hidden-import="flask" \
    --hidden-import="flask_limiter" \
    --hidden-import="requests" \
    --hidden-import="sqlite3" \
    dashboard/app.py

echo "Build complete. Executable is at dist/cybersec-dashboard"
