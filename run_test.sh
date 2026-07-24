#!/bin/bash
export DASHBOARD_AUTH_USER="admin"
export DASHBOARD_AUTH_PASSWORD="password"
export PYTHONNOUSERSITE=1 
source .venv/bin/activate
python dashboard/app.py > dashboard_test.log 2>&1 &
APP_PID=$!
sleep 5
echo "Triggering auth failure..."
curl -s -X POST -d "username=admin&password=wrong" http://localhost:8080/login > /dev/null
echo "Logging in..."
curl -s -c cookies.txt -X POST -d "username=admin&password=password" http://localhost:8080/login > /dev/null
echo "Triggering audit run..."
curl -s -b cookies.txt -X POST http://localhost:8080/api/control-panel/audit/run > /dev/null
sleep 3
echo "Fetching metrics..."
curl -s http://localhost:8080/metrics > metrics.txt
kill $APP_PID
cat metrics.txt
