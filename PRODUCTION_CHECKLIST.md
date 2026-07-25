# Production Deployment Checklist

Follow these exact steps to deploy the Docker Security Monitor in a real production environment.

## 1. Prerequisites
- **Docker & Docker Compose**: Ensure Docker and the Compose plugin are installed (`docker compose version`).
- **Domain & TLS (Optional but Recommended)**: Obtain a TLS certificate (e.g., Let's Encrypt) and configure an Nginx reverse proxy (see `README.md` TLS section).

## 2. Configuration (Environment Variables)
Before starting the stack, you must configure the mandatory environment variables. Create a `.env` file or export them in your shell:
```bash
export DASHBOARD_AUTH_USER="your_secure_username"
export DASHBOARD_AUTH_PASSWORD="your_secure_password"
export SECRET_KEY="a_long_random_string_for_session_encryption"
```
*Note: If `SECRET_KEY` is omitted in production, the application will refuse to start to protect session integrity.*

## 3. Starting the Stack
Use Docker Compose to build and start the entire stack (vulnerable app, hardened app, and the dashboard):
```bash
docker compose up --build -d
```

## 4. Verifying Health
Once started, verify the services are running and the database is connected:
```bash
docker compose ps
```
Look for `(healthy)` under the STATUS column for the `dashboard` container.
You can also manually verify by querying the health endpoint:
```bash
curl -s http://localhost:8080/health
```
You should see: `{"status": "healthy", "timestamp": "...", "version": "2.0.0"}`

## 5. Performing a Backup Drill
The database runs in SQLite WAL mode. Do NOT use `cp` to back up the database while the container is running.
Instead, use the included online snapshot script:
```bash
# 1. Take a safe backup
./backup_db.sh

# 2. Verify the backup was created
ls -l backups/

# 3. Test a restore (this will overwrite your current DB, so test carefully!)
./restore_db.sh backups/docker_monitor_YYYYMMDD_HHMMSS.db
```
It is highly recommended to add `./backup_db.sh` to your system's `cron` to run nightly.

## 6. Accessing Logs
All logs are emitted in structured JSON format. To monitor the dashboard and realtime engine logs:
```bash
tail -f logs/security_monitor.log | jq
```
Logs automatically rotate at 10MB (keeping 5 backups). No passwords or secrets are ever logged.
