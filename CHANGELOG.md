# Changelog

## [2.0.0] - Security & Durability Hardening Release
### Added
- **ML Anomaly Engine**: Production-ready Isolation Forest model integrated into the real-time threat engine for runtime container monitoring, failing back safely if model data is missing.
- **Policy-as-Code (OPA)**: Integrated Rego policies for CI enforcement. Now properly evaluates `k8s_limits` from actual Kubernetes deployment manifests rather than Docker inspect output, correctly issuing `Not Applicable` when manifests are absent.
- **Authentication & CSRF**: Control panel actions are protected by HTTP basic auth and robust Flask-WTF CSRF tokens. All session cookies enforce `HttpOnly`, `Secure`, and `SameSite=Lax`.
- **Database Durability**: Migrated SQLite to WAL (Write-Ahead Logging) mode for concurrent reads/writes. Added `backup_db.sh` and `restore_db.sh` scripts for safe, online snapshotting using the SQLite backup API.
- **Structured Logging**: Unified JSON logging across all components using `logger.py` with `RotatingFileHandler` (max 10MB, 5 backups). No secrets or passwords are ever logged.
- **Graceful Shutdown**: The dashboard now runs on `waitress` in production mode and properly catches `SIGTERM` signals for clean shutdown, avoiding dropped connections.
- **Deployment Packaging**: Added a comprehensive `docker-compose.yml` encapsulating the vulnerable app, hardened app, and the dashboard with persistent named volumes and `HEALTHCHECK` DB connectivity checks.
