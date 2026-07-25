#!/bin/bash
# SQLite Online Backup Script
# Performs a safe snapshot of the database using SQLite's backup API
# This runs safely even if the database is in use (e.g. WAL mode)

DB_PATH="docker_monitor.db"
BACKUP_DIR="backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="${BACKUP_DIR}/docker_monitor_${TIMESTAMP}.db"

mkdir -p "$BACKUP_DIR"

if [ ! -f "$DB_PATH" ]; then
    echo "Database $DB_PATH not found."
    exit 1
fi

echo "Starting safe backup of $DB_PATH to $BACKUP_PATH..."
sqlite3 "$DB_PATH" ".backup '${BACKUP_PATH}'"

if [ $? -eq 0 ]; then
    echo "Backup completed successfully."
else
    echo "Backup failed!"
    exit 1
fi
