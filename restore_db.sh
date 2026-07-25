#!/bin/bash
# SQLite Restore Script
# Restores a backup file safely

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <backup_file_path>"
    exit 1
fi

BACKUP_PATH="$1"
DB_PATH="docker_monitor.db"

if [ ! -f "$BACKUP_PATH" ]; then
    echo "Backup file $BACKUP_PATH not found."
    exit 1
fi

echo "Stopping services (if applicable)..."
# In a real environment, stop systemctl/supervisor here

echo "Restoring database from $BACKUP_PATH to $DB_PATH..."
# We use the SQLite restore API which is safer than copying files over
sqlite3 "$DB_PATH" ".restore '${BACKUP_PATH}'"

if [ $? -eq 0 ]; then
    echo "Restore completed successfully."
else
    echo "Restore failed!"
    exit 1
fi
