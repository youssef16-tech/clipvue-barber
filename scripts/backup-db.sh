#!/usr/bin/env bash
set -euo pipefail

# --- what we're backing up and where ---
DB="/home/moussa/projects/clipvue-barber/clipvue.db"
BACKUP_DIR="/home/moussa/backups/clipvue"
KEEP_DAYS=7

# --- make sure the backup folder exists ---
mkdir -p "$BACKUP_DIR"

# --- build a timestamped filename, e.g. clipvue-2026-07-23_1241.db ---
STAMP="$(date +%Y-%m-%d_%H%M)"
DEST="$BACKUP_DIR/clipvue-$STAMP.db"

# --- safe snapshot of the live database ---
sqlite3 "$DB" ".backup '$DEST'"
echo "Backup written: $DEST"

# --- delete backups older than KEEP_DAYS days ---
find "$BACKUP_DIR" -name 'clipvue-*.db' -mtime +"$KEEP_DAYS" -delete
echo "Pruned backups older than $KEEP_DAYS days"
