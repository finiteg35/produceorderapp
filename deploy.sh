#!/bin/bash
# deploy.sh — safe deploy for produceorderapp
# Usage: ./deploy.sh
# Enforces: syntax check → backup → copy to openclaw mount → restart → verify

set -e

APP_SRC="/root/produceorderapp/app.py"
APP_MOUNT="/docker/openclaw-dtsu/data/.openclaw/workspace/produceorderapp/app.py"
BACKUP_DIR="/root/produceorderapp/backups"
CONTAINER="produceorderapp-produceorderapp-1"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "[1/5] Syntax check..."
python3 -m py_compile "$APP_SRC"
echo "      OK"

echo "[2/5] Backing up current production file..."
mkdir -p "$BACKUP_DIR"
cp "$APP_MOUNT" "$BACKUP_DIR/app.py.bak_$TIMESTAMP"
echo "      Saved to $BACKUP_DIR/app.py.bak_$TIMESTAMP"

echo "[3/5] Copying to openclaw mount..."
cp "$APP_SRC" "$APP_MOUNT"
echo "      OK"

echo "[4/5] Restarting container..."
docker restart "$CONTAINER"
sleep 5

echo "[5/5] Verifying..."
LOGS=$(docker logs "$CONTAINER" --tail 5 2>&1)
if echo "$LOGS" | grep -qi "error\|traceback\|exception" ; then
  echo "      WARNING: errors detected in logs:"
  echo "$LOGS"
  echo ""
  echo "      Rolling back..."
  cp "$BACKUP_DIR/app.py.bak_$TIMESTAMP" "$APP_MOUNT"
  cp "$BACKUP_DIR/app.py.bak_$TIMESTAMP" "$APP_SRC"
  docker restart "$CONTAINER"
  echo "      Rolled back to $TIMESTAMP backup. Check the logs."
  exit 1
fi

echo "      Logs clean."
echo ""
echo "Deploy complete. Backup at: $BACKUP_DIR/app.py.bak_$TIMESTAMP"
