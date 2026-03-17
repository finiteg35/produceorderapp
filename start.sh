#!/bin/bash

# Start the FastAPI server in the background
uvicorn main:app --host 0.0.0.0 --port "${PORT:-8000}" &
SERVER_PID=$!

# Run inventory initialization (retry logic is built into inventory.py)
python inventory.py || echo "⚠️  Inventory initialization failed, but continuing..."

# Wait for the server process to keep this script running
wait $SERVER_PID
