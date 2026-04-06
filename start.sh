#!/bin/bash

# Start the Flask web app
exec gunicorn web_app:app --bind "0.0.0.0:${PORT:-5000}"
