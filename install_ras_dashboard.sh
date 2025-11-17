#!/bin/bash
set -euo pipefail

APP_DIR=/opt/ras-dashboard
PYTHON=${PYTHON:-python3}

mkdir -p "$APP_DIR"
cd "$APP_DIR"

$PYTHON -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install fastapi "uvicorn[standard]" jinja2

to_copy=(ras_client.py main.py templates)
for item in "${to_copy[@]}"; do
  cp -r "/workspace/RASWEB/${item}" "$APP_DIR/"
done

echo "Installation completed to $APP_DIR"
