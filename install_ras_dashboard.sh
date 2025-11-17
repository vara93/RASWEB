#!/bin/bash
set -euo pipefail

APP_DIR=/opt/ras-dashboard
PYTHON=${PYTHON:-python3}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

mkdir -p "$APP_DIR"
cd "$APP_DIR"

$PYTHON -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install fastapi "uvicorn[standard]" jinja2 psutil ldap3

to_copy=(ras_client.py monitoring.py web_publish.py auth.py main.py templates)
for item in "${to_copy[@]}"; do
  cp -r "${SCRIPT_DIR}/${item}" "$APP_DIR/"
done

echo "Installation completed to $APP_DIR"
