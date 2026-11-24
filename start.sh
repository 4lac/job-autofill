#!/usr/bin/env bash
cd "$(dirname "$0")"
[ -d .venv ] || { echo "First run: setting things up, this takes a few minutes..."; python3 -m venv .venv; }
. .venv/bin/activate
if ! python -c "import flask, playwright, keyring, cryptography" 2>/dev/null; then
  echo "Installing requirements..."
  python -m pip install -r requirements.txt flask playwright || { echo "Install failed. Check your internet connection."; exit 1; }
  python -m playwright install chromium
fi
python job_autofill.py
