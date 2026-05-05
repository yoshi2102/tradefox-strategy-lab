#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
pip install -q -r requirements.txt

if [ ! -f config.json ]; then
  cp config.example.json config.json
  echo
  echo "→ Edit config.json with your real IBKR credentials, then re-run:"
  echo "    ip               your public IP (must match what John C. registered)"
  echo "    credential       tradf3020 (or tradf489 / tradf035)"
  echo "    privateKeyPath   absolute path to your 3072+ bit RSA private key (.pem)"
  echo "    accountId        DUP169897"
  echo
  exit 0
fi

python server.py
