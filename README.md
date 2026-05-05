# TradeFox · IBKR Strategy Lab

Local + cloud-deployable web app for testing prediction-market trading strategies on Interactive Brokers' ForecastEx event contracts.

Pulls real data from the IBKR Trading Web API: OAuth 2.0 → SSO → tickle → `/ssodh/init` → `/iserver/accounts`. Live snapshots via `/iserver/marketdata/snapshot`. Paper-only by design.

## Run locally

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.example.json config.json   # fill in clientId/credential/accountId/privateKeyPath
python server.py                     # http://127.0.0.1:8787
```

## Deploy to Render

1. Push this repo to GitHub.
2. On Render: **New → Blueprint** → connect this repo. Render reads `render.yaml`.
3. In the service's **Environment** tab, set the secret env vars:
   - `IBKR_CLIENT_ID` = `TradeFox-paper`
   - `IBKR_CLIENT_KEY_ID` = `main`
   - `IBKR_CREDENTIAL` = `tradf3020`
   - `IBKR_ACCOUNT_ID` = `DUP169897`
   - `IBKR_PRIVATE_KEY` = paste the PEM (or base64 of it). Server writes it to `/tmp/ibkr_private.pem` at boot.
4. Deploy. The auto-connect loop will run OAuth on startup. IBKR doesn't whitelist IPs — `IBKR_AUTO_DETECT_IP=true` makes the server look up its own egress IP at connect time and put it in the JWT claim.

## What's wired

- Auth: OAuth 2.0 private-key JWT, SSO bearer, tickle, `/ssodh/init`, accounts.
- Auto-tickle every 90s, auto-reconnect with backoff.
- Portfolio: `/portfolio/{id}/summary`, `/portfolio/{id}/positions/{page}`.
- Forecast: `/forecast/category/tree`, `/forecast/contract/{details,rules,schedules}`.
- Market data: snapshot (with warmup pass), history.
- Orders: what-if, place, reply, cancel.

## Files

- `server.py` — FastAPI backend
- `index.html` — single-file frontend (Wise + Apple aesthetic, Instrument Serif + Geist)
- `render.yaml` — Render blueprint
- `requirements.txt` — pinned deps
- `config.example.json` — config schema
