"""
TradeFox IBKR Strategy Lab — local backend.

Implements the OAuth 2.0 + SSO + brokerage-session flow IBKR documented in the
TradeFox onboarding email, then proxies real Trading Web API endpoints to the
frontend at index.html. No mock data — every route hits api.ibkr.com.

Run:
    pip install -r requirements.txt
    cp config.example.json config.json   # fill in real values
    python server.py                     # http://127.0.0.1:8787
"""
from __future__ import annotations

import asyncio
import base64
import json
import math
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

ROOT = Path(__file__).parent
CONFIG_PATH = Path(os.getenv("CONFIG_PATH", ROOT / "config.json"))

OAUTH2_URL = "https://api.ibkr.com/oauth2"
GATEWAY_URL = "https://api.ibkr.com/gw"
CP_URL = "https://api.ibkr.com"
AUDIENCE = "/token"


# ──────────────────────────── config ────────────────────────────
@dataclass
class Config:
    ip: str = ""
    alternativeIps: list[str] = field(default_factory=list)
    clientId: str = ""
    clientKeyId: str = ""
    credential: str = ""
    privateKeyPath: str = ""
    accountId: str = ""
    scope: str = "sso-sessions.write"
    autoDetectIp: bool = True

    @classmethod
    def load(cls) -> "Config":
        from dataclasses import MISSING

        # Start from JSON if present, else empty.
        data: dict = {}
        if CONFIG_PATH.exists():
            try:
                data = json.loads(CONFIG_PATH.read_text())
            except Exception:
                data = {}

        # Production / Render: read overrides from env. ENV WINS over config.json
        # so secrets never need to be committed.
        ENV_KEYS = {
            "ip": "IBKR_IP",
            "clientId": "IBKR_CLIENT_ID",
            "clientKeyId": "IBKR_CLIENT_KEY_ID",
            "credential": "IBKR_CREDENTIAL",
            "privateKeyPath": "IBKR_PRIVATE_KEY_PATH",
            "accountId": "IBKR_ACCOUNT_ID",
            "scope": "IBKR_SCOPE",
        }
        for k, env in ENV_KEYS.items():
            if os.getenv(env):
                data[k] = os.getenv(env)

        # Inline private-key option for hosts (Render, Fly) that prefer env vars over
        # secret files. IBKR_PRIVATE_KEY may be the raw PEM or base64-encoded PEM.
        if os.getenv("IBKR_PRIVATE_KEY"):
            raw = os.getenv("IBKR_PRIVATE_KEY", "")
            pem = raw
            if "BEGIN" not in raw:
                try:
                    pem = base64.b64decode(raw).decode()
                except Exception:
                    pem = raw
            tmp = Path("/tmp/ibkr_private.pem")
            tmp.write_text(pem)
            tmp.chmod(0o600)
            data["privateKeyPath"] = str(tmp)

        if os.getenv("IBKR_ALTERNATIVE_IPS"):
            data["alternativeIps"] = [
                x.strip() for x in os.getenv("IBKR_ALTERNATIVE_IPS", "").split(",") if x.strip()
            ]
        if os.getenv("IBKR_AUTO_DETECT_IP") is not None:
            data["autoDetectIp"] = os.getenv("IBKR_AUTO_DETECT_IP", "true").lower() in ("1", "true", "yes")

        kwargs = {}
        for name, fld in cls.__dataclass_fields__.items():
            if name in data:
                kwargs[name] = data[name]
            elif fld.default is not MISSING:
                kwargs[name] = fld.default
            elif fld.default_factory is not MISSING:  # type: ignore[misc]
                kwargs[name] = fld.default_factory()  # type: ignore[misc]
        return cls(**kwargs)

    def save(self) -> None:
        CONFIG_PATH.write_text(json.dumps(self.__dict__, indent=2))

    def is_complete(self) -> bool:
        return all([
            self.clientId, self.clientKeyId,
            self.credential, self.privateKeyPath, self.accountId,
        ]) and (bool(self.ip) or self.autoDetectIp)


def detect_public_ip() -> str:
    """Auto-detect the egress IP IBKR will see. Falls back gracefully."""
    for url in ("https://api.ipify.org", "https://ifconfig.me", "https://ipinfo.io/ip"):
        try:
            r = httpx.get(url, timeout=5.0)
            ip = r.text.strip()
            if ip and len(ip) <= 45:
                return ip
        except Exception:
            continue
    return ""


# ──────────────────────────── session state ────────────────────────────
@dataclass
class Session:
    access_token: str = ""
    bearer_token: str = ""
    session_token: str = ""
    issued_at: float = 0.0
    last_tickle: float = 0.0
    ssodh_inited: bool = False
    accounts: list[dict] = field(default_factory=list)
    last_error: str = ""

    def is_authed(self) -> bool:
        # access_token expires in ~60 min per IBKR; refresh if older than 50.
        return bool(self.bearer_token) and (time.time() - self.issued_at) < 50 * 60

    def public(self) -> dict:
        return {
            "authed": self.is_authed(),
            "ssodh_inited": self.ssodh_inited,
            "issued_at": self.issued_at,
            "issued_age_seconds": int(time.time() - self.issued_at) if self.issued_at else None,
            "last_tickle_age_seconds": int(time.time() - self.last_tickle) if self.last_tickle else None,
            "session_token_present": bool(self.session_token),
            "accounts": self.accounts,
            "last_error": self.last_error,
        }


CFG = Config.load()
SESS = Session()


# ──────────────────────────── JWT helpers ────────────────────────────
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode().replace("+", "-").replace("/", "_").rstrip("=")


def _load_private_key():
    if not CFG.privateKeyPath:
        raise HTTPException(400, "privateKeyPath not configured")
    p = Path(CFG.privateKeyPath).expanduser()
    if not p.exists():
        raise HTTPException(400, f"Private key not found at {p}")
    return RSA.import_key(p.read_text().encode())


def _make_jws(header: dict, claims: dict) -> str:
    pk = _load_private_key()
    h = _b64(json.dumps(header, separators=(",", ":")).encode())
    c = _b64(json.dumps(claims, separators=(",", ":")).encode())
    payload = f"{h}.{c}"
    sig = PKCS1_v1_5.new(pk).sign(SHA256.new(payload.encode()))
    return f"{payload}.{_b64(sig)}"


def _client_assertion(url: str) -> str:
    now = math.floor(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": CFG.clientKeyId}
    if url == f"{OAUTH2_URL}/api/v1/token":
        claims = {
            "iss": CFG.clientId, "sub": CFG.clientId, "aud": AUDIENCE,
            "exp": now + 20, "iat": now - 10,
        }
    elif url == f"{GATEWAY_URL}/api/v1/sso-sessions":
        ip = CFG.ip
        if CFG.autoDetectIp:
            detected = detect_public_ip()
            if detected:
                ip = detected
                CFG.ip = detected  # remember it for the UI
        claims = {
            "ip": ip,
            "credential": CFG.credential,
            "iss": CFG.clientId,
            "exp": now + 86400,
            "iat": now,
        }
        if CFG.alternativeIps:
            claims["alternativeIps"] = list(CFG.alternativeIps)
    else:
        raise ValueError(f"Unknown assertion url: {url}")
    return _make_jws(header, claims)


# ──────────────────────────── IBKR calls ────────────────────────────
async def _http() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=30.0, headers={"User-Agent": "tradefox-strategy-lab/0.1"})


async def get_access_token() -> str:
    url = f"{OAUTH2_URL}/api/v1/token"
    form = {
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": _client_assertion(url),
        "grant_type": "client_credentials",
        "scope": CFG.scope,
    }
    async with await _http() as c:
        r = await c.post(url, data=form, headers={"Content-Type": "application/x-www-form-urlencoded"})
    if r.status_code != 200:
        raise HTTPException(r.status_code, f"oauth2/token failed: {r.text}")
    return r.json()["access_token"]


async def get_bearer_token(access_token: str) -> str:
    url = f"{GATEWAY_URL}/api/v1/sso-sessions"
    body = _client_assertion(url)
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/jwt"}
    async with await _http() as c:
        r = await c.post(url, headers=headers, content=body)
    if r.status_code != 200:
        raise HTTPException(r.status_code, f"sso-sessions failed: {r.text} (check ip claim)")
    return r.json()["access_token"]


async def tickle() -> str:
    headers = {"Authorization": f"Bearer {SESS.bearer_token}"}
    async with await _http() as c:
        r = await c.post(f"{CP_URL}/v1/api/tickle", headers=headers)
    if r.status_code != 200:
        raise HTTPException(r.status_code, f"tickle failed: {r.text}")
    SESS.last_tickle = time.time()
    j = r.json()
    return j.get("session", "")


async def ssodh_init() -> dict:
    headers = {"Authorization": f"Bearer {SESS.bearer_token}"}
    # Per the Postman collection IBKR ships, params go on the query string, not JSON.
    async with await _http() as c:
        r = await c.post(
            f"{CP_URL}/v1/api/iserver/auth/ssodh/init",
            headers=headers,
            params={"publish": "true", "compete": "true"},
        )
    if r.status_code == 410:
        # Newer paper accounts: brokerage session is auto-initialised; just check status.
        async with await _http() as c2:
            s = await c2.get(f"{CP_URL}/v1/api/iserver/auth/status", headers=headers)
        if s.status_code == 200:
            SESS.ssodh_inited = True
            return s.json() if s.text else {}
        raise HTTPException(s.status_code, f"auth/status after 410 failed: {s.text}")
    if r.status_code != 200:
        raise HTTPException(r.status_code, f"ssodh/init failed: {r.text}")
    SESS.ssodh_inited = True
    return r.json() if r.text else {}


async def fetch_accounts() -> list[dict]:
    headers = {"Authorization": f"Bearer {SESS.bearer_token}"}
    async with await _http() as c:
        r = await c.get(f"{CP_URL}/v1/api/iserver/accounts", headers=headers)
    if r.status_code != 200:
        raise HTTPException(r.status_code, f"/iserver/accounts failed: {r.text}")
    j = r.json()
    accs = j.get("accounts", []) if isinstance(j, dict) else j
    return [{"accountId": a} if isinstance(a, str) else a for a in accs]


async def ibkr_get(path: str, params: dict | None = None) -> Any:
    if not SESS.is_authed():
        raise HTTPException(401, "Not authenticated. POST /api/connect first.")
    headers = {"Authorization": f"Bearer {SESS.bearer_token}"}
    async with await _http() as c:
        r = await c.get(f"{CP_URL}{path}", headers=headers, params=params)
    if r.status_code >= 400:
        raise HTTPException(r.status_code, r.text)
    return r.json() if r.text else {}


async def ibkr_post(path: str, json_body: Any = None, params: dict | None = None) -> Any:
    if not SESS.is_authed():
        raise HTTPException(401, "Not authenticated. POST /api/connect first.")
    headers = {"Authorization": f"Bearer {SESS.bearer_token}", "Content-Type": "application/json"}
    async with await _http() as c:
        r = await c.post(f"{CP_URL}{path}", headers=headers, json=json_body, params=params)
    if r.status_code >= 400:
        raise HTTPException(r.status_code, r.text)
    return r.json() if r.text else {}


# ──────────────────────────── auto-tickle background loop ────────────────────────────
async def tickle_loop():
    while True:
        try:
            if SESS.is_authed():
                await tickle()
        except Exception as e:
            SESS.last_error = f"tickle: {e}"
        await asyncio.sleep(90)


# ──────────────────────────── FastAPI ────────────────────────────
app = FastAPI(title="TradeFox IBKR Strategy Lab")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


async def auto_connect_loop():
    """Try to connect on boot, then keep retrying every 60s until authed."""
    backoff = 5
    while True:
        if SESS.is_authed():
            await asyncio.sleep(60)
            continue
        if not CFG.is_complete():
            SESS.last_error = "Config incomplete — fill clientId/credential/privateKeyPath/accountId"
            await asyncio.sleep(15)
            continue
        # private key sanity check before we waste an HTTP roundtrip
        pk_path = Path(CFG.privateKeyPath).expanduser() if CFG.privateKeyPath else None
        if not pk_path or not pk_path.exists():
            SESS.last_error = f"Private key not found at {pk_path}"
            await asyncio.sleep(30)
            continue
        try:
            print(f"[auto-connect] attempting OAuth for {CFG.clientId} / {CFG.credential}")
            SESS.access_token = await get_access_token()
            SESS.bearer_token = await get_bearer_token(SESS.access_token)
            SESS.issued_at = time.time()
            SESS.session_token = await tickle()
            await ssodh_init()
            await asyncio.sleep(3)
            SESS.accounts = await fetch_accounts()
            SESS.last_error = ""
            backoff = 5
            print(f"[auto-connect] connected · accounts={[a.get('accountId') for a in SESS.accounts]}")
        except HTTPException as e:
            SESS.last_error = f"{e.status_code}: {e.detail}"
            print(f"[auto-connect] failed: {SESS.last_error}")
            backoff = min(backoff * 2, 300)
            await asyncio.sleep(backoff)
        except Exception as e:
            SESS.last_error = str(e)
            print(f"[auto-connect] error: {e}")
            backoff = min(backoff * 2, 300)
            await asyncio.sleep(backoff)
        else:
            await asyncio.sleep(60)


@app.on_event("startup")
async def _startup():
    asyncio.create_task(tickle_loop())
    asyncio.create_task(auto_connect_loop())


# ─── config ───
@app.get("/api/config")
def get_config():
    redacted = {**CFG.__dict__}
    if redacted.get("privateKeyPath"):
        redacted["privateKeyPath"] = "•••" + redacted["privateKeyPath"][-24:]
    redacted["complete"] = CFG.is_complete()
    return redacted


@app.post("/api/config")
async def set_config(payload: dict):
    for k in ("ip", "clientId", "clientKeyId", "credential", "privateKeyPath", "accountId", "scope"):
        if k in payload and payload[k] is not None:
            setattr(CFG, k, str(payload[k]).strip())
    if "autoDetectIp" in payload:
        CFG.autoDetectIp = bool(payload["autoDetectIp"])
    if "alternativeIps" in payload and payload["alternativeIps"] is not None:
        raw = payload["alternativeIps"]
        if isinstance(raw, str):
            raw = [x.strip() for x in raw.split(",")]
        CFG.alternativeIps = [ip for ip in (raw or []) if ip]
    CFG.save()
    return get_config()


@app.get("/api/whoami")
def whoami():
    """Return the public IP IBKR would see from this backend."""
    return {"ip": detect_public_ip()}


# ─── auth ───
@app.get("/api/session")
def get_session():
    return SESS.public() | {"config_complete": CFG.is_complete()}


@app.post("/api/connect")
async def connect():
    if not CFG.is_complete():
        raise HTTPException(400, "Config incomplete. POST /api/config first.")
    try:
        SESS.access_token = await get_access_token()
        SESS.bearer_token = await get_bearer_token(SESS.access_token)
        SESS.issued_at = time.time()
        SESS.session_token = await tickle()
        await ssodh_init()
        await asyncio.sleep(3)
        SESS.accounts = await fetch_accounts()
        SESS.last_error = ""
    except HTTPException as e:
        SESS.last_error = f"{e.status_code}: {e.detail}"
        raise
    except Exception as e:
        SESS.last_error = str(e)
        raise HTTPException(500, str(e))
    return SESS.public()


@app.post("/api/disconnect")
async def disconnect():
    if SESS.bearer_token:
        try:
            headers = {"Authorization": f"Bearer {SESS.bearer_token}"}
            async with await _http() as c:
                await c.post(f"{CP_URL}/v1/api/logout", headers=headers)
        except Exception:
            pass
    SESS.access_token = SESS.bearer_token = SESS.session_token = ""
    SESS.issued_at = SESS.last_tickle = 0
    SESS.ssodh_inited = False
    SESS.accounts = []
    return {"ok": True}


@app.post("/api/tickle")
async def tickle_now():
    return {"session": await tickle()}


# ─── accounts / portfolio ───
@app.get("/api/accounts")
async def accounts():
    return await ibkr_get("/v1/api/iserver/accounts")


@app.get("/api/portfolio/subaccounts")
async def portfolio_subaccounts():
    return await ibkr_get("/v1/api/portfolio/subaccounts")


@app.get("/api/portfolio/summary")
async def portfolio_summary():
    # IBKR requires /portfolio/subaccounts to be called first
    await ibkr_get("/v1/api/portfolio/subaccounts")
    return await ibkr_get(f"/v1/api/portfolio/{CFG.accountId}/summary")


@app.get("/api/portfolio/positions")
async def portfolio_positions(pageId: int = 0):
    await ibkr_get("/v1/api/portfolio/subaccounts")
    return await ibkr_get(f"/v1/api/portfolio/{CFG.accountId}/positions/{pageId}")


@app.get("/api/portfolio/ledger")
async def portfolio_ledger():
    await ibkr_get("/v1/api/portfolio/subaccounts")
    return await ibkr_get(f"/v1/api/portfolio/{CFG.accountId}/ledger")


# ─── forecast / event contracts ───
@app.get("/api/forecast/categories")
async def forecast_categories():
    return await ibkr_get("/v1/api/forecast/category/tree")


@app.get("/api/forecast/markets")
async def forecast_markets(underlyingConid: str, exchange: str = "FORECASTX"):
    """List leaf tradeable contracts under a parent forecast index.
    Returns each strike × Y/N leg with its own conid, expiry, strike, and label.
    This is the canonical drill-down — the /forecast/category/tree response
    only contains parent indices."""
    return await ibkr_get(
        "/v1/api/forecast/contract/market",
        params={"underlyingConid": underlyingConid, "exchange": exchange},
    )


@app.get("/api/forecast/details")
async def forecast_details(conid: str):
    # IBKR's signature is singular conid=, not conids=
    return await ibkr_get("/v1/api/forecast/contract/details", params={"conid": conid})


@app.get("/api/forecast/rules")
async def forecast_rules(conid: str):
    return await ibkr_get("/v1/api/forecast/contract/rules", params={"conid": conid})


@app.get("/api/forecast/schedules")
async def forecast_schedules(conid: str):
    return await ibkr_get("/v1/api/forecast/contract/schedules", params={"conid": conid})


@app.get("/api/forecast/full")
async def forecast_full(conid: str, product_conid: str | None = None):
    """One-stop call for the drawer: contract info + rules + schedules + secdef.
    Per John C. (IBKR API Integration, May 2026), the canonical path for rules
    is /iserver/contract/{conid}/info-and-rules — returns both info and rules
    in one call. The old /forecast/contract/* endpoints are kept as fallbacks
    in case the contract is structured for them.
    """
    out: dict[str, Any] = {"conid": conid, "product_conid": product_conid}
    async def safe(name: str, path: str, params: dict | None = None):
        try:
            out[name] = await ibkr_get(path, params=params)
        except HTTPException as e:
            out[name] = {"_error": f"{e.status_code}: {e.detail}"}
        except Exception as e:
            out[name] = {"_error": str(e)}

    # Primary: the combined info+rules endpoint
    await safe("info_and_rules", f"/v1/api/iserver/contract/{conid}/info-and-rules")
    # Forecast endpoints (singular `conid=` per Postman collection)
    await safe("rules",       "/v1/api/forecast/contract/rules",     {"conid": conid})
    await safe("schedules",   "/v1/api/forecast/contract/schedules", {"conid": conid})
    await safe("details",     "/v1/api/forecast/contract/details",   {"conid": conid})
    # Drill-down: enumerate leaf tradeable contracts under this parent (if it IS a parent)
    await safe("leaves",      "/v1/api/forecast/contract/market",
               {"underlyingConid": conid, "exchange": "FORECASTX"})
    # Security definition (always handy)
    await safe("secdef",      "/v1/api/iserver/secdef/info",         {"conid": conid})
    return out


@app.get("/api/forecast/bulk-drill")
async def forecast_bulk_drill(
    parents: str,
    exchange: str = "FORECASTX",
    fields: str = "84,85,86,87,88,7638,8393,8394,6509",
    concurrency: int = 8,
):
    """Drill many parent forecast events at once and return their tradeable legs
    with current snapshots. Single round-trip from the browser instead of 1k.

    `parents` is a comma-separated list of underlying parent conids.
    Returns: { events: { "<parentConid>": { legs: [{conid, strikeLabel, side, bid, ask, askSize, bidSize, volume, oi, yesPct, noPct}] } } }
    """
    parent_ids = [p.strip() for p in parents.split(",") if p.strip()]
    if not parent_ids:
        return {"events": {}}

    sem = asyncio.Semaphore(max(1, min(concurrency, 16)))

    async def fetch_legs(pid: str):
        async with sem:
            try:
                r = await ibkr_get(
                    "/v1/api/forecast/contract/market",
                    params={"underlyingConid": pid, "exchange": exchange},
                )
                return pid, (r or {}).get("contracts", []) or []
            except Exception:
                return pid, []

    leg_results = await asyncio.gather(*[fetch_legs(pid) for pid in parent_ids])

    # Collect every YES-side leg conid; that's what carries the headline price.
    yes_legs: dict[str, list[dict]] = {}
    all_conids: list[str] = []
    for pid, contracts in leg_results:
        legs = []
        for c in contracts:
            if c.get("side") != "Y":
                continue
            legs.append({
                "conid": c.get("conid"),
                "strikeLabel": c.get("strike_label") or c.get("strike") or "",
                "side": c.get("side"),
            })
            if c.get("conid") is not None:
                all_conids.append(str(c["conid"]))
        yes_legs[pid] = legs

    # Snapshot warmup + real pull in chunks of 30.
    async def snap_pass():
        out: dict[str, dict] = {}
        for i in range(0, len(all_conids), 30):
            chunk = all_conids[i : i + 30]
            try:
                r = await ibkr_get(
                    "/v1/api/iserver/marketdata/snapshot",
                    params={"conids": ",".join(chunk), "fields": fields},
                )
                items = r if isinstance(r, list) else (r or {}).get("snapshots", []) or []
                for s in items:
                    cid = s.get("conid") if isinstance(s, dict) else None
                    if cid is None and isinstance(s, dict):
                        cid = s.get("conidEx")
                    if cid is not None:
                        out[str(cid)] = s
            except Exception:
                continue
        return out

    if all_conids:
        await snap_pass()                # warmup
        await asyncio.sleep(1.5)
        snap_by_conid = await snap_pass()
    else:
        snap_by_conid = {}

    def fp(v):
        try:
            if v is None:
                return None
            n = float(v)
            if n != n:  # NaN
                return None
            return n
        except (ValueError, TypeError):
            return None

    events: dict[str, dict] = {}
    for pid, legs in yes_legs.items():
        out_legs = []
        for l in legs:
            s = snap_by_conid.get(str(l["conid"]), {}) or {}
            out_legs.append({
                "conid":       l["conid"],
                "strikeLabel": l["strikeLabel"],
                "side":        l["side"],
                "bid":         fp(s.get("84")),
                "ask":         fp(s.get("86")),
                "askSize":     fp(s.get("85")),
                "bidSize":     fp(s.get("88")),
                "volume":      fp(s.get("87")),
                "oi":          fp(s.get("7638")),
                "yesPct":      fp(s.get("8393")),
                "noPct":       fp(s.get("8394")),
                "mdAvail":     s.get("6509"),
            })
        events[pid] = {"legs": out_legs}
    return {"events": events}


# ─── market data ───
@app.get("/api/marketdata/snapshot")
async def md_snapshot(conids: str, fields: str = "84,85,86,87,88,7638,8393,8394,6509"):
    # ForecastEx (per IBKR / John C., May 2026):
    #   84   Bid              86   Ask
    #   85   Ask Size         88   Bid Size
    #   87   Volume           7638 Option Open Interest
    #   8393 YES probability  8394 NO probability
    #   6509 Market data availability flag (RealTime / Delayed / Frozen / etc.)
    # Equity-style fields (31=Last) are typically blank on event contracts.
    return await ibkr_get("/v1/api/iserver/marketdata/snapshot", params={"conids": conids, "fields": fields})


@app.get("/api/marketdata/history")
async def md_history(conid: str, period: str = "1d", bar: str = "5min", outsideRth: bool = False):
    return await ibkr_get("/v1/api/iserver/marketdata/history",
                          params={"conid": conid, "period": period, "bar": bar, "outsideRth": str(outsideRth).lower()})


# ─── orders ───
@app.get("/api/orders")
async def orders():
    return await ibkr_get("/v1/api/iserver/account/orders")


@app.get("/api/trades")
async def trades():
    return await ibkr_get("/v1/api/iserver/account/trades")


@app.post("/api/orders/whatif")
async def whatif(payload: dict):
    body = {"orders": payload.get("orders", [])}
    return await ibkr_post(f"/v1/api/iserver/account/{CFG.accountId}/orders/whatif", json_body=body)


@app.post("/api/orders/place")
async def place(payload: dict):
    body = {"orders": payload.get("orders", [])}
    return await ibkr_post(f"/v1/api/iserver/account/{CFG.accountId}/orders", json_body=body)


@app.post("/api/orders/reply/{reply_id}")
async def reply(reply_id: str, payload: dict):
    return await ibkr_post(f"/v1/api/iserver/reply/{reply_id}", json_body={"confirmed": bool(payload.get("confirmed", True))})


@app.delete("/api/orders/{order_id}")
async def cancel(order_id: str):
    if not SESS.is_authed():
        raise HTTPException(401, "Not authenticated.")
    headers = {"Authorization": f"Bearer {SESS.bearer_token}"}
    async with await _http() as c:
        r = await c.delete(f"{CP_URL}/v1/api/iserver/account/{CFG.accountId}/order/{order_id}", headers=headers)
    if r.status_code >= 400:
        raise HTTPException(r.status_code, r.text)
    return r.json() if r.text else {}


# ─── search / generic passthrough ───
@app.get("/api/search/secdef")
async def secdef(symbol: str, secType: str = "FUT"):
    return await ibkr_get("/v1/api/iserver/secdef/search", params={"symbol": symbol, "secType": secType})


@app.api_route("/api/passthrough/{path:path}", methods=["GET", "POST", "DELETE"])
async def passthrough(path: str, request: Request):
    """Escape hatch — proxy any IBKR Trading Web API path with auth attached."""
    if not SESS.is_authed():
        raise HTTPException(401, "Not authenticated.")
    method = request.method
    headers = {"Authorization": f"Bearer {SESS.bearer_token}"}
    body = await request.body()
    params = dict(request.query_params)
    async with await _http() as c:
        r = await c.request(method, f"{CP_URL}/{path}", headers=headers, params=params, content=body)
    try:
        return JSONResponse(r.json(), status_code=r.status_code)
    except Exception:
        return JSONResponse({"raw": r.text}, status_code=r.status_code)


# ────────────────────────────────────────────────────────────────────────────
# WebSocket proxy: bridge browser ↔ IBKR's wss://api.ibkr.com/v1/api/ws.
# IBKR's WS path requires the bearer token in the URL and the session token
# as the first message. We don't expose those to the browser — the proxy
# holds them and forwards subscriptions / quote updates.
# ────────────────────────────────────────────────────────────────────────────
import websockets  # noqa: E402  (after FastAPI imports for clarity)
from fastapi import WebSocket, WebSocketDisconnect  # noqa: E402


@app.websocket("/api/ws")
async def ws_proxy(client: WebSocket):
    await client.accept()
    if not SESS.is_authed():
        await client.send_json({"type": "error", "error": "not_authed"})
        await client.close()
        return

    upstream_url = f"wss://api.ibkr.com/v1/api/ws?bearer_token={SESS.bearer_token}"
    try:
        async with websockets.connect(upstream_url, ping_interval=30, max_size=2**22) as up:
            # IBKR requires the session token as the first message, JSON-encoded.
            await up.send(json.dumps({"session": SESS.session_token}))

            async def from_browser():
                """Forward subscribe/unsubscribe commands from browser to IBKR."""
                try:
                    while True:
                        msg = await client.receive_text()
                        await up.send(msg)
                except WebSocketDisconnect:
                    return

            async def from_ibkr():
                """Forward quote updates / topic messages back to browser."""
                async for raw in up:
                    text = raw if isinstance(raw, str) else raw.decode("utf-8", "replace")
                    try:
                        await client.send_text(text)
                    except Exception:
                        return

            await asyncio.gather(from_browser(), from_ibkr())
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await client.send_json({"type": "error", "error": str(e)})
        except Exception:
            pass
    finally:
        try:
            await client.close()
        except Exception:
            pass


# ────────────────────────────────────────────────────────────────────────────
# Backtest engine.
# Event-driven: pulls real /iserver/marketdata/history bars for each conid in
# the universe, walks them oldest → newest, evaluates a strategy at each bar,
# and simulates fills with conservative cost assumptions. No fabricated prices.
# Returns a real equity curve, trade log, and post-cost metrics.
#
# The 7 PRD strategies are templates — each one is a callable that takes
# (bar, position, params) and returns ('BUY' | 'SELL' | None, qty, reason).
# We ship FairValueEdge as a fully-implemented baseline; the others have
# placeholder signal functions that disable themselves until configured.
# ────────────────────────────────────────────────────────────────────────────
from dataclasses import asdict  # noqa: E402
import math as _math  # noqa: E402


def _conservative_fill(side: str, bar: dict, qty: int, slippage_cents: float = 0.5) -> tuple[float, float]:
    """Buys lift the ask, sells hit the bid; we only have OHLCV here, so use
    close ± half-tick to approximate. Returns (fill_price, fees)."""
    px = float(bar.get("c") or bar.get("close") or 0.0)
    slip = slippage_cents / 100.0
    if side == "BUY":
        px = px + slip
    else:
        px = px - slip
    px = max(0.01, min(0.99, px))
    # ForecastEx fee model isn't published consistently; use a reasonable
    # placeholder of 1c per contract per side. Replace once IBKR confirms.
    fees = 0.01 * qty
    return px, fees


def _fair_value_signal(bar: dict, position: int, params: dict) -> tuple[str | None, int, str]:
    """Trade when |market - manual_fair_value| > min_edge.
    For an MVP we accept a fair_value param (constant or piecewise) — when
    you wire a model, this is the only function that needs to change."""
    fair = float(params.get("fair_value", 0.5))
    min_edge = float(params.get("min_edge", 0.03))
    qty = int(params.get("qty", 100))
    px = float(bar.get("c") or 0.0)
    if px <= 0:
        return None, 0, "no_price"
    edge_buy = fair - px
    edge_sell = px - fair
    if position == 0 and edge_buy >= min_edge:
        return "BUY", qty, f"edge_buy={edge_buy:.3f}"
    if position > 0 and edge_sell >= min_edge:
        return "SELL", position, f"edge_sell={edge_sell:.3f}"
    return None, 0, ""


STRATEGIES = {
    "fair_value_edge":   _fair_value_signal,
    # The following are stubs — accept the same params interface, return no
    # signal until their MVP signal logic is filled in. They show in the UI
    # as templates so the user can see the planned shape.
    "short_tail":        lambda b, p, par: (None, 0, "stub"),
    "longshot_catalyst": lambda b, p, par: (None, 0, "stub"),
    "passive_mm":        lambda b, p, par: (None, 0, "stub"),
    "cross_rv":          lambda b, p, par: (None, 0, "stub"),
    "drift_momentum":    lambda b, p, par: (None, 0, "stub"),
    "mean_reversion":    lambda b, p, par: (None, 0, "stub"),
}


@app.post("/api/backtest/run")
async def backtest_run(payload: dict):
    """Run an event-driven backtest over real IBKR history bars.

    Body:
      strategy:   one of STRATEGIES keys
      conids:     list[int]  — universe to test
      period:     "1m" | "3m" | "6m" | "1y"   (passed through to /history)
      bar:        "1d" | "1h" | "5min" | …
      bankroll:   starting cash, default 10_000
      params:     strategy-specific dict (e.g. fair_value, min_edge, qty)
    """
    strat = payload.get("strategy", "fair_value_edge")
    if strat not in STRATEGIES:
        raise HTTPException(400, f"unknown strategy: {strat}")
    conids = payload.get("conids") or []
    if not conids:
        raise HTTPException(400, "conids[] is required")
    period = payload.get("period", "3m")
    bar    = payload.get("bar", "1d")
    bankroll = float(payload.get("bankroll", 10_000))
    params   = payload.get("params", {})

    signal_fn = STRATEGIES[strat]
    cash = bankroll
    positions: dict[int, dict] = {}     # conid -> {qty, avg_px}
    trades: list[dict] = []
    equity_pts: list[dict] = []
    bars_by_conid: dict[int, list[dict]] = {}

    # Pull history per conid in series; cheap enough at MVP scale, easy to parallelise later.
    for cid in conids:
        try:
            r = await ibkr_get(
                "/v1/api/iserver/marketdata/history",
                params={"conid": str(cid), "period": period, "bar": bar},
            )
            bars_by_conid[int(cid)] = r.get("data", []) or []
        except HTTPException as e:
            bars_by_conid[int(cid)] = []
            trades.append({"ts": 0, "conid": cid, "note": f"history error: {e.detail}"})

    # Build a single time-ordered event stream so PnL marks across markets correctly.
    events: list[tuple[int, int, dict]] = []
    for cid, bars in bars_by_conid.items():
        for b in bars:
            t = int(b.get("t") or b.get("time") or 0)
            events.append((t, cid, b))
    events.sort(key=lambda e: e[0])

    if not events:
        return {"error": "no_history", "bars_by_conid": {str(k): len(v) for k, v in bars_by_conid.items()}}

    for ts, cid, bar in events:
        pos = positions.get(cid, {"qty": 0, "avg_px": 0.0})
        action, qty, reason = signal_fn(bar, pos["qty"], params)
        if action and qty > 0:
            fill_px, fees = _conservative_fill(action, bar, qty)
            cost = fill_px * qty + fees
            if action == "BUY":
                cash -= cost
                new_qty = pos["qty"] + qty
                pos["avg_px"] = ((pos["avg_px"] * pos["qty"]) + fill_px * qty) / max(1, new_qty)
                pos["qty"] = new_qty
            else:  # SELL
                cash += fill_px * qty - fees
                pos["qty"] -= qty
                if pos["qty"] <= 0:
                    pos["qty"] = 0
                    pos["avg_px"] = 0.0
            positions[cid] = pos
            trades.append({
                "ts": ts, "conid": cid, "side": action, "qty": qty,
                "fill_px": round(fill_px, 4), "fees": round(fees, 4), "reason": reason,
            })

        # mark-to-market across all positions at this timestamp
        mtm = cash
        for c2, p2 in positions.items():
            last = bar["c"] if c2 == cid else None
            if last is None:
                bs = bars_by_conid.get(c2, [])
                # find the latest bar for c2 with t <= ts
                last_bar = next((bb for bb in reversed(bs) if (bb.get("t") or 0) <= ts), None)
                last = (last_bar or {}).get("c") or p2["avg_px"]
            mtm += float(last) * p2["qty"]
        equity_pts.append({"ts": ts, "equity": round(mtm, 2)})

    # Final settlement at the last available price (we can't see resolution outcome here)
    final_equity = equity_pts[-1]["equity"] if equity_pts else bankroll
    peak = bankroll
    max_dd = 0.0
    for p in equity_pts:
        peak = max(peak, p["equity"])
        dd = (peak - p["equity"]) / max(1.0, peak)
        max_dd = max(max_dd, dd)

    realised = [t for t in trades if t.get("side") == "SELL"]
    winners = [t for t in realised]  # MVP: rough win/loss requires entry pairing — skip until needed
    metrics = {
        "starting_bankroll": bankroll,
        "ending_equity":     round(final_equity, 2),
        "net_pnl":           round(final_equity - bankroll, 2),
        "net_roi_pct":       round(((final_equity / bankroll) - 1.0) * 100.0, 3),
        "max_drawdown_pct":  round(max_dd * 100.0, 3),
        "trade_count":       len(trades),
        "events":            len(events),
        "conids":            len(conids),
        "strategy":          strat,
        "period":            period,
        "bar":               bar,
    }
    return {
        "metrics": metrics,
        "equity_curve": equity_pts,
        "trades": trades,
        "params": params,
    }


@app.get("/api/backtest/strategies")
def backtest_strategies():
    return {"strategies": list(STRATEGIES.keys())}


# ─── static index ───
@app.get("/")
def root():
    return FileResponse(ROOT / "index.html")


@app.get("/healthz")
def healthz():
    return {"ok": True, "ts": time.time()}


# Mount any future static assets (e.g. /assets/*)
if (ROOT / "assets").exists():
    app.mount("/assets", StaticFiles(directory=ROOT / "assets"), name="assets")


if __name__ == "__main__":
    # Bind to 0.0.0.0 whenever PORT is set (Render, Fly, Railway, Heroku all set it).
    # Locally we keep 127.0.0.1 so the server isn't on the LAN by default.
    in_cloud = bool(os.getenv("PORT"))
    host = os.getenv("HOST") or ("0.0.0.0" if in_cloud else "127.0.0.1")
    port = int(os.getenv("PORT", "8787"))
    print(f"TradeFox Strategy Lab → http://{host}:{port}  (cloud={in_cloud})")
    uvicorn.run(app, host=host, port=port, log_level="info")
