#!/usr/bin/env python3
"""
WireShield 2FA Authentication Service
Lightweight, secure pre-connection 2FA validation for WireGuard VPN.
"""

import os
import sys
import json
import sqlite3
import hashlib
import hmac
import secrets
import logging
import asyncio
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Form, Request, Response, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import uvicorn
import subprocess
import threading
from starlette.middleware.gzip import GZipMiddleware
import pyotp
import qrcode
from io import BytesIO
import base64
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
import shutil

# ============================================================================
# Configuration
# ============================================================================
def getenv_multi(default: str, *names: str) -> str:
    """Return the first found environment value among provided names."""
    for name in names:
        val = os.getenv(name)
        if val is not None and val != "":
            return val
    return default

LOG_LEVEL = getenv_multi("INFO", "WS_2FA_LOG_LEVEL", "2FA_LOG_LEVEL")
AUTH_DB_PATH = getenv_multi("/etc/wireshield/2fa/auth.db", "WS_2FA_DB_PATH", "2FA_DB_PATH")
AUTH_HOST = getenv_multi("0.0.0.0", "WS_2FA_HOST", "2FA_HOST")
AUTH_PORT = int(getenv_multi("443", "WS_2FA_PORT", "2FA_PORT"))
AUTH_HTTP_PORT = int(getenv_multi("80", "WS_2FA_HTTP_PORT", "2FA_HTTP_PORT"))
SSL_CERT = getenv_multi("/etc/wireshield/2fa/cert.pem", "WS_2FA_SSL_CERT", "2FA_SSL_CERT")
SSL_KEY = getenv_multi("/etc/wireshield/2fa/key.pem", "WS_2FA_SSL_KEY", "2FA_SSL_KEY")
SSL_ENABLED = getenv_multi("true", "WS_2FA_SSL_ENABLED", "2FA_SSL_ENABLED").lower() in ("true", "1", "yes")
SSL_TYPE = getenv_multi("self-signed", "WS_2FA_SSL_TYPE", "2FA_SSL_TYPE")  # self-signed, letsencrypt
TFA_DOMAIN = getenv_multi("", "WS_2FA_DOMAIN", "2FA_DOMAIN")
TFA_HOSTNAME = getenv_multi("127.0.0.1", "WS_HOSTNAME_2FA", "HOSTNAME_2FA")
SECRET_KEY = getenv_multi("", "WS_2FA_SECRET_KEY", "2FA_SECRET_KEY")  # Must be set in production
SESSION_TIMEOUT_MINUTES = int(getenv_multi("1440", "WS_2FA_SESSION_TIMEOUT", "2FA_SESSION_TIMEOUT"))  # 24h default
RATE_LIMIT_MAX_REQUESTS = int(getenv_multi("30", "WS_2FA_RATE_LIMIT_MAX_REQUESTS", "2FA_RATE_LIMIT_MAX_REQUESTS"))
RATE_LIMIT_WINDOW_SECONDS = int(getenv_multi("60", "WS_2FA_RATE_LIMIT_WINDOW", "2FA_RATE_LIMIT_WINDOW"))
WIREGUARD_PARAMS_PATH = getenv_multi("/etc/wireguard/params", "WS_WIREGUARD_PARAMS", "WIREGUARD_PARAMS")
WG_INTERFACE = getenv_multi("", "WS_WG_INTERFACE", "WG_INTERFACE", "WS_SERVER_WG_NIC")
SESSION_IDLE_TIMEOUT_SECONDS = int(getenv_multi("180", "WS_2FA_SESSION_IDLE_TIMEOUT", "2FA_SESSION_IDLE_TIMEOUT"))

# Determine UI access URL based on config
if TFA_DOMAIN:
    UI_BASE_URL = f"https://{TFA_DOMAIN}"
else:
    UI_BASE_URL = f"https://{TFA_HOSTNAME}"

# ============================================================================
# Logging
# ============================================================================
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def _load_wireguard_params() -> Dict[str, str]:
    """Read /etc/wireguard/params (created by installer) for interface data."""
    params: Dict[str, str] = {}
    try:
        with open(WIREGUARD_PARAMS_PATH, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                params[key.strip()] = value.strip()
    except FileNotFoundError:
        logger.debug("WireGuard params file not found at %s", WIREGUARD_PARAMS_PATH)
    except Exception as exc:  # pragma: no cover - best effort helper
        logger.debug("WireGuard params parse error: %s", exc)
    return params


def _ensure_wg_interface() -> str:
    """Determine which WireGuard interface to monitor for peer activity."""
    global WG_INTERFACE
    if WG_INTERFACE:
        return WG_INTERFACE
    params = _load_wireguard_params()
    WG_INTERFACE = params.get("SERVER_WG_NIC") or "wg0"
    return WG_INTERFACE

# ============================================================================
# Database
# ============================================================================
def init_db():
    """Initialize or migrate SQLite database."""
    os.makedirs(os.path.dirname(AUTH_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(AUTH_DB_PATH)
    c = conn.cursor()
    
    # Users table: stores 2FA secrets and metadata
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT UNIQUE NOT NULL,
            totp_secret TEXT,
            backup_codes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            enabled BOOLEAN DEFAULT 1
        )
    ''')
    
    # Sessions table: tracks active 2FA sessions
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            device_ip TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES users(client_id)
        )
    ''')
    
    # Audit log table: security audit trail
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT,
            action TEXT NOT NULL,
            status TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    # Migrations: add wg_ipv4/wg_ipv6 columns if missing
    try:
        c.execute('ALTER TABLE users ADD COLUMN wg_ipv4 TEXT')
    except Exception:
        pass
    try:
        c.execute('ALTER TABLE users ADD COLUMN wg_ipv6 TEXT')
    except Exception:
        pass
    conn.close()
    logger.info(f"Database initialized at {AUTH_DB_PATH}")

def get_db():
    """Get database connection."""
    conn = sqlite3.connect(AUTH_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ============================================================================
# Security Utils
# ============================================================================
def generate_session_token() -> str:
    """Generate secure session token."""
    return secrets.token_urlsafe(32)

def hash_session_token(token: str) -> str:
    """Hash session token for storage."""
    return hashlib.sha256(token.encode()).hexdigest()

def verify_session_token(token: str, stored_hash: str) -> bool:
    """Verify session token."""
    return hmac.compare_digest(hash_session_token(token), stored_hash)

def audit_log(client_id: Optional[str], action: str, status: str, ip_address: str):
    """Log security events."""
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO audit_log (client_id, action, status, ip_address) VALUES (?, ?, ?, ?)",
        (client_id, action, status, ip_address)
    )
    conn.commit()
    conn.close()
    logger.info(f"Audit: {action} - {status} (Client: {client_id}, IP: {ip_address})")

# ============================================================================
# FastAPI App
# ============================================================================
app = FastAPI(
    title="WireShield 2FA Auth",
    version="1.0.0",
    docs_url=None,  # Disable docs in production
    redoc_url=None,
    openapi_url=None,
)

# Enable gzip compression to reduce payload size for faster loads
app.add_middleware(GZipMiddleware, minimum_size=500)

# HTTP to HTTPS redirect middleware (for captive portal)
@app.middleware("http")
async def redirect_http_to_https(request: Request, call_next):
    """Redirect HTTP requests to HTTPS."""
    # Check if request came through HTTP (not forwarded from reverse proxy)
    if request.url.scheme == "http":
        # Build HTTPS URL (standard port 443)
        https_url = str(request.url).replace("http://", "https://", 1)
        return Response(status_code=307, headers={"Location": https_url})
    
    response = await call_next(request)
    return response

# ----------------------------------------------------------------------------
# Lightweight HTTP redirector (port 8080) for captive portal
# ----------------------------------------------------------------------------
class _RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            target = UI_BASE_URL + "/"
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<html><head><meta http-equiv='refresh' content='0;url={target}'/></head><body>Redirecting to <a href='{target}'>WireShield 2FA</a>...</body></html>".encode("utf-8"))
        except Exception:
            pass

    def log_message(self, format, *args):
        return  # quiet

def _start_http_redirector_ipv4():
    try:
        httpd = HTTPServer(("0.0.0.0", AUTH_HTTP_PORT), _RedirectHandler)
        logger.info(f"HTTP redirector listening on 0.0.0.0:{AUTH_HTTP_PORT}")
        httpd.serve_forever()
    except Exception as e:
        logger.debug(f"HTTP redirector IPv4 failed: {e}")

def _start_http_redirector_ipv6():
    try:
        class HTTPServerV6(HTTPServer):
            address_family = socket.AF_INET6
        httpd6 = HTTPServerV6(("::", AUTH_HTTP_PORT), _RedirectHandler)
        logger.info(f"HTTP redirector listening on [::]:{AUTH_HTTP_PORT}")
        httpd6.serve_forever()
    except Exception as e:
        logger.debug(f"HTTP redirector IPv6 failed: {e}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["127.0.0.1", "localhost"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# ============================================================================
# ============================================================================
# Rate Limiting (simple sliding window by client IP + path)
# ============================================================================
class RateLimiter:
    """Minimal in-memory rate limiter to throttle abusive bursts."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def __call__(self, request: Request):
        # Combine client IP and path so limits are per-endpoint per-client.
        client_ip = request.client.host if request and request.client else "unknown"
        key = f"{client_ip}:{request.url.path if request else 'unknown'}"
        now = time.time()

        async with self._lock:
            bucket = self._hits[key]
            # Drop entries outside the window.
            cutoff = now - self.window_seconds
            while bucket and bucket[0] < cutoff:
                bucket.popleft()

            if len(bucket) >= self.max_requests:
                raise HTTPException(status_code=429, detail="Too many requests, slow down")

            bucket.append(now)


rate_limiter = RateLimiter(
    max_requests=RATE_LIMIT_MAX_REQUESTS,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)

# ============================================================================
# Traffic Gating via ipset
# ============================================================================
def _extract_ips_from_allowed_field(field: str) -> set[str]:
    """Split WireGuard allowed IP descriptors into raw IP strings."""
    ips: set[str] = set()
    for chunk in field.split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        if '/' in chunk:
            chunk = chunk.split('/', 1)[0]
        ips.add(chunk)
    return ips


def _ipset(cmd: list[str]) -> None:
    try:
        subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        logger.debug(f"ipset command failed: {cmd} ({e})")

def ensure_ipsets():
    """Ensure ipset sets exist (created in WireGuard PostUp, but safe to re-assert)."""
    _ipset(["ipset", "create", "ws_2fa_allowed_v4", "hash:ip", "family", "inet", "-exist"])
    _ipset(["ipset", "create", "ws_2fa_allowed_v6", "hash:ip", "family", "inet6", "-exist"])

def allow_client_by_id(client_id: str) -> None:
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT wg_ipv4, wg_ipv6 FROM users WHERE client_id = ?", (client_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return
    v4 = row[0] or ""
    v6 = row[1] or ""
    ensure_ipsets()
    if v4:
        _ipset(["ipset", "add", "ws_2fa_allowed_v4", v4, "-exist"])
    if v6:
        _ipset(["ipset", "add", "ws_2fa_allowed_v6", v6, "-exist"])

def remove_client_by_id(client_id: str) -> None:
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT wg_ipv4, wg_ipv6 FROM users WHERE client_id = ?", (client_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return
    v4 = row[0] or ""
    v6 = row[1] or ""
    if v4:
        _ipset(["ipset", "del", "ws_2fa_allowed_v4", v4])
    if v6:
        _ipset(["ipset", "del", "ws_2fa_allowed_v6", v6])

def _sync_ipsets_from_sessions():
    """Periodically remove clients without any active session from ipsets."""
    while True:
        try:
            conn = get_db()
            c = conn.cursor()
            # Active clients: with any non-expired session
            c.execute("SELECT DISTINCT client_id FROM sessions WHERE expires_at > datetime('now')")
            active = set(row[0] for row in c.fetchall())
            # All users
            c.execute("SELECT client_id, wg_ipv4, wg_ipv6 FROM users")
            users = c.fetchall()
            conn.close()
            ensure_ipsets()
            # Remove non-active clients from ipsets
            for client_id, v4, v6 in users:
                if client_id not in active:
                    if v4:
                        _ipset(["ipset", "del", "ws_2fa_allowed_v4", v4])
                    if v6:
                        _ipset(["ipset", "del", "ws_2fa_allowed_v6", v6])
        except Exception as e:
            logger.debug(f"ipset sync error: {e}")
        finally:
            time.sleep(60)


def _monitor_wireguard_sessions():
    """Drop 2FA sessions once peers disconnect from the WireGuard interface."""
    if SESSION_IDLE_TIMEOUT_SECONDS <= 0:
        logger.info("WireGuard session monitor disabled (timeout <= 0)")
        return

    wg_binary = shutil.which("wg")
    if not wg_binary:
        logger.warning("WireGuard binary 'wg' not found; session monitor disabled")
        return

    interface = _ensure_wg_interface()
    if not interface:
        logger.warning("WireGuard interface unknown; session monitor disabled")
        return

    poll_interval = max(30, SESSION_IDLE_TIMEOUT_SECONDS // 2)
    logger.info(
        "WireGuard session monitor active on %s (idle timeout %ss)",
        interface,
        SESSION_IDLE_TIMEOUT_SECONDS,
    )

    while True:
        stale_clients: list[str] = []
        try:
            proc = subprocess.run(
                [wg_binary, "show", interface, "dump"],
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.strip() or "wg show dump failed")

            lines = [line for line in proc.stdout.strip().splitlines() if line]
            if len(lines) <= 1:
                continue

            active_ips: set[str] = set()
            now = int(time.time())
            for line in lines[1:]:
                parts = line.split('\t')
                if len(parts) < 5:
                    continue
                allowed_field = parts[3]
                try:
                    handshake_ts = int(parts[4])
                except ValueError:
                    handshake_ts = 0
                if handshake_ts == 0:
                    continue
                if (now - handshake_ts) > SESSION_IDLE_TIMEOUT_SECONDS:
                    continue
                active_ips.update(_extract_ips_from_allowed_field(allowed_field))

            conn = get_db()
            try:
                c = conn.cursor()
                c.execute(
                    """
                    SELECT DISTINCT u.client_id, u.wg_ipv4, u.wg_ipv6
                    FROM users u
                    JOIN sessions s ON s.client_id = u.client_id
                    """
                )
                rows = c.fetchall()
                for row in rows:
                    client_id = row["client_id"]
                    v4 = (row["wg_ipv4"] or "").strip()
                    v6 = (row["wg_ipv6"] or "").strip()
                    if (v4 and v4 in active_ips) or (v6 and v6 in active_ips):
                        continue
                    stale_clients.append(client_id)

                if stale_clients:
                    for cid in stale_clients:
                        c.execute("DELETE FROM sessions WHERE client_id = ?", (cid,))
                    conn.commit()
            finally:
                conn.close()

            for cid in stale_clients:
                remove_client_by_id(cid)
                audit_log(cid, "SESSION_MONITOR", "expired_on_disconnect", "wireguard-monitor")
        except Exception as exc:
            logger.debug(f"WireGuard session monitor error: {exc}")

        time.sleep(poll_interval)


# ============================================================================
# Routes: Health & Info
# ============================================================================
@app.get("/health", tags=["health"])
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "wireshield-2fa"}

# ============================================================================
# Routes: 2FA Setup & Verification
# ============================================================================
@app.get("/", response_class=HTMLResponse, tags=["ui"])
async def root(request: Request, client_id: Optional[str] = None):
    """
    Serve 2FA setup/verification UI.
    Supports:
    - Direct access with ?client_id=<id>
    - Auto-discovery mode (detect client_id from database via IP)
    """
    ip_address = request.client.host if request and request.client else "unknown"
    
    # If client_id not provided, try to discover from IP
    if not client_id:
        try:
            conn = get_db()
            c = conn.cursor()
            # Try to find user by WireGuard IP that matches the connecting client
            c.execute(
                """
                SELECT client_id FROM users 
                WHERE wg_ipv4 = ? OR wg_ipv6 = ?
                LIMIT 1
                """,
                (ip_address, ip_address)
            )
            result = c.fetchone()
            conn.close()
            if result:
                client_id = result[0]
        except Exception as e:
            logger.debug(f"Auto-discovery for IP {ip_address} failed: {e}")
    
    if not client_id:
        return HTMLResponse(
            """
            <html>
            <head><title>WireShield</title></head>
            <body style="font-family: Arial; text-align: center; padding-top: 50px;">
            <h2>WireShield</h2>
            <p style="color: red;">❌ Unable to identify your client. Please check your VPN connection.</p>
            </body>
            </html>
            """,
            status_code=400
        )
    
    # Decide which UI to render based on whether 2FA is already configured
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT enabled, totp_secret FROM users WHERE client_id = ?", (client_id,))
        row = c.fetchone()
        conn.close()
        if row and int(row[0]) == 1 and (row[1] or "") != "":
            audit_log(client_id, "UI_ACCESS", "verify_only", ip_address)
            return get_2fa_verify_only_html(client_id)
    except Exception as e:
        logger.debug(f"State check failed for {client_id}: {e}")

    audit_log(client_id, "UI_ACCESS", "setup_flow", ip_address)
    return get_2fa_ui_html(client_id)

@app.post("/api/setup-start", tags=["2fa-setup"])
async def setup_start(
    request: Request,
    client_id: str = Form(...),
    rate_limit: None = Depends(rate_limiter),
):
    """Start 2FA setup: generate TOTP secret and QR code."""
    ip_address = request.client.host if request and request.client else "unknown"
    
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Check if user exists and whether already configured
        c.execute("SELECT id, totp_secret, enabled FROM users WHERE client_id = ?", (client_id,))
        user = c.fetchone()
        
        if user and user[2]:
            conn.close()
            audit_log(client_id, "2FA_SETUP_START", "already_configured", ip_address)
            return JSONResponse({"success": False, "detail": "already_configured"}, status_code=400)

        if not user:
            # Create new user
            c.execute(
                "INSERT INTO users (client_id, enabled) VALUES (?, ?)",
                (client_id, 0)  # Start disabled until 2FA is verified
            )
            conn.commit()
        
        # Generate new TOTP secret
        secret = pyotp.random_base32()
        c.execute("UPDATE users SET totp_secret = ? WHERE client_id = ?", (secret, client_id))
        conn.commit()
        conn.close()
        
        # Generate QR code
        totp = pyotp.TOTP(secret)
        qr_uri = totp.provisioning_uri(name=client_id, issuer_name="WireShield VPN")
        # Smaller QR for faster transfer while preserving scannability
        qr_code = qrcode.QRCode(version=1, box_size=6, border=2)
        qr_code.add_data(qr_uri)
        qr_code.make(fit=True)
        
        img = qr_code.make_image(fill_color="black", back_color="white")
        img_bytes = BytesIO()
        # Save QR code (PyPNG backend doesn't accept format/optimize kwargs)
        img.save(img_bytes)
        img_base64 = base64.b64encode(img_bytes.getvalue()).decode()
        
        audit_log(client_id, "2FA_SETUP_START", "qr_generated", ip_address)
        
        return JSONResponse({
            "success": True,
            "secret": secret,
            "qr_code": f"data:image/png;base64,{img_base64}",
            "uri": qr_uri
        })
    
    except Exception as e:
        logger.error(f"Setup start error for {client_id}: {str(e)}")
        audit_log(client_id, "2FA_SETUP_START", f"error_{str(e)}", ip_address)
        raise HTTPException(status_code=500, detail="Setup failed")

@app.post("/api/setup-verify", tags=["2fa-setup"])
async def setup_verify(
    request: Request,
    client_id: str = Form(...),
    code: str = Form(...),
    rate_limit: None = Depends(rate_limiter),
):
    """Verify TOTP code and complete 2FA setup."""
    ip_address = request.client.host if request and request.client else "unknown"
    
    try:
        conn = get_db()
        c = conn.cursor()
        
        c.execute("SELECT totp_secret FROM users WHERE client_id = ?", (client_id,))
        user = c.fetchone()
        
        if not user or not user["totp_secret"]:
            audit_log(client_id, "2FA_SETUP_VERIFY", "user_not_found", ip_address)
            raise HTTPException(status_code=404, detail="User not found")
        
        # Verify TOTP code (allow ±1 time window for clock skew)
        totp = pyotp.TOTP(user["totp_secret"])
        if not totp.verify(code, valid_window=1):
            audit_log(client_id, "2FA_SETUP_VERIFY", "invalid_code", ip_address)
            raise HTTPException(status_code=401, detail="Invalid code")
        
        # Invalidate all previous sessions for this client (re-authentication required)
        c.execute("DELETE FROM sessions WHERE client_id = ?", (client_id,))
        
        # Enable user and create session
        c.execute("UPDATE users SET enabled = 1 WHERE client_id = ?", (client_id,))
        # Persist client's WG IP (v4/v6) for ipset allowlist
        if ":" in ip_address:
            c.execute("UPDATE users SET wg_ipv6 = ? WHERE client_id = ?", (ip_address, client_id))
        else:
            c.execute("UPDATE users SET wg_ipv4 = ? WHERE client_id = ?", (ip_address, client_id))
        
        session_token = generate_session_token()
        expires_at = datetime.utcnow() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        c.execute(
            "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) VALUES (?, ?, ?, ?)",
            (client_id, hash_session_token(session_token), expires_at, ip_address)
        )
        
        conn.commit()
        conn.close()
        
        audit_log(client_id, "2FA_SETUP_VERIFY", "success", ip_address)
        # Allow this client traffic now that session exists
        try:
            allow_client_by_id(client_id)
        except Exception:
            logger.debug("Failed to add client to ipset allowlist")
        
        return JSONResponse({
            "success": True,
            "session_token": session_token,
            "expires_at": expires_at.isoformat()
        })
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Setup verify error for {client_id}: {str(e)}")
        audit_log(client_id, "2FA_SETUP_VERIFY", f"error_{str(e)}", ip_address)
        raise HTTPException(status_code=500, detail="Verification failed")

@app.post("/api/verify", tags=["2fa-auth"])
async def verify_code(
    request: Request,
    client_id: str = Form(...),
    code: str = Form(...),
    rate_limit: None = Depends(rate_limiter),
):
    """Verify TOTP code on reconnection."""
    ip_address = request.client.host if request and request.client else "unknown"
    
    try:
        conn = get_db()
        c = conn.cursor()
        
        c.execute("SELECT totp_secret, enabled FROM users WHERE client_id = ?", (client_id,))
        user = c.fetchone()
        
        if not user or not user["enabled"] or not user["totp_secret"]:
            audit_log(client_id, "2FA_VERIFY", "user_not_initialized", ip_address)
            raise HTTPException(status_code=403, detail="2FA not configured")
        
        # Verify TOTP code
        totp = pyotp.TOTP(user["totp_secret"])
        if not totp.verify(code, valid_window=1):
            audit_log(client_id, "2FA_VERIFY", "invalid_code", ip_address)
            raise HTTPException(status_code=401, detail="Invalid code")
        
        # Invalidate all previous sessions for this client (only current verification is valid)
        c.execute("DELETE FROM sessions WHERE client_id = ?", (client_id,))
        
        # Persist client's WG IP (v4/v6) for ipset allowlist
        if ":" in ip_address:
            c.execute("UPDATE users SET wg_ipv6 = ? WHERE client_id = ?", (ip_address, client_id))
        else:
            c.execute("UPDATE users SET wg_ipv4 = ? WHERE client_id = ?", (ip_address, client_id))
        
        # Create session token
        session_token = generate_session_token()
        expires_at = datetime.utcnow() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        c.execute(
            "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) VALUES (?, ?, ?, ?)",
            (client_id, hash_session_token(session_token), expires_at, ip_address)
        )
        
        conn.commit()
        conn.close()
        
        audit_log(client_id, "2FA_VERIFY", "success", ip_address)
        # Allow this client traffic now that session exists
        try:
            allow_client_by_id(client_id)
        except Exception:
            logger.debug("Failed to add client to ipset allowlist")
        
        return JSONResponse({
            "success": True,
            "session_token": session_token,
            "expires_at": expires_at.isoformat()
        })
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Verify error for {client_id}: {str(e)}")
        audit_log(client_id, "2FA_VERIFY", f"error_{str(e)}", ip_address)
        raise HTTPException(status_code=500, detail="Verification failed")

@app.post("/api/validate-session", tags=["session"])
async def validate_session(
    request: Request,
    client_id: str = Form(...),
    session_token: str = Form(...),
    rate_limit: None = Depends(rate_limiter),
):
    """Validate active session token."""
    ip_address = request.client.host if request and request.client else "unknown"
    
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Check if session exists and is not expired
        c.execute(
            "SELECT * FROM sessions WHERE client_id = ? AND expires_at > datetime('now') ORDER BY created_at DESC LIMIT 1",
            (client_id,)
        )
        session = c.fetchone()
        conn.close()
        
        if not session or not verify_session_token(session_token, session["session_token"]):
            audit_log(client_id, "SESSION_VALIDATE", "invalid_or_expired", ip_address)
            raise HTTPException(status_code=401, detail="Session invalid or expired")
        
        audit_log(client_id, "SESSION_VALIDATE", "valid", ip_address)
        
        return JSONResponse({
            "valid": True,
            "expires_at": session["expires_at"]
        })
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Session validation error for {client_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Validation failed")

@app.get("/success", response_class=HTMLResponse, tags=["ui"])
async def success_page(client_id: Optional[str] = None):
    """Success page after 2FA verification - indicates client can now access internet."""
    return HTMLResponse("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireShield — Connected</title>
    <style>
        :root {
            --bg: #f8fafc;
            --card: #ffffff;
            --text: #1e293b;
            --muted: #64748b;
            --accent: #2563eb;
            --success: #16a34a;
            --border: #e2e8f0;
            --radius: 12px;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }
        .container {
            width: 100%;
            max-width: 420px;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.06);
            padding: 32px;
            text-align: center;
        }
        .icon {
            width: 64px;
            height: 64px;
            margin: 0 auto 20px;
            background: #dcfce7;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .icon svg { width: 32px; height: 32px; color: var(--success); }
        h1 { font-size: 20px; font-weight: 600; margin-bottom: 8px; color: var(--text); }
        .subtitle { font-size: 14px; color: var(--muted); margin-bottom: 24px; }
        .status-box {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 20px;
        }
        .status-item { display: flex; align-items: center; gap: 8px; font-size: 14px; color: #166534; padding: 4px 0; }
        .status-item svg { width: 16px; height: 16px; flex-shrink: 0; }
        .note { font-size: 13px; color: var(--muted); line-height: 1.5; }
        .btn {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 24px;
            background: var(--accent);
            color: white;
            font-size: 14px;
            font-weight: 500;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            text-decoration: none;
        }
        .btn:hover { background: #1d4ed8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">
            <svg fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>
        </div>
        <h1>Verification Successful</h1>
        <p class="subtitle">Your two-factor authentication is complete.</p>
        <div class="status-box">
            <div class="status-item"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg> VPN connection is now active</div>
            <div class="status-item"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg> Full internet access enabled</div>
            <div class="status-item"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg> Session valid for 24 hours</div>
        </div>
        <p class="note">You can close this window and continue using your secure VPN connection.</p>
        <button class="btn" onclick="closeWindow();">Close Window</button>
    </div>
    <script>
        function closeWindow() {
            // Try to close the window (works if opened via window.open)
            window.close();
            // If window.close() doesn't work (most browsers block it), show a message
            setTimeout(function() {
                if (!window.closed) {
                    alert('Please close this tab manually to continue.');
                }
            }, 100);
        }
    </script>
</body>
</html>
    """)

# ============================================================================
# Web UI HTML
# ============================================================================
def get_2fa_ui_html(client_id: str) -> HTMLResponse:
    """Return modern, responsive 2FA setup/verification UI with light enterprise theme."""
    return HTMLResponse(f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireShield — 2FA Setup</title>
    <style>
        :root {{
            --bg: #f1f5f9;
            --card: #ffffff;
            --card-alt: #f8fafc;
            --text: #1e293b;
            --muted: #64748b;
            --accent: #2563eb;
            --accent-hover: #1d4ed8;
            --success: #16a34a;
            --error: #dc2626;
            --border: #e2e8f0;
            --radius: 12px;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 24px;
        }}
        .wrapper {{
            max-width: 880px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border);
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .logo {{
            width: 42px;
            height: 42px;
            border-radius: 10px;
            background: var(--accent);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 16px;
            color: #fff;
        }}
        .brand-text h1 {{
            font-size: 18px;
            font-weight: 600;
            color: var(--text);
        }}
        .brand-text p {{
            font-size: 13px;
            color: var(--muted);
            margin-top: 2px;
        }}
        .secure-badge {{
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 12px;
            color: var(--muted);
            background: var(--card);
            padding: 6px 12px;
            border-radius: 20px;
            border: 1px solid var(--border);
        }}
        .secure-badge svg {{ width: 14px; height: 14px; color: var(--success); }}
        .grid {{
            display: grid;
            grid-template-columns: 1fr 340px;
            gap: 20px;
        }}
        .card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 24px;
        }}
        .card-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
        }}
        .card-header h2 {{
            font-size: 15px;
            font-weight: 600;
        }}
        .badge {{
            font-size: 11px;
            font-weight: 500;
            padding: 4px 10px;
            border-radius: 20px;
            background: #dbeafe;
            color: var(--accent);
        }}
        .client-info {{
            background: var(--card-alt);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 14px;
            font-family: 'SF Mono', 'Consolas', monospace;
            font-size: 13px;
            color: var(--text);
            margin-bottom: 16px;
        }}
        .steps {{
            display: flex;
            gap: 8px;
            margin-bottom: 20px;
        }}
        .step {{
            flex: 1;
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 12px;
            background: var(--card-alt);
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 12px;
            color: var(--muted);
        }}
        .step.active {{
            background: #dbeafe;
            border-color: #93c5fd;
            color: var(--accent);
        }}
        .step-num {{
            width: 22px;
            height: 22px;
            border-radius: 6px;
            background: var(--card);
            border: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 11px;
        }}
        .step.active .step-num {{
            background: var(--accent);
            border-color: var(--accent);
            color: #fff;
        }}
        .section {{
            margin-bottom: 20px;
        }}
        .section-label {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 13px;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 10px;
        }}
        .section-label .num {{
            width: 20px;
            height: 20px;
            border-radius: 50%;
            background: var(--accent);
            color: #fff;
            font-size: 11px;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .btn {{
            width: 100%;
            padding: 11px 16px;
            font-size: 14px;
            font-weight: 500;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.15s ease;
        }}
        .btn-primary {{
            background: var(--accent);
            color: #fff;
        }}
        .btn-primary:hover {{ background: var(--accent-hover); }}
        .btn-primary:disabled {{ background: #94a3b8; cursor: not-allowed; }}
        .qr-box {{
            display: none;
            text-align: center;
            margin-top: 16px;
        }}
        .qr-box img {{
            width: 180px;
            height: 180px;
            border-radius: 10px;
            border: 1px solid var(--border);
            background: #fff;
            padding: 8px;
        }}
        .secret-box {{
            display: none;
            margin-top: 12px;
            background: var(--card-alt);
            border: 1px dashed var(--border);
            border-radius: 8px;
            padding: 12px;
            font-family: 'SF Mono', 'Consolas', monospace;
            font-size: 12px;
            color: var(--text);
            word-break: break-all;
            text-align: center;
        }}
        label {{
            display: block;
            font-size: 13px;
            font-weight: 500;
            color: var(--text);
            margin-bottom: 6px;
        }}
        input[type="text"] {{
            width: 100%;
            padding: 10px 14px;
            font-size: 14px;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: #fff;
            color: var(--text);
            outline: none;
            transition: border-color 0.15s, box-shadow 0.15s;
        }}
        input[type="text"]:focus {{
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }}
        .alert {{
            display: none;
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 13px;
            margin-top: 12px;
        }}
        .alert-success {{
            background: #dcfce7;
            border: 1px solid #bbf7d0;
            color: #166534;
        }}
        .alert-error {{
            background: #fee2e2;
            border: 1px solid #fecaca;
            color: #991b1b;
        }}
        .info-card {{
            background: var(--card-alt);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            font-size: 13px;
            color: var(--muted);
            line-height: 1.5;
            margin-bottom: 16px;
        }}
        .tags {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 16px;
        }}
        .tag {{
            font-size: 11px;
            padding: 5px 10px;
            border-radius: 6px;
            background: var(--card-alt);
            border: 1px solid var(--border);
            color: var(--muted);
        }}
        .spinner {{
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid rgba(255,255,255,0.3);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin-right: 8px;
            vertical-align: middle;
        }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        @media (max-width: 800px) {{
            .grid {{ grid-template-columns: 1fr; }}
            .header {{ flex-direction: column; align-items: flex-start; gap: 12px; }}
            .steps {{ flex-direction: column; }}
        }}
    </style>
</head>
<body onload="init()">
    <div class="wrapper">
        <div class="header">
            <div class="brand">
                <div class="logo">WS</div>
                <div class="brand-text">
                    <h1>WireShield 2FA Setup</h1>
                    <p>Configure two-factor authentication for VPN access</p>
                </div>
            </div>
            <div class="secure-badge">
                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                Secure TLS Connection
            </div>
        </div>
        <div class="grid">
            <div class="card">
                <div class="card-header">
                    <h2>Authentication Setup</h2>
                    <span class="badge">Required</span>
                </div>
                <div class="client-info">Client ID: {client_id}</div>
                <div class="steps">
                    <div class="step active"><span class="step-num">1</span>Generate QR</div>
                    <div class="step active"><span class="step-num">2</span>Scan Code</div>
                    <div class="step"><span class="step-num">3</span>Verify</div>
                </div>

                <div id="setupPhase">
                    <div class="section">
                        <div class="section-label"><span class="num">1</span>Generate QR Code</div>
                        <button class="btn btn-primary" onclick="generateQR()">Generate QR Code</button>
                        <div class="qr-box" id="qrBox">
                            <img id="qrImage" src="" alt="QR Code">
                        </div>
                        <div class="secret-box" id="secretBox"></div>
                    </div>

                    <div class="section">
                        <div class="section-label"><span class="num">2</span>Enter Verification Code</div>
                        <label for="code">6-digit code from your authenticator app</label>
                        <input type="text" id="code" placeholder="000000" maxlength="6" inputmode="numeric" autocomplete="one-time-code">
                        <button class="btn btn-primary" id="verifyBtn" onclick="verify()" style="margin-top: 12px;">Verify &amp; Continue</button>
                        <div id="successMsg" class="alert alert-success"></div>
                        <div id="errorMsg" class="alert alert-error"></div>
                    </div>

                    <div class="tags">
                        <span class="tag">24h session</span>
                        <span class="tag">No code stored server-side</span>
                        <span class="tag">Time drift tolerant</span>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2>Setup Guide</h2>
                </div>
                <div class="info-card">
                    <strong>Step 1:</strong> Click "Generate QR Code" to create your unique authentication code.
                </div>
                <div class="info-card">
                    <strong>Step 2:</strong> Open your authenticator app (Google Authenticator, 1Password, Authy, etc.) and scan the QR code.
                </div>
                <div class="info-card">
                    <strong>Step 3:</strong> Enter the 6-digit code displayed in your authenticator app to complete verification.
                </div>
                <div class="info-card" style="background: #fef9c3; border-color: #fde047;">
                    <strong>Note:</strong> Ensure your device clock is accurate. Codes refresh every 30 seconds.
                </div>
                <div class="tags">
                    <span class="tag">TLS enforced</span>
                    <span class="tag">Rate limited</span>
                    <span class="tag">Audit logged</span>
                </div>
            </div>
        </div>
    </div>

    <script>
        function init() {{
            document.getElementById('code').focus();
            document.addEventListener('keydown', e => {{ if (e.key === 'Enter') verify(); }});
        }}

        async function generateQR() {{
            hide('errorMsg'); hide('successMsg');
            const form = new FormData();
            form.append('client_id', '{client_id}');
            try {{
                const res = await fetch('/api/setup-start', {{ method: 'POST', body: form }});
                const data = await res.json();
                if (data.success) {{
                    document.getElementById('qrImage').src = data.qr_code;
                    document.getElementById('secretBox').textContent = 'Manual entry: ' + data.secret;
                    show('qrBox'); show('secretBox');
                    showSuccess('QR code generated. Scan it with your authenticator app.');
                }} else {{
                    showError(data.detail || 'Failed to generate QR code');
                }}
            }} catch (e) {{
                showError('Network error: ' + e.message);
            }}
        }}

        async function verify() {{
            const code = document.getElementById('code').value.trim();
            if (!/^\\d{{6}}$/.test(code)) {{ showError('Enter a valid 6-digit code'); return; }}
            hide('errorMsg'); hide('successMsg');
            const btn = document.getElementById('verifyBtn');
            const orig = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span>Verifying...';
            try {{
                const form = new FormData();
                form.append('client_id', '{client_id}');
                form.append('code', code);
                const res = await fetch('/api/setup-verify', {{ method: 'POST', body: form }});
                const data = await res.json();
                if (data.success) {{
                    localStorage.setItem('session_token', data.session_token);
                    localStorage.setItem('client_id', '{client_id}');
                    showSuccess('Verification successful! Redirecting...');
                    setTimeout(() => window.location.href = '/success?client_id={client_id}', 1200);
                }} else {{
                    showError(data.detail || 'Verification failed');
                    btn.disabled = false;
                    btn.innerHTML = orig;
                }}
            }} catch (e) {{
                showError('Network error: ' + e.message);
                btn.disabled = false;
                btn.innerHTML = orig;
            }}
        }}

        function show(id) {{ document.getElementById(id).style.display = 'block'; }}
        function hide(id) {{ document.getElementById(id).style.display = 'none'; }}
        function showError(msg) {{ const el = document.getElementById('errorMsg'); el.textContent = msg; el.style.display = 'block'; }}
        function showSuccess(msg) {{ const el = document.getElementById('successMsg'); el.textContent = msg; el.style.display = 'block'; }}
    </script>
</body>
</html>
    """)

# ----------------------------------------------------------------------------
# Verify-only UI (for users who already completed setup)
# ----------------------------------------------------------------------------
def get_2fa_verify_only_html(client_id: str) -> HTMLResponse:
    """Return verify-only UI with light enterprise theme for returning users."""
    return HTMLResponse(f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireShield — Verify Access</title>
    <style>
        :root {{
            --bg: #f1f5f9;
            --card: #ffffff;
            --card-alt: #f8fafc;
            --text: #1e293b;
            --muted: #64748b;
            --accent: #2563eb;
            --accent-hover: #1d4ed8;
            --success: #16a34a;
            --error: #dc2626;
            --border: #e2e8f0;
            --radius: 12px;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }}
        .container {{
            width: 100%;
            max-width: 420px;
        }}
        .header {{
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            gap: 12px;
            margin-bottom: 24px;
        }}
        .logo {{
            width: 48px;
            height: 48px;
            border-radius: 12px;
            background: var(--accent);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 18px;
            color: #fff;
        }}
        .header-text h1 {{
            font-size: 20px;
            font-weight: 600;
            color: var(--text);
        }}
        .header-text p {{
            font-size: 13px;
            color: var(--muted);
            margin-top: 4px;
        }}
        .card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 24px;
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.06);
        }}
        .card-title {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
        }}
        .card-title h2 {{
            font-size: 15px;
            font-weight: 600;
        }}
        .badge {{
            font-size: 11px;
            font-weight: 500;
            padding: 4px 10px;
            border-radius: 20px;
            background: #dcfce7;
            color: var(--success);
        }}
        .client-info {{
            background: var(--card-alt);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px 14px;
            font-family: 'SF Mono', 'Consolas', monospace;
            font-size: 12px;
            color: var(--muted);
            margin-bottom: 16px;
        }}
        label {{
            display: block;
            font-size: 13px;
            font-weight: 500;
            color: var(--text);
            margin-bottom: 6px;
        }}
        input {{
            width: 100%;
            padding: 12px 14px;
            font-size: 16px;
            letter-spacing: 4px;
            text-align: center;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: #fff;
            color: var(--text);
            outline: none;
            transition: border-color 0.15s, box-shadow 0.15s;
        }}
        input:focus {{
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }}
        input::placeholder {{
            letter-spacing: 2px;
            color: #cbd5e1;
        }}
        .btn {{
            width: 100%;
            padding: 12px 16px;
            font-size: 14px;
            font-weight: 500;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.15s ease;
            margin-top: 12px;
            background: var(--accent);
            color: #fff;
        }}
        .btn:hover {{ background: var(--accent-hover); }}
        .btn:disabled {{ background: #94a3b8; cursor: not-allowed; }}
        .alert {{
            display: none;
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 13px;
            margin-top: 12px;
        }}
        .alert-success {{
            background: #dcfce7;
            border: 1px solid #bbf7d0;
            color: #166534;
        }}
        .alert-error {{
            background: #fee2e2;
            border: 1px solid #fecaca;
            color: #991b1b;
        }}
        .info {{
            background: var(--card-alt);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 14px;
            font-size: 13px;
            color: var(--muted);
            line-height: 1.5;
            margin-top: 16px;
        }}
        .tags {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 16px;
        }}
        .tag {{
            font-size: 11px;
            padding: 5px 10px;
            border-radius: 6px;
            background: var(--card-alt);
            border: 1px solid var(--border);
            color: var(--muted);
        }}
        .spinner {{
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid rgba(255,255,255,0.3);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin-right: 8px;
            vertical-align: middle;
        }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body onload="init()">
    <div class="container">
        <div class="header">
            <div class="logo">WS</div>
            <div class="header-text">
                <h1>WireShield Verification</h1>
                <p>Enter your authenticator code to connect</p>
            </div>
        </div>
        <div class="card">
            <div class="card-title">
                <h2>Two-Factor Authentication</h2>
                <span class="badge">Configured</span>
            </div>
            <div class="client-info">Client: {client_id}</div>
            <label for="code">Enter 6-digit code</label>
            <input type="text" id="code" maxlength="6" inputmode="numeric" placeholder="000000" autocomplete="one-time-code">
            <button class="btn" id="verifyBtn" onclick="verify()">Verify &amp; Connect</button>
            <div id="ok" class="alert alert-success"></div>
            <div id="err" class="alert alert-error"></div>
            <div class="info">
                Open your authenticator app and enter the current code for WireShield. Codes refresh every 30 seconds.
            </div>
            <div class="tags">
                <span class="tag">TLS secured</span>
                <span class="tag">Rate limited</span>
                <span class="tag">24h session</span>
            </div>
        </div>
    </div>
    <script>
        function init() {{
            document.getElementById('code').focus();
            document.addEventListener('keydown', e => {{ if (e.key === 'Enter') verify(); }});
        }}
        async function verify() {{
            const code = document.getElementById('code').value.trim();
            const ok = document.getElementById('ok');
            const err = document.getElementById('err');
            ok.style.display = 'none';
            err.style.display = 'none';
            if (!/^\\d{{6}}$/.test(code)) {{
                err.textContent = 'Please enter a valid 6-digit code';
                err.style.display = 'block';
                return;
            }}
            const btn = document.getElementById('verifyBtn');
            const orig = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span>Verifying...';
            try {{
                const form = new FormData();
                form.append('client_id', '{client_id}');
                form.append('code', code);
                const res = await fetch('/api/verify', {{ method: 'POST', body: form }});
                const data = await res.json();
                if (data.success) {{
                    localStorage.setItem('session_token', data.session_token);
                    localStorage.setItem('client_id', '{client_id}');
                    ok.textContent = 'Verification successful! Connecting...';
                    ok.style.display = 'block';
                    setTimeout(() => window.location.href = '/success?client_id={client_id}', 1000);
                }} else {{
                    err.textContent = data.detail || 'Invalid code. Please try again.';
                    err.style.display = 'block';
                    btn.disabled = false;
                    btn.innerHTML = orig;
                }}
            }} catch (e) {{
                err.textContent = 'Network error: ' + e.message;
                err.style.display = 'block';
                btn.disabled = false;
                btn.innerHTML = orig;
            }}
        }}
    </script>
</body>
</html>
    """)

# ============================================================================
# Startup
# ============================================================================
if __name__ == "__main__":
    # Ensure SECRET_KEY is set
    if not SECRET_KEY:
        logger.warning("2FA_SECRET_KEY not set; generating temporary key (not suitable for production)")
        SECRET_KEY = secrets.token_urlsafe(32)
    
    init_db()
    # Start background ipset sync thread
    threading.Thread(target=_sync_ipsets_from_sessions, daemon=True).start()
    # Tear down 2FA sessions when peers disconnect from WireGuard
    threading.Thread(target=_monitor_wireguard_sessions, daemon=True).start()
    # Start captive portal HTTP redirector (IPv4 and IPv6) on AUTH_HTTP_PORT
    threading.Thread(target=_start_http_redirector_ipv4, daemon=True).start()
    threading.Thread(target=_start_http_redirector_ipv6, daemon=True).start()
    
    # Log SSL configuration
    if SSL_ENABLED:
        ssl_info = f"{SSL_TYPE.upper()} (Valid for: {TFA_DOMAIN or TFA_HOSTNAME})"
    else:
        ssl_info = "DISABLED"
    
    logger.info(f"Starting WireShield 2FA Auth")
    logger.info(f"  Listen: {AUTH_HOST}:{AUTH_PORT}")
    logger.info(f"  SSL: {ssl_info}")
    logger.info(f"  UI: {UI_BASE_URL}/?client_id=<CLIENT_ID>")
    
    # Check if SSL files exist
    if SSL_ENABLED and (not os.path.exists(SSL_CERT) or not os.path.exists(SSL_KEY)):
        logger.warning(f"SSL cert/key not found at {SSL_CERT}/{SSL_KEY}")
        logger.warning(f"Create with: openssl req -x509 -newkey rsa:4096 -keyout {SSL_KEY} -out {SSL_CERT} -days 365 -nodes")
    
    # Run server
    uvicorn.run(
        app,
        host=AUTH_HOST,
        port=AUTH_PORT,
        ssl_keyfile=SSL_KEY if (SSL_ENABLED and os.path.exists(SSL_KEY)) else None,
        ssl_certfile=SSL_CERT if (SSL_ENABLED and os.path.exists(SSL_CERT)) else None,
        log_level=LOG_LEVEL.lower(),
    )
