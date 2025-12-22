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
import pyotp
import qrcode
from io import BytesIO
import base64
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler

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
AUTH_PORT = int(getenv_multi("8443", "WS_2FA_PORT", "2FA_PORT"))
AUTH_HTTP_PORT = int(getenv_multi("8080", "WS_2FA_HTTP_PORT", "2FA_HTTP_PORT"))
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

# Determine UI access URL based on config
if TFA_DOMAIN:
    UI_BASE_URL = f"https://{TFA_DOMAIN}:8443"
else:
    UI_BASE_URL = f"https://{TFA_HOSTNAME}:8443"

# ============================================================================
# Logging
# ============================================================================
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

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

# HTTP to HTTPS redirect middleware (for captive portal)
@app.middleware("http")
async def redirect_http_to_https(request: Request, call_next):
    """Redirect HTTP requests to HTTPS."""
    # Check if request came through HTTP (not forwarded from reverse proxy)
    if request.url.scheme == "http":
        # Build HTTPS URL, replacing port 80 with 8443
        https_url = str(request.url)
        https_url = https_url.replace("http://", "https://", 1)
        # Replace :80/ with :8443/
        if ":80/" in https_url:
            https_url = https_url.replace(":80/", ":8443/")
        elif https_url.count("://") == 1:
            # No explicit port in URL, add :8443
            parts = https_url.split("://")
            domain_path = parts[1]
            if "/" in domain_path:
                domain, path = domain_path.split("/", 1)
                https_url = f"{parts[0]}://{domain}:8443/{path}"
            else:
                https_url = f"{parts[0]}://{domain_path}:8443/"
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

    def log_message(self, fmt, *args):
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
async def root(client_id: Optional[str] = None, request: Request = None):
    """
    Serve 2FA setup/verification UI.
    Supports:
    - Direct access with ?client_id=<id>
    - Auto-discovery mode (detect client_id from database via IP)
    """
    ip_address = request.client.host if request else "unknown"
    
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
            <head><title>WireShield 2FA</title></head>
            <body style="font-family: Arial; text-align: center; padding-top: 50px;">
            <h2>WireShield 2FA Setup</h2>
            <p style="color: red;">❌ Unable to identify your client. Please check your VPN connection.</p>
            </body>
            </html>
            """,
            status_code=400
        )
    
    audit_log(client_id, "UI_ACCESS", "page_loaded", ip_address)
    return get_2fa_ui_html(client_id)

@app.post("/api/setup-start", tags=["2fa-setup"])
async def setup_start(
    client_id: str = Form(...),
    request: Request = None,
    rate_limit: None = Depends(rate_limiter),
):
    """Start 2FA setup: generate TOTP secret and QR code."""
    ip_address = request.client.host if request else "unknown"
    
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Check if user exists
        c.execute("SELECT id, totp_secret FROM users WHERE client_id = ?", (client_id,))
        user = c.fetchone()
        
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
        qr_code = qrcode.QRCode(version=1, box_size=10, border=5)
        qr_code.add_data(qr_uri)
        qr_code.make(fit=True)
        
        img = qr_code.make_image(fill_color="black", back_color="white")
        img_bytes = BytesIO()
        img.save(img_bytes, format="PNG")
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
    client_id: str = Form(...),
    code: str = Form(...),
    request: Request = None,
    rate_limit: None = Depends(rate_limiter),
):
    """Verify TOTP code and complete 2FA setup."""
    ip_address = request.client.host if request else "unknown"
    
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
        
        # Enable user and create session
        c.execute("UPDATE users SET enabled = 1 WHERE client_id = ?", (client_id,))
        
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
    client_id: str = Form(...),
    code: str = Form(...),
    request: Request = None,
    rate_limit: None = Depends(rate_limiter),
):
    """Verify TOTP code on reconnection."""
    ip_address = request.client.host if request else "unknown"
    
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
    client_id: str = Form(...),
    session_token: str = Form(...),
    request: Request = None,
    rate_limit: None = Depends(rate_limiter),
):
    """Validate active session token."""
    ip_address = request.client.host if request else "unknown"
    
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
    <title>✓ Connected - WireShield</title>
    <style>
        * {margin: 0; padding: 0; box-sizing: border-box;}
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 60px 40px;
            text-align: center;
            max-width: 500px;
        }
        .success-icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 30px;
            background: #22c55e;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 48px;
        }
        h1 {
            color: #1f2937;
            margin-bottom: 12px;
            font-size: 28px;
        }
        p {
            color: #6b7280;
            margin-bottom: 10px;
            line-height: 1.6;
        }
        .status {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            color: #166534;
            padding: 16px;
            border-radius: 12px;
            margin: 30px 0;
            font-size: 14px;
        }
        .note {
            font-size: 13px;
            color: #9ca3af;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✓</div>
        <h1>Successfully Verified!</h1>
        <p>Your 2FA authentication was successful.</p>
        <div class="status">
            ✓ Your VPN connection is now active<br>
            ✓ You have full internet access<br>
            ✓ Session valid for 24 hours
        </div>
        <p style="margin-top: 30px;">You can close this window and enjoy your secure VPN connection.</p>
        <div class="note">
            Your session will remain active until you disconnect from the VPN.
        </div>
    </div>
    <script>
        setTimeout(function() { window.close(); }, 5000);
    </script>
</body>
</html>
    """)

# ============================================================================
# Web UI HTML
# ============================================================================
def get_2fa_ui_html(client_id: str) -> str:
    """Return modern, responsive 2FA setup/verification UI."""
    return HTMLResponse(f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireShield 2FA</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #0b1224;
            --card: #0f172a;
            --card-soft: #152036;
            --text: #e7ecf5;
            --muted: #94a3b8;
            --accent: #0ea5e9;
            --accent-strong: #0284c7;
            --success: #22c55e;
            --error: #f43f5e;
            --border: rgba(255, 255, 255, 0.08);
            --shadow: 0 24px 80px rgba(0, 0, 0, 0.45);
            --radius: 16px;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Space Grotesk', 'Segoe UI', sans-serif;
            background: radial-gradient(circle at 10% 20%, rgba(14,165,233,0.15), transparent 25%),
                        radial-gradient(circle at 80% 0%, rgba(34,197,94,0.12), transparent 25%),
                        linear-gradient(135deg, #0b1224 0%, #0f162b 40%, #0b1224 100%);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 32px;
        }}
        .shell {{
            width: min(960px, 100%);
            background: linear-gradient(145deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01));
            border: 1px solid var(--border);
            border-radius: calc(var(--radius) + 4px);
            box-shadow: var(--shadow);
            padding: 26px;
            backdrop-filter: blur(10px);
        }}
        .top {{
            display: flex;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 18px;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .badge {{
            width: 40px;
            height: 40px;
            border-radius: 12px;
            background: linear-gradient(135deg, #0ea5e9, #22c55e);
            display: grid;
            place-items: center;
            font-size: 20px;
            color: #0b1224;
            font-weight: 700;
        }}
        .title-block h1 {{ font-size: 20px; letter-spacing: -0.01em; }}
        .title-block p {{ color: var(--muted); font-size: 13px; margin-top: 2px; }}
        .meta {{
            display: flex;
            gap: 12px;
            align-items: center;
            color: var(--muted);
            font-size: 13px;
        }}
        .meta .dot {{ width: 6px; height: 6px; border-radius: 999px; background: var(--accent); display: inline-block; margin-right: 6px; }}
        .grid {{
            display: grid;
            grid-template-columns: 1.1fr 0.9fr;
            gap: 18px;
        }}
        .card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 22px;
        }}
        .card + .card {{ margin-top: 0; }}
        .section-title {{
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 12px;
            font-weight: 600;
            color: #e2e8f0;
        }}
        .section-title .pill {{
            background: rgba(14,165,233,0.15);
            color: var(--accent);
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 12px;
            border: 1px solid rgba(14,165,233,0.25);
        }}
        .info-box {{
            background: var(--card-soft);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 14px 16px;
            font-size: 14px;
            color: var(--muted);
            line-height: 1.5;
        }}
        .client-id {{
            margin-top: 10px;
            padding: 12px 14px;
            border-radius: 10px;
            background: rgba(255,255,255,0.04);
            border: 1px solid var(--border);
            font-family: "SFMono-Regular", "Consolas", monospace;
            font-size: 13px;
            color: #d7e3f4;
        }}
        .steps {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 10px;
            margin: 14px 0 6px;
        }}
        .step {{
            padding: 12px 14px;
            border-radius: 10px;
            border: 1px solid var(--border);
            background: rgba(255,255,255,0.02);
            color: var(--muted);
            font-size: 13px;
            display: flex;
            gap: 10px;
            align-items: center;
        }}
        .step.active {{
            background: rgba(14,165,233,0.12);
            color: var(--text);
            border-color: rgba(14,165,233,0.35);
        }}
        .step .index {{
            width: 28px;
            height: 28px;
            border-radius: 10px;
            background: rgba(255,255,255,0.05);
            display: grid;
            place-items: center;
            font-weight: 600;
            color: #e2e8f0;
        }}
        .qr {{ text-align: center; margin-top: 12px; }}
        .qr img {{
            max-width: 240px;
            width: 100%;
            border-radius: 14px;
            border: 1px solid var(--border);
            background: #0b1224;
            padding: 12px;
        }}
        .secret-code {{
            background: #0b1224;
            border: 1px dashed rgba(255,255,255,0.15);
            color: #e2e8f0;
            padding: 12px;
            border-radius: 12px;
            font-family: "SFMono-Regular", "Consolas", monospace;
            font-size: 13px;
            margin-top: 12px;
            word-break: break-all;
        }}
        label {{
            display: block;
            color: var(--muted);
            font-size: 13px;
            margin-bottom: 6px;
        }}
        input[type="text"] {{
            width: 100%;
            padding: 12px 14px;
            border-radius: 10px;
            border: 1px solid var(--border);
            background: rgba(255,255,255,0.03);
            color: var(--text);
            font-size: 14px;
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
        }}
        input[type="text"]:focus {{
            border-color: rgba(14,165,233,0.6);
            box-shadow: 0 0 0 3px rgba(14,165,233,0.18);
        }}
        button {{
            width: 100%;
            padding: 12px 14px;
            border-radius: 12px;
            border: none;
            background: linear-gradient(135deg, var(--accent), var(--accent-strong));
            color: #0b1224;
            font-weight: 700;
            letter-spacing: 0.01em;
            cursor: pointer;
            transition: transform 0.15s ease, box-shadow 0.15s ease;
        }}
        button:hover {{ transform: translateY(-1px); box-shadow: 0 12px 30px rgba(14,165,233,0.35); }}
        button:active {{ transform: translateY(0); }}
        button:disabled {{ opacity: 0.6; cursor: not-allowed; box-shadow: none; transform: none; }}
        .muted {{ color: var(--muted); font-size: 13px; }}
        .status {{
            display: grid;
            gap: 10px;
            margin-top: 10px;
        }}
        .alert {{
            display: none;
            padding: 12px 14px;
            border-radius: 10px;
            font-size: 14px;
            border: 1px solid transparent;
        }}
        .alert.success {{
            display: none;
            background: rgba(34,197,94,0.12);
            color: #bbf7d0;
            border-color: rgba(34,197,94,0.35);
        }}
        .alert.error {{
            display: none;
            background: rgba(244,63,94,0.12);
            color: #fecdd3;
            border-color: rgba(244,63,94,0.35);
        }}
        .pill-row {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 12px;
        }}
        .pill-row .pill {{
            background: rgba(255,255,255,0.04);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 8px 12px;
            border-radius: 999px;
            font-size: 12px;
        }}
        .success-view {{ text-align: center; padding: 10px 6px 0; }}
        .success-view h2 {{ margin-bottom: 8px; letter-spacing: -0.01em; }}
        .success-view p {{ color: var(--muted); margin-bottom: 16px; }}
        .tick {{
            width: 74px;
            height: 74px;
            border-radius: 22px;
            margin: 0 auto 16px;
            display: grid;
            place-items: center;
            background: radial-gradient(circle, rgba(34,197,94,0.4) 0%, rgba(34,197,94,0.08) 60%, transparent 70%);
            color: var(--success);
            font-size: 36px;
        }}
        .spinner {{
            border: 3px solid rgba(255,255,255,0.08);
            border-top: 3px solid var(--accent);
            border-radius: 50%;
            width: 18px;
            height: 18px;
            animation: spin 0.9s linear infinite;
            display: inline-block;
            margin-right: 8px;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        @media (max-width: 900px) {{
            .grid {{ grid-template-columns: 1fr; }}
            .shell {{ padding: 20px; }}
        }}
    </style>
</head>
<body>
    <div class="shell">
        <div class="top">
            <div class="brand">
                <div class="badge">WS</div>
                <div class="title-block">
                    <h1>WireShield 2FA Verification</h1>
                    <p>Pre-connection identity check for VPN access</p>
                </div>
            </div>
            <div class="meta">
                <span class="dot"></span>
                Secure channel via TLS 1.2+
            </div>
        </div>
        <div class="grid">
            <div class="card">
                <div class="section-title"><span class="pill">Client</span> Verification Flow</div>
                <div class="client-id">Client ID: {client_id}</div>
                <div class="steps">
                    <div class="step active"><span class="index">1</span>Get authenticator</div>
                    <div class="step active"><span class="index">2</span>Scan QR or copy code</div>
                    <div class="step"><span class="index">3</span>Enter 6-digit TOTP</div>
                </div>
                <div class="info-box">Use Google Authenticator, 1Password, or any TOTP app. Codes rotate every 30 seconds and tolerate slight clock drift.</div>

                <div id="setupPhase">
                    <div class="section-title" style="margin-top:16px;"><span class="pill">Step 1</span>Generate QR</div>
                    <button onclick="generateQR()">Generate QR Code</button>
                    <div id="qrContainer" class="qr" style="display:none;">
                        <img id="qrImage" src="" alt="QR code">
                    </div>
                    <div id="secretContainer" style="display:none;">
                        <div class="muted" style="margin-top:10px;">Or enter this secret manually:</div>
                        <div class="secret-code" id="secretCode"></div>
                    </div>

                    <div class="section-title" style="margin-top:20px;"><span class="pill">Step 2</span>Verify TOTP</div>
                    <label for="verifyCode">6-digit code</label>
                    <input type="text" id="verifyCode" placeholder="123456" maxlength="6" pattern="[0-9]{{6}}" inputmode="numeric" autocomplete="one-time-code" />
                    <button onclick="verifySetup()" id="verifyBtn" style="margin-top:12px;">Verify and continue</button>

                    <div class="status">
                        <div id="successMsg" class="alert success"></div>
                        <div id="errorMsg" class="alert error"></div>
                    </div>
                    <div class="pill-row">
                        <div class="pill">Sessions last 24h</div>
                        <div class="pill">No code stored server-side</div>
                        <div class="pill">Time drift tolerant</div>
                    </div>
                </div>

                <div id="successPhase" class="success-view" style="display:none;">
                    <div class="tick">✓</div>
                    <h2>2FA Verified</h2>
                    <p>Your session token is active. You can close this window and connect your VPN client.</p>
                    <button onclick="location.reload()" style="background: linear-gradient(135deg, var(--success), #16a34a); color:#0b1224;">Close and connect</button>
                </div>
            </div>

            <div class="card" style="background: var(--card-soft);">
                <div class="section-title"><span class="pill">Details</span>Connection facts</div>
                <div class="info-box" style="margin-bottom:12px;">
                    Keep this window open while verifying. If the code fails, wait for the next 30-second rotation and try again.
                </div>
                <div class="pill-row">
                    <div class="pill">TLS enforced</div>
                    <div class="pill">Per-IP rate limits</div>
                    <div class="pill">No reuse after expiry</div>
                    <div class="pill">Audit logged</div>
                </div>
                <div class="info-box" style="margin-top:14px;">
                    Need help? Ensure your device clock is accurate and that your browser allows loading images (for the QR). Self-signed deployments will show a certificate warning; proceed if you trust this host.
                </div>
            </div>
        </div>
    </div>

    <script>
        let setupData = {{}};

        async function generateQR() {{
            try {{
                const errorBox = document.getElementById('errorMsg');
                const successBox = document.getElementById('successMsg');
                errorBox.style.display = 'none';
                successBox.style.display = 'none';

                const formData = new FormData();
                formData.append('client_id', '{client_id}');

                const response = await fetch('/api/setup-start', {{ method: 'POST', body: formData }});
                const data = await response.json();

                if (data.success) {{
                    setupData = data;
                    document.getElementById('qrImage').src = data.qr_code;
                    document.getElementById('secretCode').textContent = data.secret;
                    document.getElementById('qrContainer').style.display = 'block';
                    document.getElementById('secretContainer').style.display = 'block';
                    successBox.textContent = 'QR code generated. Scan or copy the secret to continue.';
                    successBox.style.display = 'block';
                }} else {{
                    showError(data.detail || 'Failed to generate QR code');
                }}
            }} catch (e) {{
                showError('Error: ' + e.message);
            }}
        }}

        async function verifySetup() {{
            const code = document.getElementById('verifyCode').value;
            if (code.length !== 6 || isNaN(code)) {{
                showError('Please enter a valid 6-digit code');
                return;
            }}

            const btn = document.getElementById('verifyBtn');
            const originalLabel = btn.innerHTML;
            try {{
                btn.disabled = true;
                btn.innerHTML = '<span class="spinner"></span>Verifying...';

                const formData = new FormData();
                formData.append('client_id', '{client_id}');
                formData.append('code', code);

                const response = await fetch('/api/setup-verify', {{ method: 'POST', body: formData }});
                const data = await response.json();

                if (data.success) {{
                    localStorage.setItem('session_token', data.session_token);
                    localStorage.setItem('client_id', '{client_id}');

                    showSuccess('2FA verified successfully!');
                    // Redirect to success page after 1.5 seconds
                    setTimeout(function() {{
                        window.location.href = '/success?client_id={client_id}';
                    }}, 1500);
                }} else {{
                    showError(data.detail || 'Verification failed');
                    btn.disabled = false;
                    btn.innerHTML = originalLabel;
                }}
            }} catch (e) {{
                showError('Error: ' + e.message);
                btn.disabled = false;
                btn.innerHTML = originalLabel;
            }}
        }}

        function showError(msg) {{
            const el = document.getElementById('errorMsg');
            el.textContent = msg;
            el.style.display = 'block';
        }}

        function showSuccess(msg) {{
            const el = document.getElementById('successMsg');
            el.textContent = msg;
            el.style.display = 'block';
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
