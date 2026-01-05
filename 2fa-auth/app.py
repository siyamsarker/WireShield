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
# Idle timeout while connected: how recent a handshake must be to consider the peer active.
# Default 3600s (1 hour) to keep sessions for long idle periods while connected.
SESSION_IDLE_TIMEOUT_SECONDS = int(getenv_multi("3600", "WS_2FA_SESSION_IDLE_TIMEOUT", "2FA_SESSION_IDLE_TIMEOUT"))
# Disconnect grace: revoke session after this many seconds without any handshake.
DISCONNECT_GRACE_SECONDS = int(getenv_multi("3600", "WS_2FA_DISCONNECT_GRACE_SECONDS", "2FA_DISCONNECT_GRACE_SECONDS"))

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
            enabled BOOLEAN DEFAULT 1,
            console_access BOOLEAN DEFAULT 0
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
    try:
        c.execute('ALTER TABLE users ADD COLUMN console_access BOOLEAN DEFAULT 0')
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

# Mount static files
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")

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
# Console Access & Routes
# ============================================================================

def _check_console_access(request: Request):
    """Dependency: Verify if the requester is authorized for console access."""
    client_ip = request.client.host
    
    conn = get_db()
    c = conn.cursor()
    
    # Find client by IP (v4 or v6)
    c.execute("SELECT client_id, console_access FROM users WHERE wg_ipv4 = ? OR wg_ipv6 = ?", (client_ip, client_ip))
    row = c.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=403, detail="Access denied: Unknown client")
    
    client_id, access = row["client_id"], row["console_access"]
    if not access:
        raise HTTPException(status_code=403, detail="Access denied: Console access not granted")
    
    return client_id

@app.get("/console", response_class=HTMLResponse)
async def console_dashboard(request: Request):
    """Render the Web Console Dashboard."""
    try:
        _check_console_access(request)
    except HTTPException:
        html_error = """
<!DOCTYPE html>
<html lang="en">
<head>
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied | WireShield</title>
    <title>Access Denied | WireShield</title>
    <style>
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 400; font-display: swap; src: url('/static/fonts/Inter-Regular.woff2') format('woff2'); }
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 600; font-display: swap; src: url('/static/fonts/Inter-SemiBold.woff2') format('woff2'); }
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 700; font-display: swap; src: url('/static/fonts/Inter-Bold.woff2') format('woff2'); }
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 900; font-display: swap; src: url('/static/fonts/Inter-Black.woff2') format('woff2'); }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            min-height: 100vh;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 50%, #16213e 100%);
            display: flex; align-items: center; justify-content: center;
            overflow: hidden; position: relative; color: #fff;
        }
        body::before {
            content: ''; position: absolute; top: 0; left: 0; right: 0; bottom: 0;
            background-image: linear-gradient(rgba(255,0,60,0.03) 1px, transparent 1px),
                              linear-gradient(90deg, rgba(255,0,60,0.03) 1px, transparent 1px);
            background-size: 50px 50px; animation: gridPulse 4s ease-in-out infinite;
        }
        @keyframes gridPulse { 0%, 100% { opacity: 0.3; } 50% { opacity: 0.6; } }
        .glow-orb {
            position: absolute; width: 400px; height: 400px; border-radius: 50%;
            background: radial-gradient(circle, rgba(220,38,38,0.15) 0%, transparent 70%);
            top: 50%; left: 50%; transform: translate(-50%, -50%);
            animation: orbPulse 3s ease-in-out infinite;
        }
        @keyframes orbPulse {
            0%, 100% { transform: translate(-50%, -50%) scale(1); opacity: 0.5; }
            50% { transform: translate(-50%, -50%) scale(1.2); opacity: 0.8; }
        }
        .container { position: relative; z-index: 10; text-align: center; padding: 3rem; max-width: 520px; }
        .shield-icon { width: 120px; height: 120px; margin: 0 auto 2rem; position: relative; }
        .shield-icon svg {
            width: 100%; height: 100%; filter: drop-shadow(0 0 30px rgba(220,38,38,0.5));
            animation: shieldGlow 2s ease-in-out infinite;
        }
        @keyframes shieldGlow {
            0%, 100% { filter: drop-shadow(0 0 20px rgba(220,38,38,0.4)); }
            50% { filter: drop-shadow(0 0 40px rgba(220,38,38,0.7)); }
        }
        .error-code {
            font-size: 0.875rem; font-weight: 600; letter-spacing: 0.3em;
            color: #dc2626; text-transform: uppercase; margin-bottom: 1rem; opacity: 0.9;
        }
        h1 {
            font-size: 2.5rem; font-weight: 900; color: #ffffff; margin-bottom: 1rem;
            letter-spacing: -0.02em; text-shadow: 0 0 40px rgba(220,38,38,0.3);
        }
        .subtitle { font-size: 1.125rem; color: #94a3b8; margin-bottom: 2.5rem; line-height: 1.6; }
        .warning-box {
            background: rgba(220,38,38,0.1); border: 1px solid rgba(220,38,38,0.3);
            border-radius: 12px; padding: 1.25rem 1.5rem; margin-bottom: 2rem;
        }
        .warning-box p {
            color: #f87171; font-size: 0.9rem; font-weight: 500;
            display: flex; align-items: center; justify-content: center; gap: 0.5rem;
        }
        .info-text { font-size: 0.875rem; color: #64748b; line-height: 1.7; }
        .info-text strong { color: #94a3b8; }
        .brand {
            position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%);
            font-size: 0.75rem; color: #475569; letter-spacing: 0.1em;
        }
        /* Corners */
        .corner { position: fixed; width: 100px; height: 100px; border: 2px solid rgba(220,38,38,0.2); }
        .corner-tl { top: 20px; left: 20px; border-right: none; border-bottom: none; }
        .corner-tr { top: 20px; right: 20px; border-left: none; border-bottom: none; }
        .corner-bl { bottom: 20px; left: 20px; border-right: none; border-top: none; }
        .corner-br { bottom: 20px; right: 20px; border-left: none; border-top: none; }
    </style>
</head>
<body>
    <div class="glow-orb"></div>
    <div class="corner corner-tl"></div><div class="corner corner-tr"></div>
    <div class="corner corner-bl"></div><div class="corner corner-br"></div>
    
    <div class="container">
        <div class="shield-icon">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L3 7V12C3 17.55 6.84 22.74 12 24C17.16 22.74 21 17.55 21 12V7L12 2Z" 
                      fill="url(#shieldGrad)" stroke="#dc2626" stroke-width="0.5"/>
                <path d="M12 8V13M12 16V16.01" stroke="#ffffff" stroke-width="2" stroke-linecap="round"/>
                <defs><linearGradient id="shieldGrad" x1="12" y1="2" x2="12" y2="24" gradientUnits="userSpaceOnUse"><stop offset="0%" stop-color="#7f1d1d"/><stop offset="100%" stop-color="#450a0a"/></linearGradient></defs>
            </svg>
        </div>
        
        <div class="error-code">403 Forbidden</div>
        <h1>Access Denied</h1>
        <p class="subtitle">You are not authorized to view the Console logs.</p>
        
        <div class="warning-box">
            <p>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                Console permission required
            </p>
        </div>
        
        <p class="info-text">
            To view system logs, your client ID must be explicitly authorized. 
            Please contact your administrator to request access.
        </p>
    </div>
    
    <div class="brand">WIRESHIELD SECURITY</div>
</body>
</html>
        """
        return HTMLResponse(content=html_error, status_code=403)
        
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireShield Console</title>
    <style>
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 400; font-display: swap; src: url('/static/fonts/Inter-Regular.woff2') format('woff2'); }
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 500; font-display: swap; src: url('/static/fonts/Inter-SemiBold.woff2') format('woff2'); }
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 600; font-display: swap; src: url('/static/fonts/Inter-SemiBold.woff2') format('woff2'); }
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 700; font-display: swap; src: url('/static/fonts/Inter-Bold.woff2') format('woff2'); }

        :root {
            --bg: #f1f5f9;
            --card: #ffffff;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --accent: #2563eb;
            --accent-hover: #1d4ed8;
            --danger: #ef4444;
            --success: #16a34a;
            --border: #e2e8f0;
            --shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg);
            color: var(--text-primary);
            line-height: 1.5;
        }
        
        .layout {
            display: grid;
            grid-template-rows: auto 1fr;
            min-height: 100vh;
        }
        
        header {
            background-color: var(--card);
            border-bottom: 1px solid var(--border);
            padding: 0 2rem;
            height: 64px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            z-index: 10;
        }
        
        .brand {
            font-weight: 700;
            font-size: 1.25rem;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .brand span { color: var(--accent); }
        
        main {
            padding: 2rem;
            max-width: 1400px;
            margin: 0 auto;
            width: 100%;
        }
        
        .tabs {
            display: flex;
            gap: 2rem;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border);
        }
        
        .tab {
            padding: 0.75rem 0;
            cursor: pointer;
            color: var(--text-secondary);
            font-weight: 500;
            border-bottom: 2px solid transparent;
            transition: all 0.2s;
            font-size: 0.95rem;
        }
        
        .tab:hover { color: var(--text-primary); }
        
        .tab.active {
            color: var(--accent);
            border-bottom-color: var(--accent);
        }
        
        .card {
            background-color: var(--card);
            border-radius: 8px;
            border: 1px solid var(--border);
            box-shadow: var(--shadow);
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }
        
        .toolbar {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background-color: #f8fafc;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        .toolbar h3 {
            font-size: 1rem;
            font-weight: 600;
            color: var(--text-primary);
            margin-right: auto;
        }
        
        .filters {
            display: flex;
            gap: 0.75rem;
            align-items: center;
        }
        
        .input-group {
            position: relative;
        }
        
        .form-control {
            padding: 0.5rem 0.75rem;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 0.875rem;
            color: var(--text-primary);
            background: var(--card);
            min-width: 150px;
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.1);
        }
        
        select.form-control {
            cursor: pointer;
        }
        
        .btn {
            background-color: var(--accent);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            font-size: 0.875rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            transition: background-color 0.15s;
        }
        
        .btn:hover { background-color: var(--accent-hover); }
        
        .btn-outline {
            background-color: transparent;
            border: 1px solid var(--border);
            color: var(--text-secondary);
        }
        
        .btn-outline:hover:not(:disabled) {
            background-color: #f1f5f9;
            color: var(--text-primary);
        }
        
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .table-container {
            overflow-x: auto;
            min-height: 200px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }
        
        th, td {
            text-align: left;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border);
        }
        
        th {
            background-color: #f8fafc;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
            cursor: pointer;
            user-select: none;
            transition: background-color 0.2s;
        }
        
        th:hover {
            background-color: #e2e8f0;
            color: var(--text-primary);
        }
        
        th .sort-icon {
            display: inline-block;
            margin-left: 0.5rem;
            opacity: 0.3;
        }
        
        th.sorted-asc .sort-icon::after { content: '▲'; opacity: 1; }
        th.sorted-desc .sort-icon::after { content: '▼'; opacity: 1; }
        
        tr:hover td { background-color: #f8fafc; }
        
        .badge {
            padding: 0.25rem 0.625rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            display: inline-block;
        }
        
        .badge.success { background-color: #dcfce7; color: #166534; }
        .badge.error { background-color: #fee2e2; color: #991b1b; }
        .badge.info { background-color: #dbeafe; color: #1e40af; }
        
        .footer {
            padding: 1rem 1.5rem;
            border-top: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background-color: #f8fafc;
            font-size: 0.875rem;
            color: var(--text-secondary);
        }
        
        .pagination {
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }
        
        .view { display: none; }
        .view.active { display: block; animation: fadeIn 0.3s ease-out; }
        
        /* Loader */
        .spinner {
            border: 3px solid rgba(255,255,255,0.1);
            border-left-color: var(--accent);
            border-radius: 50%;
            width: 20px;
            height: 20px;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin { 100% { transform: rotate(360deg); } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }
    </style>
</head>
<body>
    <div class="layout">
        <header>
            <div class="brand">
                <img src="/static/logo.svg" alt="WireShield" style="width:40px;height:40px;">
                WireShield Console
            </div>
            <div style="font-size: 0.875rem; color: var(--text-secondary); background: var(--bg); padding: 0.25rem 0.75rem; border-radius: 9999px; border: 1px solid var(--border); font-weight: 500;">Authenticated</div>
        </header>
        
        <main>
            <div class="tabs">
                <div class="tab active" onclick="switchTab('activity', event)">Activity Log</div>
                <div class="tab" onclick="switchTab('access', event)">Access Log</div>
            </div>
            
            <!-- Activity Log View -->
            <div id="view-activity" class="view active">
                <div class="card">
                    <div class="toolbar">
                        <h3>System Activity</h3>
                        <div class="filters">
                            <select class="form-control" id="act-user" onchange="changeActivityPage(1)">
                                <option value="all">All Users</option>
                            </select>
                            <input type="text" class="form-control" id="act-search" placeholder="Search logs..." onkeyup="debounce(() => changeActivityPage(1), 500)">
                            <select class="form-control" id="act-limit" onchange="changeActivityPage(1)">
                                <option value="50">50 Rows</option>
                                <option value="100">100 Rows</option>
                                <option value="200">200 Rows</option>
                                <option value="500">500 Rows</option>
                            </select>
                            <button class="btn" onclick="changeActivityPage(1)">Refresh</button>
                        </div>
                    </div>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th onclick="sortActivity('timestamp')">Time <span class="sort-icon"></span></th>
                                    <th>User</th>
                                    <th>Source</th>
                                    <th>Destination</th>
                                    <th>Proto</th>
                                </tr>
                            </thead>
                            <tbody id="activity-tbody"></tbody>
                        </table>
                    </div>
                    <div class="footer">
                        <span id="act-info">Showing recent logs</span>
                        <div class="pagination">
                            <button class="btn btn-outline" id="act-prev" onclick="changeActivityPage(currentActivityPage - 1)" disabled>Previous</button>
                            <button class="btn btn-outline" id="act-next" onclick="changeActivityPage(currentActivityPage + 1)" disabled>Next</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Access Log View -->
            <div id="view-access" class="view">
                <div class="card">
                    <div class="toolbar">
                        <h3>Authentication Events</h3>
                        <div class="filters">
                            <select class="form-control" id="acc-user" onchange="changeAccessPage(1)">
                                <option value="all">All Users</option>
                            </select>
                            <input type="text" class="form-control" id="acc-search" placeholder="Search..." onkeyup="debounce(() => changeAccessPage(1), 500)">
                            <select class="form-control" id="acc-status" onchange="changeAccessPage(1)">
                                <option value="all">All Status</option>
                                <option value="success">Success</option>
                                <option value="failure">Failure / Denied</option>
                            </select>
                            <select class="form-control" id="acc-limit" onchange="changeAccessPage(1)">
                                <option value="10">10 Rows</option>
                                <option value="50" selected>50 Rows</option>
                                <option value="100">100 Rows</option>
                            </select>
                            <button class="btn" onclick="changeAccessPage(1)">Refresh</button>
                        </div>
                    </div>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th onclick="sortAccess('timestamp')">Time <span class="sort-icon"></span></th>
                                    <th onclick="sortAccess('client_id')">Client <span class="sort-icon"></span></th>
                                    <th onclick="sortAccess('action')">Action <span class="sort-icon"></span></th>
                                    <th onclick="sortAccess('status')">Status <span class="sort-icon"></span></th>
                                    <th onclick="sortAccess('ip_address')">IP Address <span class="sort-icon"></span></th>
                                </tr>
                            </thead>
                            <tbody id="access-tbody"></tbody>
                        </table>
                    </div>
                    <div class="footer">
                        <span id="acc-info">Loading...</span>
                        <div class="pagination">
                            <button class="btn btn-outline" id="acc-prev" onclick="changeAccessPage(currentAccessPage - 1)" disabled>Previous</button>
                            <button class="btn btn-outline" id="acc-next" onclick="changeAccessPage(currentAccessPage + 1)" disabled>Next</button>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script>
        // State
        let currentTab = 'activity';
        let currentActivityPage = 1;
        let currentAccessPage = 1;
        let debounceTimer;
        
        // Sorting State
        let actSortOrder = 'desc'; 
        
        let accSortBy = 'timestamp';
        let accSortOrder = 'desc';

        // Initial load
        init();

        async function init() {
            await fetchUsers();
            fetchActivityLogs();
        }

        async function fetchUsers() {
            try {
                const res = await fetch('/api/console/users');
                if (!res.ok) return;
                const users = await res.json();
                
                const actSelect = document.getElementById('act-user');
                const accSelect = document.getElementById('acc-user');
                
                users.forEach(u => {
                    const opt1 = document.createElement('option');
                    opt1.value = u.client_id;
                    opt1.innerText = `${u.client_id} (${u.ip})`;
                    actSelect.appendChild(opt1);
                    
                    const opt2 = document.createElement('option');
                    opt2.value = u.client_id;
                    opt2.innerText = `${u.client_id}`;
                    accSelect.appendChild(opt2);
                });
            } catch (e) {
                console.error("Failed to load users", e);
            }
        }

        // Utils
        const debounce = (func, delay) => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(func, delay);
        };

        function switchTab(tab, event) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
            
            event.target.classList.add('active');
            document.getElementById('view-' + tab).classList.add('active');
            
            currentTab = tab;
            if (tab === 'activity') fetchActivityLogs();
            if (tab === 'access') fetchAccessLogs();
        }
        
        // --- Activity Logs ---
        function sortActivity(col) {
            // Only timestamp is practically sortable for journalctl efficiently in this setup
            if (col !== 'timestamp') return; 
            
            actSortOrder = actSortOrder === 'desc' ? 'asc' : 'desc';
            updateHeaders('activity', col, actSortOrder);
            changeActivityPage(1);
        }
        
        function changeActivityPage(page) {
            if (page < 1) return;
            currentActivityPage = page;
            fetchActivityLogs();
        }

        async function fetchActivityLogs() {
            const tbody = document.getElementById('activity-tbody');
            const limit = document.getElementById('act-limit').value;
            const search = document.getElementById('act-search').value;
            const user = document.getElementById('act-user').value;
            
            updateHeaders('activity', 'timestamp', actSortOrder);
            
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 2rem;">Loading...</td></tr>';
            
            try {
                const params = new URLSearchParams({ 
                    page: currentActivityPage, 
                    limit, 
                    search, 
                    order: actSortOrder,
                    client_filter: user
                });
                const res = await fetch(`/api/console/activity-logs?${params}`);
                if (!res.ok) throw new Error('Failed to fetch');
                const data = await res.json();
                
                if (data.items.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 2rem;">No logs found matching filters.</td></tr>';
                    document.getElementById('act-info').innerText = 'No results';
                    return;
                }
                
                tbody.innerHTML = data.items.map(log => `
                    <tr>
                        <td style="color: var(--text-secondary); white-space: nowrap;">${log.timestamp}</td>
                        <td style="font-weight: 500;">${log.client || '-'}</td>
                        <td style="font-family: monospace;">${log.src}</td>
                        <td style="font-family: monospace;">${log.dst}:${log.dpt || ''}</td>
                        <td><span class="badge info">${log.proto}</span></td>
                    </tr>
                `).join('');
                
                updateActivityPagination(data);
                
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--danger); padding: 2rem;">Error: ${e.message}</td></tr>`;
            }
        }
        
        // --- Access Logs ---
        function sortAccess(col) {
            if (accSortBy === col) {
                accSortOrder = accSortOrder === 'desc' ? 'asc' : 'desc';
            } else {
                accSortBy = col;
                accSortOrder = 'desc'; // Default new sort to desc
            }
            changeAccessPage(1);
        }

        function changeAccessPage(page) {
            if (page < 1) return;
            currentAccessPage = page;
            fetchAccessLogs();
        }

        async function fetchAccessLogs() {
            const tbody = document.getElementById('access-tbody');
            const limit = document.getElementById('acc-limit').value;
            const search = document.getElementById('acc-search').value;
            const status = document.getElementById('acc-status').value;
            const user = document.getElementById('acc-user').value;
            
            updateHeaders('access', accSortBy, accSortOrder);
            
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 2rem;">Loading...</td></tr>';
            
            try {
                const params = new URLSearchParams({ 
                    page: currentAccessPage, 
                    limit, 
                    search, 
                    status,
                    sort_by: accSortBy,
                    order: accSortOrder,
                    client_filter: user
                });
                
                const res = await fetch(`/api/console/audit-logs?${params}`);
                if (!res.ok) throw new Error('Failed to fetch');
                const data = await res.json();
                
                if (data.items.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 2rem;">No logs found.</td></tr>';
                    updatePagination(data);
                    return;
                }
                
                tbody.innerHTML = data.items.map(log => {
                    let badgeClass = 'info';
                    const s = log.status.toLowerCase();
                    if (s.includes('success')) badgeClass = 'success';
                    if (s.includes('fail') || s.includes('invalid') || s.includes('denied')) badgeClass = 'error';
                    
                    return `
                    <tr>
                        <td style="color: var(--text-secondary); white-space: nowrap;">${log.timestamp}</td>
                        <td style="font-weight: 500;">${log.client_id || 'Unknown'}</td>
                        <td>${log.action}</td>
                        <td><span class="badge ${badgeClass}">${log.status}</span></td>
                        <td style="font-family: monospace;">${log.ip_address}</td>
                    </tr>
                `}).join('');
                
                updatePagination(data);
                
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--danger); padding: 2rem;">Error: ${e.message}</td></tr>`;
            }
        }
        
        function updateHeaders(tab, currentSort, currentOrder) {
            // Find specific view headers
            const container = document.getElementById(`view-${tab}`);
            if (!container) return;
            
            const ths = container.querySelectorAll('th');
            ths.forEach(th => {
                th.classList.remove('sorted-asc', 'sorted-desc');
                
                // Check if this th calls sort function with currentSort
                const onClick = th.getAttribute('onclick');
                if (onClick && onClick.includes(`'${currentSort}'`)) {
                    th.classList.add(`sorted-${currentOrder}`);
                }
            });
        }
        
        function updatePagination(data) {
            const start = (data.page - 1) * data.limit + 1;
            const end = Math.min(start + data.limit - 1, data.total);
            
            if (data.total === 0) {
                document.getElementById('acc-info').innerText = 'No results';
            } else {
                document.getElementById('acc-info').innerText = `Showing ${start}-${end} of ${data.total}`;
            }
            
            document.getElementById('acc-prev').disabled = data.page <= 1;
            document.getElementById('acc-next').disabled = data.page >= data.pages;
        }
        
        function updateActivityPagination(data) {
            const page = data.page || 1;
            const pages = data.pages || 1;
            const total = data.total || data.items.length;
            const limit = data.limit;
            const start = (page - 1) * limit + 1;
            const end = Math.min(start + limit - 1, total);
            
            if (total === 0) {
                document.getElementById('act-info').innerText = 'No results';
            } else {
                document.getElementById('act-info').innerText = `Showing ${start}-${end} of ${total}`;
            }
            
            document.getElementById('act-prev').disabled = page <= 1;
            document.getElementById('act-next').disabled = page >= pages;
        }
        
        // Initial load
       // fetchActivityLogs(); // Called by init() now
    </script>
</body>
</html>
    """
    return html

@app.get("/api/console/users")
async def get_console_users(client_id: str = Depends(_check_console_access)):
    """Fetch list of users for filter dropdowns."""
    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT client_id, wg_ipv4, wg_ipv6 FROM users ORDER BY client_id ASC")
    rows = c.fetchall()
    conn.close()
    
    users = []
    for r in rows:
        ip = r['wg_ipv4'] or r['wg_ipv6'] or 'No IP'
        users.append({"client_id": r['client_id'], "ip": ip})
    return users

@app.get("/api/console/audit-logs")
async def get_audit_logs(
    request: Request,
    page: int = 1,
    limit: int = 50,
    search: str = None,
    status: str = None,
    client_filter: str = None,
    sort_by: str = 'timestamp',
    order: str = 'desc',
    client_id: str = Depends(_check_console_access)
):
    """Fetch paginated and filtered audit logs from DB."""
    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    query = "SELECT timestamp, client_id, action, status, ip_address FROM audit_log"
    count_query = "SELECT COUNT(*) FROM audit_log"
    params = []
    conditions = []
    
    # Build filters
    if search:
        conditions.append("(client_id LIKE ? OR ip_address LIKE ? OR action LIKE ?)")
        search_term = f"%{search}%"
        params.extend([search_term, search_term, search_term])
    
    if status and status != 'all':
        if status == 'success':
            conditions.append("status LIKE '%Success%'")
        elif status == 'failure':
            conditions.append("(status LIKE '%Fail%' OR status LIKE '%Invalid%' OR status LIKE '%Denied%')")
            
    if client_filter:
        conditions.append("client_id LIKE ?")
        params.append(f"%{client_filter}%")
        
    # Apply filters
    if conditions:
        where_clause = " WHERE " + " AND ".join(conditions)
        query += where_clause
        count_query += where_clause
        
    # Get total count
    c.execute(count_query, params)
    total_count = c.fetchone()[0]
    
    # Apply sorting and pagination
    allowed_sorts = {'timestamp', 'client_id', 'action', 'status', 'ip_address'}
    if sort_by not in allowed_sorts:
        sort_by = 'timestamp'
    
    sort_order = 'DESC' if order.lower() == 'desc' else 'ASC'
    query += f" ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?"
    
    offset = (page - 1) * limit
    params.extend([limit, offset])
    
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    
    return {
        "items": [dict(row) for row in rows],
        "total": total_count,
        "page": page,
        "limit": limit,
        "pages": (total_count + limit - 1) // limit if limit > 0 else 1
    }

@app.get("/api/console/activity-logs")
async def get_activity_logs(
    page: int = 1,
    limit: int = 50,
    search: str = None,
    order: str = 'desc',
    client_filter: str = None,
    client_id: str = Depends(_check_console_access)
):
    """Fetch parsed activity logs from journalctl with filtering and pagination."""
    try:
        # Fetch more logs to support pagination (up to 10x limit for practical browsing)
        fetch_limit = min(limit * 10, 5000)
        cmd = ["journalctl", "-k", "-n", str(fetch_limit), "--output=short-iso", "--no-pager"]
        
        # Add search filter (grep pattern)
        if search:
            # -g is extremely fast on journalctl
            cmd.extend(["-g", search])
        else:
            # Default filter to show relevant traffic if no specific search
            cmd.extend(["-g", "WS-Audit"])
            
        proc = subprocess.run(cmd, capture_output=True, text=True)
        
        if proc.returncode != 0:
            return {"items": [], "limit": limit, "page": 1, "pages": 1, "total": 0}
            
        lines = proc.stdout.strip().splitlines()
        logs = []
        
        # We need to map IPs to Client IDs for display
        conn = get_db()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT client_id, wg_ipv4, wg_ipv6 FROM users")
        user_rows = c.fetchall()
        conn.close()
        
        ip_map = {}
        for row in user_rows:
            if row["wg_ipv4"]: ip_map[row["wg_ipv4"]] = row["client_id"]
            if row["wg_ipv6"]: ip_map[row["wg_ipv6"]] = row["client_id"]
            
        import re
        for line in lines:
            try:
                # Format: 2023-12-01T12:00:00+0000 hostname kernel: [WS-Audit] ... SRC=... DST=...
                parts = line.split()
                if len(parts) < 3: continue
                ts_raw = parts[0]
                # Format: 2023-12-01T12:00:00+0000 -> 2023-12-01 12:00:00
                ts = ts_raw.replace('T', ' ')[:19]
                
                src = ""
                dst = ""
                dpt = ""
                proto = ""
                
                src_m = re.search(r'SRC=([^\s]+)', line)
                dst_m = re.search(r'DST=([^\s]+)', line)
                dpt_m = re.search(r'DPT=([^\s]+)', line)
                proto_m = re.search(r'PROTO=([^\s]+)', line)
                
                if src_m: src = src_m.group(1)
                if dst_m: dst = dst_m.group(1)
                if dpt_m: dpt = dpt_m.group(1)
                if proto_m: proto = proto_m.group(1)
                
                client_name = ip_map.get(src, '')
                
                # Filter by client if requested
                if client_filter and client_filter != 'all':
                    if client_name != client_filter:
                        continue
                
                if src and dst:
                    logs.append({
                        "timestamp": ts,
                        "client": client_name,
                        "src": src,
                        "dst": dst,
                        "dpt": dpt,
                        "proto": proto
                    })
            except Exception:
                continue
        
        # Default is newest first (reversed from journalctl output)
        # If order is asc, keep original order
        if order.lower() == 'desc':
            logs = logs[::-1]
        
        # Pagination
        total = len(logs)
        pages = (total + limit - 1) // limit if limit > 0 else 1
        offset = (page - 1) * limit
        paginated_logs = logs[offset:offset + limit]
            
        return {"items": paginated_logs, "limit": limit, "page": page, "pages": pages, "total": total}
        
    except Exception as e:
        print(f"Error fetching logs: {e}")
        return {"items": [], "error": str(e), "limit": limit, "page": 1, "pages": 1, "total": 0}

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

    poll_interval = 3
    logger.info(
        "WireGuard session monitor active on %s (idle=%ss, disconnect_grace=%ss, poll=%ss)",
        interface,
        SESSION_IDLE_TIMEOUT_SECONDS,
        DISCONNECT_GRACE_SECONDS,
        poll_interval,
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

            # Map each allowed IP to its stats
            # keys: ip -> { 'handshake_ts': int, 'rx': int }
            ip_stats: Dict[str, Dict[str, int]] = {}
            now = int(time.time())
            for line in lines[1:]:
                parts = line.split('\t')
                if len(parts) < 6:
                    continue
                allowed_field = parts[3]
                try:
                    handshake_ts = int(parts[4])
                except ValueError:
                    handshake_ts = 0
                
                try:
                    rx_bytes = int(parts[5])
                except ValueError:
                    rx_bytes = 0
                
                stats = {'handshake_ts': handshake_ts, 'rx': rx_bytes}
                
                for ip in _extract_ips_from_allowed_field(allowed_field):
                    ip_stats[ip] = stats

            conn = get_db()
            try:
                c = conn.cursor()
                # Include session creation time to avoid pruning brand new sessions
                c.execute(
                    """
                    SELECT u.client_id AS client_id,
                           u.wg_ipv4     AS wg_ipv4,
                           u.wg_ipv6     AS wg_ipv6,
                           MAX(s.created_at) AS last_session_created
                    FROM users u
                    JOIN sessions s ON s.client_id = u.client_id
                    GROUP BY u.client_id, u.wg_ipv4, u.wg_ipv6
                    """
                )
                rows = c.fetchall()

                # Grace period after a fresh 2FA verification before we start enforcing checks
                # This ensures we don't kill a session before the client even connects
                grace_seconds = max(60, DISCONNECT_GRACE_SECONDS + 30)

                for row in rows:
                    client_id = row["client_id"]
                    v4 = (row["wg_ipv4"] or "").strip()
                    v6 = (row["wg_ipv6"] or "").strip()

                    # 1. New Session Grace: Skip if session is brand new
                    try:
                        created_ts = row["last_session_created"]
                        created_dt = datetime.strptime(created_ts, "%Y-%m-%d %H:%M:%S") if created_ts else None
                    except Exception:
                        created_dt = None

                    if created_dt is not None:
                        if (datetime.utcnow() - created_dt).total_seconds() < grace_seconds:
                            continue

                    # 2. Get Stats for this client
                    # We combine stats from v4 and v6 IPs (logic: if either is active, client is active)
                    current_stats = []
                    if v4 and v4 in ip_stats:
                        current_stats.append(ip_stats[v4])
                    if v6 and v6 in ip_stats:
                        current_stats.append(ip_stats[v6])
                    
                    if not current_stats:
                        # No info found in dump? Maybe disconnected or mismatch.
                        # If we can't find them in WG, they are definitely not active.
                        # But we should be careful about race conditions with WG restart.
                        # For now, treat missing as "no activity".
                        pass

                    # 3. Determine last activity time
                    # We track this in a persistent in-memory dict: client_activity_monitor
                    if not hasattr(_monitor_wireguard_sessions, "client_state"):
                        _monitor_wireguard_sessions.client_state = {}
                    
                    state = _monitor_wireguard_sessions.client_state.get(client_id, {
                        'last_rx': 0,
                        'last_handshake': 0,
                        'last_seen_active': time.time() # Assume active on startup/discovery to prevent instant kill
                    })
                    
                    # Calculate max current values across IPs
                    curr_rx = 0
                    curr_handshake = 0
                    for s in current_stats:
                         if s['rx'] > curr_rx: curr_rx = s['rx']
                         if s['handshake_ts'] > curr_handshake: curr_handshake = s['handshake_ts']
                    
                    is_active = False
                    
                    # Check for RX increase
                    if curr_rx > state['last_rx']:
                        is_active = True
                        state['last_rx'] = curr_rx
                    
                    # Check for Handshake update
                    if curr_handshake > state['last_handshake']:
                        is_active = True
                        state['last_handshake'] = curr_handshake
                        
                    if is_active:
                        state['last_seen_active'] = time.time()
                    
                    _monitor_wireguard_sessions.client_state[client_id] = state
                    
                    # 4. Check for Timeout
                    # How long since we last saw activity?
                    time_since_active = time.time() - state['last_seen_active']
                    
                    # We use DISCONNECT_GRACE_SECONDS as the threshold.
                    # Default 30s is fine if keepalives (25s) are working and RX checking is used.
                    
                    if time_since_active > DISCONNECT_GRACE_SECONDS:
                         stale_clients.append(client_id)
                    
                    # Note: We effectively ignore SESSION_IDLE_TIMEOUT_SECONDS for the "Drop" logic 
                    # because we want to enforce the stricter 'Disconnect' check.
                    # The session expiry (24h) is handled by the SQL query `expires_at > datetime('now')` check in `_sync_ipsets_from_sessions`?
                    # No, `_sync_ipsets_from_sessions` (not shown here) handles expiry.
                    # This function is purely for "Disconnect" cleanup.

                if stale_clients:
                    for cid in stale_clients:
                        c.execute("DELETE FROM sessions WHERE client_id = ?", (cid,))
                        # Cleanup state
                        if cid in _monitor_wireguard_sessions.client_state:
                            del _monitor_wireguard_sessions.client_state[cid]

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
<!DOCTYPE html>
<html lang="en">
<head>
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied | WireShield</title>
    <style>
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 400; font-display: swap; src: url('/static/fonts/Inter-Regular.woff2') format('woff2'); }
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 600; font-display: swap; src: url('/static/fonts/Inter-SemiBold.woff2') format('woff2'); }
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 700; font-display: swap; src: url('/static/fonts/Inter-Bold.woff2') format('woff2'); }
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 900; font-display: swap; src: url('/static/fonts/Inter-Black.woff2') format('woff2'); }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            min-height: 100vh;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 50%, #16213e 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            position: relative;
        }
        
        /* Animated background grid */
        body::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image: 
                linear-gradient(rgba(255,0,60,0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,0,60,0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            animation: gridPulse 4s ease-in-out infinite;
        }
        
        @keyframes gridPulse {
            0%, 100% { opacity: 0.3; }
            50% { opacity: 0.6; }
        }
        
        /* Glowing orb effect */
        .glow-orb {
            position: absolute;
            width: 400px;
            height: 400px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(220,38,38,0.15) 0%, transparent 70%);
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            animation: orbPulse 3s ease-in-out infinite;
        }
        
        @keyframes orbPulse {
            0%, 100% { transform: translate(-50%, -50%) scale(1); opacity: 0.5; }
            50% { transform: translate(-50%, -50%) scale(1.2); opacity: 0.8; }
        }
        
        .container {
            position: relative;
            z-index: 10;
            text-align: center;
            padding: 3rem;
            max-width: 520px;
        }
        
        /* Shield icon with warning */
        .shield-icon {
            width: 120px;
            height: 120px;
            margin: 0 auto 2rem;
            position: relative;
        }
        
        .shield-icon svg {
            width: 100%;
            height: 100%;
            filter: drop-shadow(0 0 30px rgba(220,38,38,0.5));
            animation: shieldGlow 2s ease-in-out infinite;
        }
        
        @keyframes shieldGlow {
            0%, 100% { filter: drop-shadow(0 0 20px rgba(220,38,38,0.4)); }
            50% { filter: drop-shadow(0 0 40px rgba(220,38,38,0.7)); }
        }
        
        .error-code {
            font-size: 0.875rem;
            font-weight: 600;
            letter-spacing: 0.3em;
            color: #dc2626;
            text-transform: uppercase;
            margin-bottom: 1rem;
            opacity: 0.9;
        }
        
        h1 {
            font-size: 2.5rem;
            font-weight: 900;
            color: #ffffff;
            margin-bottom: 1rem;
            letter-spacing: -0.02em;
            text-shadow: 0 0 40px rgba(220,38,38,0.3);
        }
        
        .subtitle {
            font-size: 1.125rem;
            color: #94a3b8;
            margin-bottom: 2.5rem;
            line-height: 1.6;
        }
        
        .warning-box {
            background: rgba(220,38,38,0.1);
            border: 1px solid rgba(220,38,38,0.3);
            border-radius: 12px;
            padding: 1.25rem 1.5rem;
            margin-bottom: 2rem;
        }
        
        .warning-box p {
            color: #f87171;
            font-size: 0.9rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }
        
        .info-text {
            font-size: 0.875rem;
            color: #64748b;
            line-height: 1.7;
        }
        
        .info-text strong {
            color: #94a3b8;
        }
        
        /* Decorative corners */
        .corner {
            position: fixed;
            width: 100px;
            height: 100px;
            border: 2px solid rgba(220,38,38,0.2);
        }
        
        .corner-tl { top: 20px; left: 20px; border-right: none; border-bottom: none; }
        .corner-tr { top: 20px; right: 20px; border-left: none; border-bottom: none; }
        .corner-bl { bottom: 20px; left: 20px; border-right: none; border-top: none; }
        .corner-br { bottom: 20px; right: 20px; border-left: none; border-top: none; }
        
        .brand {
            position: fixed;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 0.75rem;
            color: #475569;
            letter-spacing: 0.1em;
        }
    </style>
</head>
<body>
    <div class="glow-orb"></div>
    <div class="corner corner-tl"></div>
    <div class="corner corner-tr"></div>
    <div class="corner corner-bl"></div>
    <div class="corner corner-br"></div>
    
    <div class="container">
        <div class="shield-icon">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L3 7V12C3 17.55 6.84 22.74 12 24C17.16 22.74 21 17.55 21 12V7L12 2Z" 
                      fill="url(#shieldGrad)" stroke="#dc2626" stroke-width="0.5"/>
                <path d="M12 8V13M12 16V16.01" stroke="#ffffff" stroke-width="2" stroke-linecap="round"/>
                <defs>
                    <linearGradient id="shieldGrad" x1="12" y1="2" x2="12" y2="24" gradientUnits="userSpaceOnUse">
                        <stop offset="0%" stop-color="#7f1d1d"/>
                        <stop offset="100%" stop-color="#450a0a"/>
                    </linearGradient>
                </defs>
            </svg>
        </div>
        
        <div class="error-code">Security Alert</div>
        <h1>Access Denied</h1>
        <p class="subtitle">This portal is restricted to authorized VPN clients only.</p>
        
        <div class="warning-box">
            <p>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="12" y1="8" x2="12" y2="12"/>
                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                Your connection was not recognized
            </p>
        </div>
        
        <p class="info-text">
            To access this service, you must be connected through <strong>WireShield VPN</strong>. 
            If you believe this is an error, verify your VPN connection and try again.
        </p>
    </div>
    
    <div class="brand">WIRESHIELD SECURITY</div>
</body>
</html>
            """,
            status_code=403
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
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
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
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
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
                <img src="/static/logo.svg" alt="WireShield" style="width:42px;height:42px;">
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
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
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
            <img src="/static/logo.svg" alt="WireShield" style="width:60px;height:60px;">
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
