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
import pyotp
import qrcode
from io import BytesIO
import base64

# ============================================================================
# Configuration
# ============================================================================
LOG_LEVEL = os.getenv("2FA_LOG_LEVEL", "INFO")
AUTH_DB_PATH = os.getenv("2FA_DB_PATH", "/etc/wireshield/2fa/auth.db")
AUTH_HOST = os.getenv("2FA_HOST", "0.0.0.0")
AUTH_PORT = int(os.getenv("2FA_PORT", "8443"))
SSL_CERT = os.getenv("2FA_SSL_CERT", "/etc/wireshield/2fa/cert.pem")
SSL_KEY = os.getenv("2FA_SSL_KEY", "/etc/wireshield/2fa/key.pem")
SSL_ENABLED = os.getenv("2FA_SSL_ENABLED", "true").lower() in ("true", "1", "yes")
SSL_TYPE = os.getenv("2FA_SSL_TYPE", "self-signed")  # self-signed, letsencrypt
TFA_DOMAIN = os.getenv("2FA_DOMAIN", "")
TFA_HOSTNAME = os.getenv("2FA_HOSTNAME", "127.0.0.1")
SECRET_KEY = os.getenv("2FA_SECRET_KEY", "")  # Must be set in production
SESSION_TIMEOUT_MINUTES = int(os.getenv("2FA_SESSION_TIMEOUT", "1440"))  # 24h default
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("2FA_RATE_LIMIT_MAX_REQUESTS", "30"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("2FA_RATE_LIMIT_WINDOW", "60"))

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
    """Serve 2FA setup/verification UI."""
    if not client_id:
        return HTMLResponse("<h1>Missing client_id</h1>", status_code=400)
    
    ip_address = request.client.host if request else "unknown"
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
    <title>WireShield 2FA - Secure Authentication</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 500px;
            width: 100%;
            padding: 40px;
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
        }}
        .logo {{
            font-size: 32px;
            margin-bottom: 10px;
        }}
        h1 {{
            color: #333;
            font-size: 24px;
            margin-bottom: 10px;
        }}
        .subtitle {{
            color: #666;
            font-size: 14px;
        }}
        .client-id {{
            background: #f5f5f5;
            padding: 10px;
            border-radius: 6px;
            margin-top: 15px;
            font-family: monospace;
            font-size: 12px;
            color: #666;
            word-break: break-all;
        }}
        .section {{
            margin-bottom: 30px;
        }}
        .qr-container {{
            text-align: center;
            margin: 20px 0;
        }}
        .qr-container img {{
            max-width: 100%;
            border: 2px solid #f0f0f0;
            border-radius: 8px;
            padding: 10px;
        }}
        .secret-code {{
            background: #f9f9f9;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #667eea;
            margin: 15px 0;
            font-family: monospace;
            font-size: 13px;
            word-break: break-all;
            color: #333;
        }}
        .info-box {{
            background: #e8f4f8;
            border-left: 4px solid #2196F3;
            padding: 15px;
            border-radius: 6px;
            font-size: 13px;
            color: #0277bd;
            margin: 15px 0;
        }}
        input[type="text"], input[type="password"] {{
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
            margin: 10px 0;
            transition: border-color 0.3s;
        }}
        input[type="text"]:focus, input[type="password"]:focus {{
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }}
        button {{
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            margin-top: 10px;
        }}
        button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }}
        button:active {{
            transform: translateY(0);
        }}
        button:disabled {{
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }}
        .success {{
            background: #c8e6c9;
            color: #2e7d32;
            padding: 15px;
            border-radius: 6px;
            margin: 15px 0;
            display: none;
        }}
        .error {{
            background: #ffcdd2;
            color: #c62828;
            padding: 15px;
            border-radius: 6px;
            margin: 15px 0;
            display: none;
        }}
        .spinner {{
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            animation: spin 1s linear infinite;
            display: inline-block;
            margin-right: 10px;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        .step-indicator {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 30px;
            text-align: center;
        }}
        .step {{
            flex: 1;
            color: #999;
            font-size: 12px;
            position: relative;
        }}
        .step.active {{
            color: #667eea;
            font-weight: 600;
        }}
        .step:not(:last-child)::after {{
            content: '';
            position: absolute;
            top: -15px;
            right: -50%;
            width: 100%;
            height: 2px;
            background: #ddd;
        }}
        .step.active::before {{
            content: '✓';
            display: inline-block;
            width: 24px;
            height: 24px;
            background: #667eea;
            color: white;
            border-radius: 50%;
            line-height: 24px;
            margin-bottom: 5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️</div>
            <h1>WireShield 2FA</h1>
            <p class="subtitle">Secure your VPN connection</p>
            <div class="client-id">Client: {client_id}</div>
        </div>
        
        <div id="successMsg" class="success"></div>
        <div id="errorMsg" class="error"></div>
        
        <div id="setupPhase">
            <div class="step-indicator">
                <div class="step active">1. Download App</div>
                <div class="step">2. Scan QR</div>
                <div class="step">3. Verify</div>
            </div>
            
            <div class="section">
                <h2 style="font-size: 16px; margin-bottom: 15px;">Step 1: Download Authenticator</h2>
                <div class="info-box">
                    Install <strong>Google Authenticator</strong> or any TOTP-compatible app (Authy, Microsoft Authenticator, etc.)
                </div>
            </div>
            
            <div class="section">
                <h2 style="font-size: 16px; margin-bottom: 15px;">Step 2: Scan QR Code</h2>
                <button onclick="generateQR()">Generate QR Code</button>
                <div id="qrContainer" class="qr-container" style="display: none;">
                    <img id="qrImage" src="" alt="QR Code">
                </div>
                <div id="secretContainer" style="display: none;">
                    <p style="font-size: 12px; color: #666; margin-bottom: 10px;">Or enter this code manually:</p>
                    <div class="secret-code" id="secretCode"></div>
                </div>
            </div>
            
            <div class="section">
                <h2 style="font-size: 16px; margin-bottom: 15px;">Step 3: Verify Code</h2>
                <input type="text" id="verifyCode" placeholder="Enter 6-digit code from your app" maxlength="6" pattern="[0-9]{{6}}" inputmode="numeric" />
                <button onclick="verifySetup()" id="verifyBtn">Verify & Connect</button>
            </div>
        </div>
        
        <div id="successPhase" style="display: none; text-align: center;">
            <div style="font-size: 48px; margin-bottom: 20px;">✅</div>
            <h2 style="color: #4caf50; margin-bottom: 10px;">Setup Complete!</h2>
            <p style="color: #666; margin-bottom: 20px;">Your 2FA is now active. You can connect to VPN.</p>
            <p style="font-size: 12px; color: #999; margin-bottom: 20px;">Session expires in 24 hours.</p>
            <button onclick="location.reload()" style="background: #4caf50;">Close & Connect</button>
        </div>
    </div>
    
    <script>
        let setupData = {{}};
        
        async function generateQR() {{
            try {{
                document.getElementById('errorMsg').style.display = 'none';
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
            
            try {{
                const btn = document.getElementById('verifyBtn');
                btn.disabled = true;
                btn.innerHTML = '<span class="spinner"></span>Verifying...';
                
                const formData = new FormData();
                formData.append('client_id', '{client_id}');
                formData.append('code', code);
                
                const response = await fetch('/api/setup-verify', {{ method: 'POST', body: formData }});
                const data = await response.json();
                
                if (data.success) {{
                    // Save session token to localStorage for firewall integration
                    localStorage.setItem('session_token', data.session_token);
                    localStorage.setItem('client_id', '{client_id}');
                    
                    document.getElementById('setupPhase').style.display = 'none';
                    document.getElementById('successPhase').style.display = 'block';
                    showSuccess('2FA verified successfully!');
                }} else {{
                    showError(data.detail || 'Verification failed');
                    btn.disabled = false;
                    btn.textContent = 'Verify & Connect';
                }}
            }} catch (e) {{
                showError('Error: ' + e.message);
                btn.disabled = false;
                btn.textContent = 'Verify & Connect';
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
