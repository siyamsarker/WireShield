import base64
import pyotp
import qrcode
import logging
from io import BytesIO
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from app.core.database import get_db
from app.core.security import (
    audit_log, rate_limiter, generate_session_token, hash_session_token,
    verify_session_token, allow_client_by_id
)
from app.core.config import SESSION_TIMEOUT_MINUTES
from app.templates import (
    get_2fa_ui_html, get_2fa_verify_only_html, get_success_html,
    get_access_denied_html
)

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/", response_class=HTMLResponse, tags=["ui"])
async def root(request: Request, client_id: Optional[str] = None):
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
        return get_access_denied_html()
    
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

@router.get("/success", response_class=HTMLResponse, tags=["ui"])
async def success_page(client_id: Optional[str] = None):
    """Success page after 2FA verification - indicates client can now access internet."""
    return get_success_html()

@router.post("/api/setup-start", tags=["2fa-setup"])
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

@router.post("/api/setup-verify", tags=["2fa-setup"])
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

@router.post("/api/verify", tags=["2fa-auth"])
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

@router.post("/api/validate-session", tags=["session"])
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
