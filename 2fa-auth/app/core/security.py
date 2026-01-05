import hashlib
import hmac
import secrets
import logging
import asyncio
import time
import subprocess
from collections import defaultdict, deque
from typing import Optional
from fastapi import Request, HTTPException

from app.core.database import get_db
from app.core.config import RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS

logger = logging.getLogger(__name__)

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
