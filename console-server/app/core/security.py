import hashlib
import hmac
import secrets
import sqlite3
import logging
import asyncio
import time
import subprocess
from collections import deque
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
    """Sliding-window in-memory rate limiter, per (client IP, path).

    Every unique (IP, path) pair creates an entry in _hits.  Without
    eviction those entries accumulate forever — one per unique client per
    rate-limited endpoint — causing unbounded memory growth under sustained
    traffic from many clients.

    Fix: a periodic sweep (every _SWEEP_INTERVAL calls) deletes any key
    whose most recent hit is older than the sliding window.  If a client
    has been silent for longer than window_seconds its bucket is guaranteed
    to be empty, so removing the key is safe and free.  The sweep is O(n)
    in the number of live keys but runs infrequently (amortised O(1)/call).
    """

    _SWEEP_INTERVAL = 500  # evict stale keys every N __call__ invocations

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict = {}       # key -> deque[float] of hit timestamps
        self._lock = asyncio.Lock()
        self._call_count = 0

    async def __call__(self, request: Request):
        # Combine client IP and path so limits are per-endpoint per-client.
        client_ip = request.client.host if request and request.client else "unknown"
        key = f"{client_ip}:{request.url.path if request else 'unknown'}"
        now = time.time()
        cutoff = now - self.window_seconds

        async with self._lock:
            self._call_count += 1

            # Periodic sweep: delete keys whose most recent hit is outside
            # the window — they hold no active hits and will never fire a
            # 429.  Runs every _SWEEP_INTERVAL calls to amortise the cost.
            if self._call_count % self._SWEEP_INTERVAL == 0:
                stale = [k for k, v in self._hits.items() if not v or v[-1] < cutoff]
                for k in stale:
                    del self._hits[k]

            # Get or create this caller's bucket.
            if key not in self._hits:
                self._hits[key] = deque()
            bucket = self._hits[key]

            # Drop entries outside the window.
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


# ============================================================================
# TOTP Replay Prevention
# ============================================================================

# TOTP codes are valid for ±1 window (30 s each) = up to 90 s total.
_TOTP_REPLAY_WINDOW_SECONDS = 90


def check_and_mark_totp_code(client_id: str, code: str) -> bool:
    """Return True if `code` is being used for the first time (safe to accept).
    Return False if the same code was already accepted within the replay window.

    The INSERT with UNIQUE(client_id, code) is atomic: two concurrent requests
    carrying the same intercepted code will race — exactly one succeeds and the
    other gets IntegrityError, so there is no TOCTOU window between check and mark.

    Stale entries (older than the replay window) are pruned inline on each call
    so the table stays small without a separate background job.

    Call this AFTER pyotp.TOTP.verify() succeeds — only accepted codes are stored,
    so a user who miskeys the same digit sequence twice in a row is not locked out.
    """
    conn = get_db()
    c = conn.cursor()
    try:
        # Prune expired entries for this client to keep the table bounded.
        c.execute(
            "DELETE FROM totp_used_codes WHERE client_id = ? AND used_at < datetime('now', ?)",
            (client_id, f"-{_TOTP_REPLAY_WINDOW_SECONDS} seconds"),
        )
        # Atomically mark this code as used.  If the row already exists the
        # UNIQUE constraint fires and we catch IntegrityError below.
        c.execute(
            "INSERT INTO totp_used_codes (client_id, code) VALUES (?, ?)",
            (client_id, code),
        )
        conn.commit()
        return True  # First use — not a replay
    except sqlite3.IntegrityError:
        conn.rollback()
        return False  # Already used within the validity window — replay
    finally:
        conn.close()


# ============================================================================
# Client IP Verification (prevents client_id forgery / account takeover)
# ============================================================================

def verify_client_ip(client_id: str, ip_address: str) -> bool:
    """Return True when ip_address is legitimately associated with client_id.

    Two-pass check:
      1. If the connecting IP already belongs to a *different* client in the
         users table, reject immediately — this is a clear forgery attempt.
      2. If the requested client_id has a registered WG IP, it must match the
         connecting IP.  If no IP is registered yet (edge case: manual DB entry
         or legacy path in setup_start), we allow so first-time setup is not
         broken.

    Returns False only when the IP clearly belongs to someone else, or when
    a mismatch is detected on a client that already has an IP registered.
    """
    conn = get_db()
    c = conn.cursor()
    try:
        # Pass 1: does this IP already belong to a DIFFERENT client?
        c.execute(
            "SELECT client_id FROM users "
            "WHERE (wg_ipv4 = ? OR wg_ipv6 = ?) AND client_id != ?",
            (ip_address, ip_address, client_id),
        )
        if c.fetchone() is not None:
            return False  # IP owned by someone else — reject

        # Pass 2: does this client have a registered IP that differs?
        c.execute(
            "SELECT wg_ipv4, wg_ipv6 FROM users WHERE client_id = ?",
            (client_id,),
        )
        row = c.fetchone()
        if row is None:
            # Unknown client_id — allow (setup_start auto-creates users)
            return True
        registered_v4 = (row["wg_ipv4"] or "").strip()
        registered_v6 = (row["wg_ipv6"] or "").strip()
        if not registered_v4 and not registered_v6:
            # No IP on file yet — allow (first-time setup edge case)
            return True
        return ip_address in (registered_v4, registered_v6)
    finally:
        conn.close()
