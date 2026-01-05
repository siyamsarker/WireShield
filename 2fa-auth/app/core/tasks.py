import time
import shutil
import subprocess
import logging
import threading
import socket
from datetime import datetime
from typing import Dict
from http.server import HTTPServer, BaseHTTPRequestHandler

from app.core.config import (
    AUTH_HTTP_PORT, WIREGUARD_PARAMS_PATH, WG_INTERFACE,
    SESSION_IDLE_TIMEOUT_SECONDS, DISCONNECT_GRACE_SECONDS, UI_BASE_URL
)
from app.core.database import get_db
from app.core.security import (
    ensure_ipsets, _ipset, audit_log, remove_client_by_id,
    _extract_ips_from_allowed_field
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
    except Exception as exc: 
        logger.debug("WireGuard params parse error: %s", exc)
    return params

def _ensure_wg_interface() -> str:
    """Determine which WireGuard interface to monitor for peer activity."""
    # We need to handle the global WG_INTERFACE potentially being updated
    # In this cleaner module, we'll re-read or use the config value
    if WG_INTERFACE:
        return WG_INTERFACE
    params = _load_wireguard_params()
    return params.get("SERVER_WG_NIC") or "wg0"

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
                    current_stats = []
                    if v4 and v4 in ip_stats:
                        current_stats.append(ip_stats[v4])
                    if v6 and v6 in ip_stats:
                        current_stats.append(ip_stats[v6])
                    
                    if not current_stats:
                        pass

                    # 3. Determine last activity time
                    if not hasattr(_monitor_wireguard_sessions, "client_state"):
                        _monitor_wireguard_sessions.client_state = {}
                    
                    state = _monitor_wireguard_sessions.client_state.get(client_id, {
                        'last_rx': 0,
                        'last_handshake': 0,
                        'last_seen_active': time.time()
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
                    time_since_active = time.time() - state['last_seen_active']
                    
                    if time_since_active > DISCONNECT_GRACE_SECONDS:
                         stale_clients.append(client_id)

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

def start_background_tasks():
    threading.Thread(target=_sync_ipsets_from_sessions, daemon=True).start()
    threading.Thread(target=_monitor_wireguard_sessions, daemon=True).start()
    threading.Thread(target=_start_http_redirector_ipv4, daemon=True).start()
    threading.Thread(target=_start_http_redirector_ipv6, daemon=True).start()
