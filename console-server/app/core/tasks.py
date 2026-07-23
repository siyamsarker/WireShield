import time
import shutil
import subprocess
import logging
import threading
import socket
import hashlib
import re
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler

from app.core.config import (
    AUTH_HTTP_PORT, WIREGUARD_PARAMS_PATH, WG_INTERFACE,
    SESSION_IDLE_TIMEOUT_SECONDS, DISCONNECT_GRACE_SECONDS, UI_BASE_URL,
    ACTIVITY_LOG_RETENTION_DAYS
)
from app.core.database import get_db
from app.core.security import (
    ensure_ipsets, _ipset, audit_log, remove_client_by_id,
    _extract_ips_from_allowed_field
)

logger = logging.getLogger(__name__)

# Track wireguard session stats across polling cycles
_MONITOR_BW_STATE: Dict[str, Dict[str, int]] = {}
_MONITOR_CLIENT_STATE: Dict[str, Dict[str, float]] = {}

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
    """Periodically remove clients without any active session from ipsets.

    Diffs against the actual ipset membership (`ipset list -q`) before
    issuing deletes — without this each cycle forks N×2 `ipset del` calls
    for users that were never in the set, costing seconds of CPU at fleet
    scale and contending for ipset's internal lock.
    """
    def _ipset_members(name: str) -> set:
        try:
            out = subprocess.run(
                ["ipset", "list", "-q", name],
                capture_output=True, text=True, timeout=10,
            )
            if out.returncode != 0:
                return set()
            members = set()
            in_members = False
            for line in out.stdout.splitlines():
                if line.startswith("Members:"):
                    in_members = True
                    continue
                if in_members:
                    addr = line.strip().split()[0] if line.strip() else ""
                    if addr:
                        members.add(addr)
            return members
        except Exception:
            return set()

    while True:
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT DISTINCT client_id FROM sessions WHERE expires_at > datetime('now')")
            active = set(row[0] for row in c.fetchall())
            c.execute("SELECT client_id, wg_ipv4, wg_ipv6 FROM users")
            users = c.fetchall()
            conn.close()
            ensure_ipsets()

            members_v4 = _ipset_members("ws_2fa_allowed_v4")
            members_v6 = _ipset_members("ws_2fa_allowed_v6")

            for client_id, v4, v6 in users:
                if client_id in active:
                    continue
                if v4 and v4 in members_v4:
                    _ipset(["ipset", "del", "ws_2fa_allowed_v4", v4])
                if v6 and v6 in members_v6:
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
                    rx_bytes = int(parts[5]) # Server RX (Client Upload)
                except ValueError:
                    rx_bytes = 0
                
                try:
                    tx_bytes = int(parts[6]) # Server TX (Client Download)
                except ValueError:
                    tx_bytes = 0
                
                stats = {'handshake_ts': handshake_ts, 'rx': rx_bytes, 'tx': tx_bytes}
                
                for ip in _extract_ips_from_allowed_field(allowed_field):
                    ip_stats[ip] = stats

            conn = get_db()
            try:
                c = conn.cursor()
                # Need ALL users (ip -> client_id mapping) for bandwidth tracking
                # AND need session data for expiration
                c.execute(
                    """
                    SELECT u.client_id, u.wg_ipv4, u.wg_ipv6, 
                           MAX(s.created_at) as last_session_created,
                           MAX(s.expires_at) as session_expires
                    FROM users u
                    LEFT JOIN sessions s ON s.client_id = u.client_id
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
                    has_session = row["session_expires"] is not None

                    # 1. Get Stats for this client (always, regardless of session age)
                    current_stats = []
                    if v4 and v4 in ip_stats:
                        current_stats.append(ip_stats[v4])
                    if v6 and v6 in ip_stats:
                        current_stats.append(ip_stats[v6])

                    # 2. Bandwidth Tracking (runs unconditionally)
                    # We track deltas for Server RX (Client Upload) and Server TX (Client Download)
                    curr_server_rx = 0
                    curr_server_tx = 0
                    curr_handshake = 0

                    for s in current_stats:
                         if s['rx'] > curr_server_rx: curr_server_rx = s['rx']
                         if s['tx'] > curr_server_tx: curr_server_tx = s['tx']
                         if s['handshake_ts'] > curr_handshake: curr_handshake = s['handshake_ts']

                    bw_state = _MONITOR_BW_STATE.get(client_id, {
                        'prev_server_rx': curr_server_rx,
                        'prev_server_tx': curr_server_tx
                    })

                    # Calculate Deltas
                    delta_rx = curr_server_rx - bw_state['prev_server_rx'] # Client Upload
                    delta_tx = curr_server_tx - bw_state['prev_server_tx'] # Client Download

                    # Handle restart/reset (curr < prev)
                    if delta_rx < 0: delta_rx = curr_server_rx
                    if delta_tx < 0: delta_tx = curr_server_tx

                    # Update State
                    bw_state['prev_server_rx'] = curr_server_rx
                    bw_state['prev_server_tx'] = curr_server_tx
                    _MONITOR_BW_STATE[client_id] = bw_state

                    # Persist if there is activity
                    if delta_rx > 0 or delta_tx > 0:
                        # Use UTC date to match API queries (SQLite date('now') is UTC)
                        today = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d")
                        # DB Mapping: rx_bytes (Client Download/Server TX), tx_bytes (Client Upload/Server RX)
                        # Note: We are using standard ISP terminology for the DB columns where RX is what client receives.
                        try:
                            c.execute("""
                                INSERT INTO bandwidth_usage (client_id, scan_date, rx_bytes, tx_bytes)
                                VALUES (?, ?, ?, ?)
                                ON CONFLICT(client_id, scan_date) DO UPDATE SET
                                rx_bytes = rx_bytes + ?,
                                tx_bytes = tx_bytes + ?,
                                updated_at = CURRENT_TIMESTAMP
                            """, (client_id, today, delta_tx, delta_rx, delta_tx, delta_rx))
                        except Exception as e:
                            logger.error(f"Failed to update bandwidth for {client_id}: {e}")

                    # 3. Session Idle Check & Expiry Logic (only for active sessions)
                    if has_session:
                        # Grace period: skip expiry checks for brand-new sessions
                        in_grace = False
                        try:
                            created_ts = row["last_session_created"]
                            created_dt = datetime.strptime(created_ts, "%Y-%m-%d %H:%M:%S") if created_ts else None
                        except Exception:
                            created_dt = None

                        if created_dt is not None:
                            in_grace = (datetime.now(timezone.utc).replace(tzinfo=None) - created_dt).total_seconds() < grace_seconds

                        if not in_grace:
                            state = _MONITOR_CLIENT_STATE.get(client_id, {
                                'last_rx': 0,
                                'last_handshake': 0,
                                'last_seen_active': time.time()
                            })

                            is_active = False
                            if curr_server_rx > state['last_rx']:
                                is_active = True
                                state['last_rx'] = curr_server_rx
                            if curr_handshake > state['last_handshake']:
                                is_active = True
                                state['last_handshake'] = curr_handshake

                            if is_active:
                                 state['last_seen_active'] = time.time()

                            _MONITOR_CLIENT_STATE[client_id] = state

                            if (time.time() - state['last_seen_active']) > DISCONNECT_GRACE_SECONDS:
                                 stale_clients.append(client_id)

                    conn.commit() # Commit active updates
            finally:
                conn.close()

            for cid in stale_clients:
                remove_client_by_id(cid)
                audit_log(cid, "SESSION_MONITOR", "expired_on_disconnect", "wireguard-monitor")
        except Exception as exc:
            logger.debug(f"WireGuard session monitor error: {exc}")

        time.sleep(poll_interval)


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/reserved (no useful reverse DNS)."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return True


def _reverse_resolve(ip_str: str) -> Optional[str]:
    """Perform a reverse DNS lookup for an IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        if hostname:
            return hostname.rstrip('.')
    except (socket.herror, socket.gaierror, OSError, UnicodeError):
        pass
    return None


def _resolve_ips_to_dns_cache(ips: List[str]) -> int:
    """Reverse-resolve a list of IPs and store results in dns_cache.
    Returns the number of new mappings cached."""
    resolved = 0
    for ip in ips:
        if _is_private_ip(ip):
            continue
        domain = _reverse_resolve(ip)
        if domain:
            try:
                conn = get_db()
                c = conn.cursor()
                c.execute("""
                    INSERT OR REPLACE INTO dns_cache (ip_address, domain, timestamp)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                """, (ip, domain))
                conn.commit()
                conn.close()
                resolved += 1
            except Exception:
                pass
    return resolved


# ----------------------------------------------------------------------------
# Activity Log Ingestion (journalctl -> SQLite)
# ----------------------------------------------------------------------------
def _ingest_activity_logs():
    journalctl = shutil.which("journalctl")
    if not journalctl:
        logger.warning("journalctl not found; activity log ingestion disabled")
        return

    poll_interval = 5
    logger.info("Activity log ingestion enabled (poll=%ss)", poll_interval)

    while True:
        start_time = time.monotonic()
        try:
            # Determine starting point
            last_ts = None
            try:
                conn = get_db()
                c = conn.cursor()
                c.execute("SELECT MAX(timestamp) FROM activity_log")
                last_ts = c.fetchone()[0]
                conn.close()
            except Exception:
                last_ts = None

            cmd = [journalctl, "-k", "-n", "5000", "--output=short-iso", "--no-pager"]
            if last_ts:
                # last_ts is stored UTC ("YYYY-MM-DD HH:MM:SS"). journalctl
                # interprets bare timestamps as system-local, so on a non-UTC
                # host the window is wrong and we either re-ingest or skip
                # log lines. Pin the window to UTC explicitly.
                cmd.extend(["--since", f"{last_ts} UTC"])

            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            lines = proc.stdout.strip().splitlines() if proc.stdout else []

            # Filter for WireShield audit logs (must have [WS-Audit] prefix AND iptables markers)
            wg_lines = [l for l in lines if "[WS-Audit]" in l and any(marker in l for marker in ["IN=", "OUT=", "SRC=", "DST="])]
            if not wg_lines:
                time.sleep(poll_interval)
                continue

            # Load client IP mapping for identification
            ip_to_client = {}
            try:
                conn = get_db()
                c = conn.cursor()
                c.execute("SELECT client_id, wg_ipv4, wg_ipv6 FROM users")
                for row in c.fetchall():
                    if row[1]:
                        ip_to_client[row[1]] = row[0]
                    if row[2]:
                        ip_to_client[row[2]] = row[0]
                conn.close()
            except Exception:
                pass

            # Retroactively backfill client_id for any historical NULL records
            # that can now be resolved (e.g. client authenticated after traffic was logged)
            if ip_to_client:
                try:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute("SELECT COUNT(*) FROM activity_log WHERE client_id IS NULL")
                    null_count = c.fetchone()[0]
                    if null_count > 0:
                        for ip, cid in ip_to_client.items():
                            c.execute(
                                "UPDATE activity_log SET client_id = ? "
                                "WHERE client_id IS NULL AND (src_ip = ? OR dst_ip = ?)",
                                (cid, ip, ip)
                            )
                        conn.commit()
                    conn.close()
                except Exception:
                    pass

            entries = []
            for line in wg_lines:
                parts = line.split(" ", 3)
                ts_raw = parts[0] if parts else ""
                msg = parts[3] if len(parts) > 3 else line

                ts = ts_raw
                try:
                    if 'T' in ts_raw:
                        dt = datetime.fromisoformat(ts_raw.replace('Z', '+00:00'))
                        # journalctl --output=short-iso emits LOCAL time with
                        # a TZ offset (e.g. 2026-05-12T20:30:00+0530). Naively
                        # strftime'ing the parsed value preserves the local
                        # wall-clock instead of UTC, which then drifts from the
                        # UTC dates the API filters expect. Convert to UTC
                        # before storing so timestamps are uniform regardless
                        # of host timezone.
                        if dt.tzinfo is not None:
                            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
                        ts = dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    pass

                direction = None
                protocol = None
                src_ip = None
                src_port = None
                dst_ip = None
                dst_port = None
                client_id = None

                in_match = re.search(r'IN=(\S*)', msg)
                out_match = re.search(r'OUT=(\S*)', msg)
                if in_match and in_match.group(1):
                    direction = "IN"
                elif out_match and out_match.group(1):
                    direction = "OUT"

                src_match = re.search(r'SRC=(\S+)', msg)
                dst_match = re.search(r'DST=(\S+)', msg)
                if src_match:
                    src_ip = src_match.group(1)
                    if src_ip in ip_to_client:
                        client_id = ip_to_client[src_ip]
                if dst_match:
                    dst_ip = dst_match.group(1)
                    if not client_id and dst_ip in ip_to_client:
                        client_id = ip_to_client[dst_ip]

                spt_match = re.search(r'SPT=(\d+)', msg)
                dpt_match = re.search(r'DPT=(\d+)', msg)
                if spt_match:
                    src_port = spt_match.group(1)
                if dpt_match:
                    dst_port = dpt_match.group(1)

                proto_match = re.search(r'PROTO=(\S+)', msg)
                if proto_match:
                    protocol = proto_match.group(1)

                line_hash = hashlib.sha256(line.encode('utf-8', errors='ignore')).hexdigest()
                entries.append((ts, client_id, direction, protocol, src_ip, src_port, dst_ip, dst_port, line, line_hash))

            if entries:
                conn = get_db()
                c = conn.cursor()
                before = conn.total_changes
                c.executemany(
                    """
                    INSERT OR IGNORE INTO activity_log
                    (timestamp, client_id, direction, protocol, src_ip, src_port, dst_ip, dst_port, raw_line, line_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    entries
                )
                conn.commit()
                inserted = conn.total_changes - before
                conn.close()

                # Actively resolve new destination IPs that aren't in dns_cache
                if inserted > 0:
                    new_ips = list(set(e[6] for e in entries if e[6]))  # e[6] = dst_ip
                    if new_ips:
                        try:
                            conn = get_db()
                            c = conn.cursor()
                            placeholders = ','.join('?' * len(new_ips))
                            c.execute(
                                f"SELECT DISTINCT ip_address FROM dns_cache WHERE ip_address IN ({placeholders})",
                                new_ips
                            )
                            cached = set(row[0] for row in c.fetchall())
                            conn.close()
                            uncached = [ip for ip in new_ips if ip not in cached and not _is_private_ip(ip)]
                            if uncached:
                                threading.Thread(
                                    target=_resolve_ips_to_dns_cache,
                                    args=(uncached,),
                                    daemon=True
                                ).start()
                        except Exception:
                            pass

                elapsed_ms = int((time.monotonic() - start_time) * 1000)
                logger.info("Activity log ingestion: %s lines, %s inserted, %sms", len(entries), inserted, elapsed_ms)
        except Exception as exc:
            logger.debug(f"Activity log ingestion error: {exc}")
        finally:
            time.sleep(poll_interval)


# ----------------------------------------------------------------------------
# Activity Log Retention Cleanup
# ----------------------------------------------------------------------------
def _cleanup_activity_logs():
    retention_days = max(1, ACTIVITY_LOG_RETENTION_DAYS)
    logger.info("Activity log retention cleanup enabled (days=%s)", retention_days)

    while True:
        try:
            cutoff = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=retention_days)).strftime("%Y-%m-%d %H:%M:%S")
            conn = get_db()
            c = conn.cursor()

            c.execute("SELECT COUNT(*) FROM activity_log")
            total_before = c.fetchone()[0]

            c.execute("DELETE FROM activity_log WHERE timestamp < ?", (cutoff,))
            deleted_rows = c.rowcount

            c.execute("SELECT COUNT(*) FROM activity_log")
            total_after = c.fetchone()[0]

            c.execute(
                "INSERT INTO activity_log_metrics (last_cleanup_at, deleted_rows, remaining_rows) VALUES (CURRENT_TIMESTAMP, ?, ?)",
                (deleted_rows, total_after)
            )

            conn.commit()
            conn.close()

            logger.info(
                "Activity log cleanup: cutoff=%s deleted=%s remaining=%s (before=%s)",
                cutoff,
                deleted_rows,
                total_after,
                total_before,
            )
        except Exception as exc:
            logger.debug(f"Activity log cleanup error: {exc}")

        # Run once a day
        time.sleep(24 * 60 * 60)


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

# ----------------------------------------------------------------------------
# Periodic DNS Resolution for Unresolved IPs
# ----------------------------------------------------------------------------
def _resolve_unresolved_activity_ips():
    """Periodically resolve destination IPs in activity_log that aren't in dns_cache."""
    poll_interval = 60  # Run every 60 seconds
    logger.info("Unresolved IP resolver enabled (poll=%ss)", poll_interval)

    while True:
        try:
            conn = get_db()
            c = conn.cursor()

            # Find dst_ip values in activity_log that don't have dns_cache entries
            # Exclude private IPs since they won't have useful reverse DNS
            c.execute("""
                SELECT DISTINCT a.dst_ip
                FROM activity_log a
                LEFT JOIN dns_cache dc ON dc.ip_address = a.dst_ip
                WHERE dc.ip_address IS NULL
                AND a.dst_ip IS NOT NULL
                LIMIT 100
            """)

            rows = c.fetchall()
            conn.close()

            if rows:
                ips = [row[0] for row in rows]
                # Filter out private IPs
                public_ips = [ip for ip in ips if not _is_private_ip(ip)]

                if public_ips:
                    resolved = _resolve_ips_to_dns_cache(public_ips)
                    if resolved > 0:
                        logger.info("Resolved %s new IPs to domains", resolved)

        except Exception as exc:
            logger.debug(f"Unresolved IP resolver error: {exc}")

        time.sleep(poll_interval)


def _interface_operstate(iface: str) -> str:
    """Return 'up', 'down', or 'missing' for an interface."""
    try:
        with open(f"/sys/class/net/{iface}/operstate", "r") as f:
            state = f.read().strip()
        return "up" if state in ("up", "unknown") else "down"
    except (FileNotFoundError, PermissionError, OSError):
        return "missing"


# Module-level state shared by /health endpoint
_WATCHDOG_STATE: Dict[str, object] = {
    "iface": None,
    "iface_state": "unknown",
    "last_transition": None,
    "portal_rule_fixes": 0,
    "last_check": None,
}


def _ensure_portal_iptables_rules():
    """Make sure the portal's listener ports (80, 443) are ACCEPTed in INPUT.

    The WireGuard PostUp adds these rules, but if wg-quick@wg0 restarts or
    crashes, its PostDown hook removes them — which can leave the portal
    unreachable even while the FastAPI service is still running. This
    watchdog re-adds them whenever they are missing.
    """
    fixes = 0
    for port in (80, 443):
        try:
            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if check.returncode != 0:
                subprocess.run(
                    ["iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                fixes += 1
                logger.warning(f"Watchdog re-inserted missing INPUT ACCEPT rule for port {port}")
        except FileNotFoundError:
            # iptables binary not present (dev/test env) — nothing we can do
            return 0
        except Exception as e:
            logger.debug(f"Watchdog iptables check failed for port {port}: {e}")
    return fixes


def _watchdog_loop():
    """Monitors WireGuard interface state and re-asserts critical firewall rules.

    Runs every 30 seconds:
      1. Checks if wg0 operstate has changed (up <-> down). Logs transitions so
         the admin can correlate portal outages with interface flaps.
      2. Re-inserts INPUT ACCEPT rules for ports 80/443 if they were removed
         (e.g., by wg-quick PostDown), so the portal stays reachable even
         during WireGuard flaps.
      3. Updates shared watchdog state consumed by the /health endpoint.
    """
    iface = _ensure_wg_interface() or "wg0"
    _WATCHDOG_STATE["iface"] = iface
    poll_interval = 30
    last_state = None

    logger.info(f"Watchdog started (iface={iface}, poll={poll_interval}s)")

    while True:
        try:
            state = _interface_operstate(iface)
            _WATCHDOG_STATE["iface_state"] = state
            _WATCHDOG_STATE["last_check"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()

            if last_state is not None and state != last_state:
                logger.warning(f"Watchdog: {iface} transitioned {last_state} → {state}")
                _WATCHDOG_STATE["last_transition"] = {
                    "from": last_state, "to": state,
                    "at": _WATCHDOG_STATE["last_check"],
                }
            last_state = state

            # Always try to ensure portal firewall rules are in place
            fixes = _ensure_portal_iptables_rules()
            if fixes:
                _WATCHDOG_STATE["portal_rule_fixes"] = (
                    int(_WATCHDOG_STATE.get("portal_rule_fixes") or 0) + fixes
                )
        except Exception as exc:
            logger.error(f"Watchdog iteration error: {exc}")

        time.sleep(poll_interval)


def get_watchdog_state() -> dict:
    """Snapshot of watchdog state for /health endpoint consumption."""
    return dict(_WATCHDOG_STATE)


# ============================================================================
# Per-user agent allowlist enforcement
# ----------------------------------------------------------------------------
# Reconciliative iptables sync. Every interval we compute the desired
# rule set from the DB and overwrite the WS_AGENT_ACL chain. Behaviour:
#
#   1. For every *restricted* enrolled agent (is_restricted=1) with at
#      least one advertised CIDR: install a default-DROP rule in
#      WS_AGENT_ACL for traffic whose -d matches the CIDR.
#   2. Then prepend ACCEPT rules for each allowlisted (client_ipv4,
#      agent_cidr) pair so allowed clients short-circuit the DROP.
#   3. Unrestricted agents (is_restricted=0) get no rules — preserves
#      the legacy default-allow behaviour. Existing 2FA + ipset gating
#      still applies to those flows.
#
# The chain is JUMPed-to from FORWARD exactly once. We never duplicate
# the JUMP (idempotent ensure) and rebuild the chain by flush + re-add.
# ============================================================================

_AGENT_ACL_CHAIN = "WS_AGENT_ACL"
_AGENT_ACL_LOCK = threading.Lock()
_AGENT_ACL_STATE = {
    "last_sync_unix": 0,
    "last_rule_count": 0,
    "last_error": None,
    "missing_iptables": False,
}


def _has_iptables() -> bool:
    return shutil.which("iptables") is not None


def _iptables_run(args, check=False) -> subprocess.CompletedProcess:
    """Wrapper that returns CompletedProcess; never raises unless check=True."""
    return subprocess.run(
        ["iptables"] + args,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=check,
    )


def _ensure_agent_acl_chain():
    """Create WS_AGENT_ACL + the FORWARD JUMP if missing. Idempotent."""
    r = _iptables_run(["-n", "-L", _AGENT_ACL_CHAIN])
    if r.returncode != 0:
        _iptables_run(["-N", _AGENT_ACL_CHAIN])
    r = _iptables_run(["-C", "FORWARD", "-j", _AGENT_ACL_CHAIN])
    if r.returncode != 0:
        # INSERT at position 1 so the ACL fires before any FORWARD rule
        # could short-circuit the flow.
        _iptables_run(["-I", "FORWARD", "1", "-j", _AGENT_ACL_CHAIN])


def _ensure_forward_state_accept():
    """Idempotently ensure ESTABLISHED,RELATED traffic is ACCEPTed at the
    top of FORWARD.

    Without this, return packets for already-authorized 2FA flows fall
    through to the captive-portal sinkhole (the `-A WS_2FA_PORTAL -j DROP`
    appended by the wireshield.sh PostUp block). The 2FA gate rule
    `-A FORWARD -i wg0 -m set --match-set ws_2fa_allowed_v4 src -j ACCEPT`
    only matches when SOURCE is a 2FA-authed client — it does not match
    return traffic where source is a LAN host (e.g. 192.168.169.1) behind
    an agent peer, even when the destination IS a 2FA-authed client.

    Standard stateful-firewall idiom: NEW connections still pass through
    the 2FA gate; only return traffic for already-permitted flows is
    short-circuited via conntrack.
    """
    rule = ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]
    r = _iptables_run(["-C", "FORWARD"] + rule)
    if r.returncode == 0:
        return
    # Insert at position 1 so it runs before the audit LOG and any
    # subsequent chain jumps. -I FORWARD 1 pushes everything down by one.
    _iptables_run(["-I", "FORWARD", "1"] + rule)


def _flush_agent_acl_chain():
    _iptables_run(["-F", _AGENT_ACL_CHAIN])


def _build_acl_rules() -> List[List[str]]:
    """Compute the desired iptables -A rules for WS_AGENT_ACL from
    current DB state. Order matters: ACCEPTs first so an allowlisted
    client short-circuits before the per-CIDR DROP."""
    try:
        from app.core.agents import all_access_grants
    except Exception as e:
        logger.error(f"agent ACL: import failed: {e}")
        return []

    grants = all_access_grants()
    accepts: List[List[str]] = []
    drops: List[List[str]] = []
    seen_drop_cidrs: set = set()

    by_agent: Dict[int, Dict[str, Any]] = {}
    for g in grants:
        aid = g.get("agent_id")
        if aid is None:
            continue
        bucket = by_agent.setdefault(aid, {
            "is_restricted": g.get("is_restricted"),
            "advertised_cidrs": g.get("advertised_cidrs") or [],
            "clients": [],
        })
        if g.get("client_id") and g.get("client_ipv4"):
            bucket["clients"].append(g["client_ipv4"])

    for aid, bucket in by_agent.items():
        if not bucket["is_restricted"]:
            continue
        for cidr in bucket["advertised_cidrs"]:
            if not cidr:
                continue
            for client_ipv4 in bucket["clients"]:
                accepts.append(
                    ["-A", _AGENT_ACL_CHAIN,
                     "-s", client_ipv4, "-d", cidr,
                     "-j", "ACCEPT"]
                )
            if cidr not in seen_drop_cidrs:
                seen_drop_cidrs.add(cidr)
                drops.append(
                    ["-A", _AGENT_ACL_CHAIN, "-d", cidr, "-j", "DROP"]
                )

    return accepts + drops


def _sync_agent_acl_once():
    """Run one iptables sync pass."""
    with _AGENT_ACL_LOCK:
        if not _has_iptables():
            _AGENT_ACL_STATE["missing_iptables"] = True
            return

        try:
            _ensure_forward_state_accept()
            _ensure_agent_acl_chain()
            _flush_agent_acl_chain()
            rules = _build_acl_rules()
            for r in rules:
                _iptables_run(r)
            _AGENT_ACL_STATE["last_rule_count"] = len(rules)
            _AGENT_ACL_STATE["last_error"] = None
            _AGENT_ACL_STATE["last_sync_unix"] = int(time.time())
            logger.debug(f"agent ACL: synced {len(rules)} rules")
        except Exception as e:
            _AGENT_ACL_STATE["last_error"] = str(e)
            logger.error(f"agent ACL sync failed: {e}")


def _sync_agent_acl_loop():
    """Background reconciliation loop. 30s cadence — matches existing
    ipset sync. time.sleep before the first pass so a crash-loop in
    the sync can't thrash iptables."""
    interval = 30
    while True:
        time.sleep(interval)
        try:
            _sync_agent_acl_once()
        except Exception as e:
            logger.error(f"agent ACL loop unexpected error: {e}")


def get_agent_acl_state() -> dict:
    """Snapshot used by /health for observability."""
    return dict(_AGENT_ACL_STATE)


def trigger_agent_acl_sync():
    """Synchronous on-demand sync. Called from admin endpoints so a
    grant is reflected in iptables immediately rather than waiting for
    the next 30s tick."""
    threading.Thread(target=_sync_agent_acl_once, daemon=True).start()


# ============================================================================
# Per-user firewall enforcement (policies + block kill-switch)
# ----------------------------------------------------------------------------
# Same reconciliative flush-and-rebuild approach as WS_AGENT_ACL above, but
# driven by app.core.firewall.all_firewall_rules() (firewall_policies /
# firewall_rules / user_firewall) instead of agent_user_access. The two
# subsystems are intentionally independent — this one never reads or writes
# agent_user_access, and WS_AGENT_ACL is never modified here.
#
# Two chains, two priority levels:
#   - WS_USER_BLOCK: the block kill-switch. Always pinned at literal
#     FORWARD position 1 — above WS_AGENT_ACL, above the ESTABLISHED,RELATED
#     accept, above everything. A block must win unconditionally, including
#     over an agent-CIDR grant the user still holds (WS_AGENT_ACL's ACCEPT
#     is terminal and would otherwise let that traffic through before it
#     ever reached a lower chain).
#   - WS_USER_FW: firewall-policy rules. Positioned at
#     max(WS_AGENT_ACL position, ESTABLISHED,RELATED accept position) + 1 —
#     below WS_AGENT_ACL (so an agent grant still overrides a policy,
#     matching the product decision to keep the two systems separate rather
#     than unifying them) AND below the ESTABLISHED,RELATED accept (so
#     return traffic for an already-permitted flow isn't caught by a
#     default-deny policy's tail, which only matches on -s/-d, not the
#     original --dport rule).
#
# Full evaluation order: WS_USER_BLOCK, then [WS_AGENT_ACL / ESTABLISHED —
# relative order between these two is whichever was created first, doesn't
# matter functionally], then WS_USER_FW, then the existing ws_2fa_allowed
# ipset ACCEPT.
#
# Both _ensure_user_block_chain() and _ensure_user_fw_chain() recompute and
# reassert their required position on EVERY sync pass, not just at first
# creation. This is what makes the ordering self-correcting rather than a
# one-time race: _ensure_agent_acl_chain() (pre-existing, untouched, and its
# own 30s loop independently scheduled from this one) can insert at FORWARD
# position 1 the first time it runs, which could transiently displace either
# of these chains — but the next pass of this loop (within 30s) notices and
# reclaims the correct position, so a bad ordering never persists
# indefinitely the way a "only fix if the jump is completely missing" check
# would.
# ============================================================================

_USER_FW_CHAIN = "WS_USER_FW"
_USER_BLOCK_CHAIN = "WS_USER_BLOCK"
_USER_FW_LOCK = threading.Lock()
_USER_FW_STATE = {
    "last_sync_unix": 0,
    "last_rule_count": 0,
    "last_error": None,
    "missing_iptables": False,
}

# The exact rule-spec _ensure_forward_state_accept() installs — reused here
# so WS_USER_FW can locate it as a positioning anchor without duplicating
# the literal args in two places.
_ESTABLISHED_RULE_SPEC = ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]


def _forward_rule_position(contains: List[str]) -> Optional[int]:
    """Return the 1-based FORWARD position of the first rule whose full
    rule-spec contains every token in `contains`, or None if not found."""
    r = _iptables_run(["-S", "FORWARD"])
    if r.returncode != 0:
        return None
    pos = 0
    for line in r.stdout.decode(errors="replace").splitlines():
        if line.startswith("-P "):
            continue
        pos += 1
        if all(tok in line for tok in contains):
            return pos
    return None


def _ensure_user_block_chain():
    """Create WS_USER_BLOCK if missing, and — on EVERY call, not just at
    first creation — reassert it at literal FORWARD position 1: above
    WS_AGENT_ACL, above the ESTABLISHED,RELATED accept, above everything.
    A blocked user must win over every other rule unconditionally
    (including an agent-CIDR grant they still hold — WS_AGENT_ACL's
    terminal ACCEPT would otherwise let that traffic through before it
    ever reached WS_USER_FW), which is why this is a separate top-priority
    chain rather than rules inside WS_USER_FW.

    Re-checking every pass (rather than only "insert if the jump is
    entirely missing") makes this self-healing: if the independently
    scheduled agent-ACL loop inserts something above WS_USER_BLOCK between
    passes, the next pass (within 30s) reclaims position 1 rather than
    leaving the inversion in place indefinitely.
    """
    r = _iptables_run(["-n", "-L", _USER_BLOCK_CHAIN])
    if r.returncode != 0:
        _iptables_run(["-N", _USER_BLOCK_CHAIN])

    pos = _forward_rule_position(["-j", _USER_BLOCK_CHAIN])
    if pos == 1:
        return  # already exactly where it needs to be — no-op
    if pos is not None:
        _iptables_run(["-D", "FORWARD", "-j", _USER_BLOCK_CHAIN])
    _iptables_run(["-I", "FORWARD", "1", "-j", _USER_BLOCK_CHAIN])


def _ensure_user_fw_chain():
    """Create WS_USER_FW if missing, and — on EVERY call, not just at
    first creation — reassert its position at
    max(WS_AGENT_ACL position, ESTABLISHED,RELATED accept position) + 1.

    Below WS_AGENT_ACL: so an agent-CIDR grant keeps taking priority over
    firewall policies (matches the product decision to keep the two
    subsystems independent). Below the ESTABLISHED,RELATED accept too —
    not just below WS_AGENT_ACL — because that accept rule can itself end
    up above or below WS_AGENT_ACL depending on which was created first;
    positioning WS_USER_FW relative to only one of the two anchors can
    still leave it above the other, and if it ends up above the
    ESTABLISHED accept, a default-deny policy's return traffic (the reply
    packet only matches on -s/-d, never the original --dport rule) would
    hit the default-deny tail before ever reaching the ESTABLISHED accept,
    silently breaking that user's connections.

    Re-checking every pass makes this self-healing against a startup race
    with the independently-scheduled agent-ACL loop: a transient
    mis-ordering corrects itself within one reconcile interval instead of
    persisting until a manual chain rebuild.
    """
    r = _iptables_run(["-n", "-L", _USER_FW_CHAIN])
    if r.returncode != 0:
        _iptables_run(["-N", _USER_FW_CHAIN])

    _ensure_agent_acl_chain()  # read-only from here — guarantees a position to anchor to, doesn't touch its rules/behavior

    def _desired_pos() -> int:
        agent_acl_pos = _forward_rule_position(["-j", _AGENT_ACL_CHAIN])
        established_pos = _forward_rule_position(_ESTABLISHED_RULE_SPEC)
        if agent_acl_pos is None and established_pos is None:
            # Couldn't locate either anchor (transient iptables error) —
            # fall back to right after WS_USER_BLOCK. Never position 1:
            # a lookup hiccup must not let WS_USER_FW outrank the
            # kill-switch chain.
            logger.warning("user firewall: could not locate WS_AGENT_ACL or ESTABLISHED anchor; falling back to FORWARD position 2")
            return 2
        return max(agent_acl_pos or 0, established_pos or 0, 1) + 1

    current_pos = _forward_rule_position(["-j", _USER_FW_CHAIN])
    desired_pos = _desired_pos()
    if current_pos == desired_pos:
        return  # already correctly positioned — no-op

    if current_pos is not None:
        _iptables_run(["-D", "FORWARD", "-j", _USER_FW_CHAIN])
        # Deleting a mis-positioned WS_USER_FW (e.g. one that ended up
        # above one of the anchors) shifts indices — recompute before
        # inserting.
        desired_pos = _desired_pos()
    _iptables_run(["-I", "FORWARD", str(desired_pos), "-j", _USER_FW_CHAIN])


def _flush_user_fw_chain():
    _iptables_run(["-F", _USER_FW_CHAIN])


def _flush_user_block_chain():
    _iptables_run(["-F", _USER_BLOCK_CHAIN])


def _build_user_block_rules() -> List[List[str]]:
    """Compute the desired iptables -A rules for WS_USER_BLOCK: a plain
    DROP for a blocked user's tunnel IP in both directions. Pure function
    — no side effects. (Session/ipset revocation for a newly-blocked user
    happens once, synchronously, in firewall.set_user_firewall() at the
    moment of the state transition — not here, since this runs on every
    30s reconcile pass and would otherwise re-revoke an already-blocked
    user indefinitely.)
    """
    try:
        from app.core.firewall import all_firewall_rules
    except Exception as e:
        logger.error(f"user firewall: import failed: {e}")
        return []

    rules: List[List[str]] = []
    for entry in all_firewall_rules():
        if not entry.get("blocked"):
            continue
        ipv4 = entry.get("ipv4")
        if ipv4:
            rules.append(["-A", _USER_BLOCK_CHAIN, "-s", ipv4, "-j", "DROP"])
            rules.append(["-A", _USER_BLOCK_CHAIN, "-d", ipv4, "-j", "DROP"])
    return rules


def _build_user_fw_rules() -> List[List[str]]:
    """Compute the desired iptables -A rules for WS_USER_FW from current
    DB state (app.core.firewall.all_firewall_rules()). IPv4 only for now,
    matching the existing WS_AGENT_ACL scope.

    Blocked users are skipped entirely here — WS_USER_BLOCK (see
    _build_user_block_rules) owns their enforcement, since it must take
    priority over WS_AGENT_ACL and this chain sits below it. Non-blocked,
    policy-governed users get one rule per firewall_rules row (override
    rules first, then their policy's rules — all_firewall_rules() already
    returns them in that order) followed by a default-deny tail only when
    the assigned policy's default_action is 'deny'; a default_action of
    'allow' needs no tail rule since falling through WS_USER_FW reaches
    the existing 2FA ipset ACCEPT for an already-authenticated client.
    """
    try:
        from app.core.firewall import all_firewall_rules
    except Exception as e:
        logger.error(f"user firewall: import failed: {e}")
        return []

    rules: List[List[str]] = []
    for entry in all_firewall_rules():
        if entry.get("blocked"):
            continue  # handled by WS_USER_BLOCK instead

        ipv4 = entry.get("ipv4")
        if not ipv4:
            continue  # no known tunnel IP yet — nothing to enforce against

        for rule in entry.get("rules", []):
            target = "ACCEPT" if rule["action"] == "allow" else "DROP"
            protocol = rule.get("protocol") or "all"
            remote_cidr = rule.get("remote_cidr")

            if rule["direction"] == "outbound":
                args = ["-A", _USER_FW_CHAIN, "-s", ipv4]
                if remote_cidr:
                    args += ["-d", remote_cidr]
            else:
                args = ["-A", _USER_FW_CHAIN, "-d", ipv4]
                if remote_cidr:
                    args += ["-s", remote_cidr]

            if protocol != "all":
                args += ["-p", protocol]
                port_start, port_end = rule.get("port_start"), rule.get("port_end")
                if port_start is not None:
                    port_arg = str(port_start) if port_start == port_end else f"{port_start}:{port_end}"
                    args += ["--dport", port_arg]

            args += ["-j", target]
            rules.append(args)

        if entry.get("policy_id") is not None and entry.get("policy_default_action") == "deny":
            rules.append(["-A", _USER_FW_CHAIN, "-s", ipv4, "-j", "DROP"])
            rules.append(["-A", _USER_FW_CHAIN, "-d", ipv4, "-j", "DROP"])

    return rules


def _sync_user_fw_once():
    """Run one iptables sync pass for the per-user firewall."""
    with _USER_FW_LOCK:
        if not _has_iptables():
            _USER_FW_STATE["missing_iptables"] = True
            return

        try:
            _ensure_forward_state_accept()
            # Reclaim WS_USER_BLOCK's top-of-FORWARD position first — it
            # must be pinned before computing where WS_USER_FW goes, since
            # reclaiming it can shift every other rule's index.
            _ensure_user_block_chain()
            _ensure_user_fw_chain()

            _flush_user_block_chain()
            block_rules = _build_user_block_rules()
            for r in block_rules:
                _iptables_run(r)

            _flush_user_fw_chain()
            fw_rules = _build_user_fw_rules()
            for r in fw_rules:
                _iptables_run(r)

            _USER_FW_STATE["last_rule_count"] = len(fw_rules) + len(block_rules)
            _USER_FW_STATE["last_error"] = None
            _USER_FW_STATE["last_sync_unix"] = int(time.time())
            logger.debug(f"user firewall: synced {len(fw_rules)} rules ({len(block_rules)} block)")
        except Exception as e:
            _USER_FW_STATE["last_error"] = str(e)
            logger.error(f"user firewall sync failed: {e}")


def _sync_user_fw_loop():
    """Background reconciliation loop. Same 30s cadence as the agent ACL
    sync; sleeps before the first pass so a crash-loop can't thrash
    iptables."""
    interval = 30
    while True:
        time.sleep(interval)
        try:
            _sync_user_fw_once()
        except Exception as e:
            logger.error(f"user firewall loop unexpected error: {e}")


def get_user_fw_state() -> dict:
    """Snapshot used by /health for observability."""
    return dict(_USER_FW_STATE)


def trigger_user_fw_sync():
    """Synchronous on-demand sync. Called from admin endpoints so a
    policy/assignment change is reflected in iptables immediately rather
    than waiting for the next 30s tick."""
    threading.Thread(target=_sync_user_fw_once, daemon=True).start()


def _agent_housekeeping_loop():
    """Runs once per hour: purges expired/used enrollment tokens and prunes
    agent_heartbeats rows older than the configured retention window.

    Keeps both tables bounded so /health stats queries stay fast as the
    fleet grows."""
    from app.core.config import AGENT_HEARTBEAT_RETENTION_HOURS

    interval = 3600  # 1 hour — cleanup is not latency-sensitive
    while True:
        try:
            # Import here so tests can init without importing agents first
            from app.core.agents import purge_expired_tokens
            purged = purge_expired_tokens()
            if purged:
                logger.info(f"Agent housekeeping: purged {purged} stale enrollment tokens")

            conn = get_db()
            try:
                c = conn.cursor()
                c.execute(
                    "DELETE FROM agent_heartbeats WHERE received_at < datetime('now', ?)",
                    (f"-{AGENT_HEARTBEAT_RETENTION_HOURS} hours",),
                )
                dropped = c.rowcount
                conn.commit()
            finally:
                conn.close()
            if dropped:
                logger.info(f"Agent housekeeping: pruned {dropped} old heartbeat rows")
        except Exception as exc:
            logger.error(f"Agent housekeeping error: {exc}")

        time.sleep(interval)


def _wg_peer_reconcile_loop():
    """Every 60 s: compare enrolled agents in DB against running wg0 peers.
    Re-adds any missing peers and rewrites stale AllowedIPs, then calls
    wg_syncconf. This heals drift caused by:
      - wg_syncconf failing silently at enrollment time
      - wg0 restarted independently of the console server
      - CIDR update whose syncconf failed
    The startup lifespan handler runs one pass before this loop fires,
    so the first sleep here gives that pass a head-start."""
    interval = 60
    time.sleep(interval)
    while True:
        try:
            from app.core.agents import reconcile_wg_peers
            synced = reconcile_wg_peers()
            if synced:
                logger.info(f"WG peer reconcile loop: healed {synced} peer(s)")
        except Exception as exc:
            logger.error(f"WG peer reconcile loop error: {exc}")
        time.sleep(interval)


def start_background_tasks():
    threading.Thread(target=_sync_ipsets_from_sessions, daemon=True).start()
    threading.Thread(target=_monitor_wireguard_sessions, daemon=True).start()
    threading.Thread(target=_ingest_activity_logs, daemon=True).start()
    threading.Thread(target=_cleanup_activity_logs, daemon=True).start()
    threading.Thread(target=_resolve_unresolved_activity_ips, daemon=True).start()
    threading.Thread(target=_start_http_redirector_ipv4, daemon=True).start()
    threading.Thread(target=_start_http_redirector_ipv6, daemon=True).start()
    threading.Thread(target=_watchdog_loop, daemon=True).start()
    threading.Thread(target=_agent_housekeeping_loop, daemon=True).start()
    threading.Thread(target=_sync_agent_acl_loop, daemon=True).start()
    threading.Thread(target=_sync_user_fw_loop, daemon=True).start()
    threading.Thread(target=_wg_peer_reconcile_loop, daemon=True).start()
