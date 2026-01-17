import math
import subprocess
import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Request, Depends, HTTPException
from datetime import datetime
from fastapi.responses import HTMLResponse

from app.core.database import get_db
from app.core.security import audit_log
from app.core.config import LOG_LEVEL
from app.templates import get_access_denied_html, get_console_html

logger = logging.getLogger(__name__)

router = APIRouter()

# ----------------------------------------------------------------------------
# Console Access (restricted to admins)
# ----------------------------------------------------------------------------
async def _check_console_access(request: Request) -> str:
    """Dependency: verify client has console_access=1."""
    ip_address = request.client.host if request and request.client else "unknown"
    client_id = None
    
    # Try discovery by IP
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT client_id, console_access FROM users WHERE wg_ipv4=? OR wg_ipv6=?", (ip_address, ip_address))
        row = c.fetchone()
        conn.close()
        
        if row:
            client_id = row[0]
            has_access = row[1]
            if has_access:
                return client_id
    except Exception:
        pass
        
    audit_log(client_id, "CONSOLE_ACCESS", "denied", ip_address)
    raise HTTPException(status_code=403, detail="Console access denied")

@router.get("/console", response_class=HTMLResponse, tags=["console"])
async def console_dashboard(request: Request):
    """Admin console dashboard."""
    try:
        client_id = await _check_console_access(request)
    except HTTPException:
        return get_access_denied_html(request)
        
    client_host = request.client.host if request and request.client else "unknown"
    audit_log(client_id, "CONSOLE_ACCESS", "granted", client_host)
    
    return get_console_html(request)

@router.get("/api/console/users")
async def get_users(
    page: int = 1, 
    limit: int = 20, 
    search: Optional[str] = None, 
    client_id: str = Depends(_check_console_access)
):
    try:
        offset = (page - 1) * limit
        conn = get_db()
        c = conn.cursor()
        
        # Subquery to get active session start time
        query = """
            SELECT u.*, 
            (SELECT MAX(created_at) FROM sessions s WHERE s.client_id = u.client_id) as session_start
            FROM users u
        """
        params = []
        if search:
            query += " WHERE u.client_id LIKE ?"
            params.append(f"%{search}%")
            
        query += " ORDER BY u.id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        c.execute(query, tuple(params))
        rows = []
        for row in c.fetchall():
            item = dict(row)
            # Calculate active duration
            duration = "-"
            if item.get('session_start'):
                try:
                    start = datetime.strptime(item['session_start'], "%Y-%m-%d %H:%M:%S")
                    diff = datetime.utcnow() - start
                    total_seconds = int(diff.total_seconds())
                    if total_seconds > 0:
                        hours = total_seconds // 3600
                        minutes = (total_seconds % 3600) // 60
                        duration = f"{hours}h {minutes}m"
                except Exception:
                    pass
            item['active_duration'] = duration
            rows.append(item)
        
        # Count total
        count_query = "SELECT COUNT(*) FROM users"
        if search:
            count_query += " WHERE client_id LIKE ?"
            c.execute(count_query, (f"%{search}%",))
        else:
            c.execute(count_query)
            
        total = c.fetchone()[0]
        conn.close()
        
        return {
            "users": rows,
            "page": page,
            "pages": math.ceil(total / limit) if limit > 0 else 1,
            "total": total
        }
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return {"users": [], "page": 1, "pages": 0, "total": 0}

@router.get("/api/console/audit-logs")
async def get_audit_logs(
    page: int = 1,
    limit: int = 50,
    search: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    client_filter: Optional[str] = None,
    client_id: str = Depends(_check_console_access)
):
    try:
        offset = (page - 1) * limit
        conn = get_db()
        c = conn.cursor()
        
        query = "SELECT * FROM audit_log"
        conditions = []
        params = []
        
        if search:
            conditions.append("(client_id LIKE ? OR action LIKE ? OR status LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        
        if client_filter:
            conditions.append("client_id = ?")
            params.append(client_filter)
        
        if start_date:
            conditions.append("timestamp >= ?")
            params.append(f"{start_date} 00:00:00")
        
        if end_date:
            conditions.append("timestamp <= ?")
            params.append(f"{end_date} 23:59:59")
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        c.execute(query, tuple(params))
        rows = [dict(row) for row in c.fetchall()]
        
        # Count total
        count_query = "SELECT COUNT(*) FROM audit_log"
        if conditions:
            count_query += " WHERE " + " AND ".join(conditions)
            c.execute(count_query, tuple(params[:-2]))  # Exclude LIMIT/OFFSET params
        else:
            c.execute(count_query)
            
        total = c.fetchone()[0]
        conn.close()
        
        return {
            "logs": rows,
            "page": page,
            "pages": math.ceil(total / limit) if limit > 0 else 1,
            "total": total
        }
    except Exception as e:
        logger.error(f"Error fetching audit logs: {e}")
        return {"logs": [], "page": 1, "pages": 0, "total": 0}

@router.get("/api/console/activity-logs")
async def get_activity_logs(
    page: int = 1,
    limit: int = 50,
    search: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    client_filter: Optional[str] = None,
    domain_filter: Optional[str] = None,
    client_id: str = Depends(_check_console_access)
):
    """Fetch WireGuard/iptables kernel logs via journalctl with enhanced parsing."""
    import re
    import socket
    import asyncio
    import ipaddress
    from urllib.parse import urlsplit
    from importlib import import_module
    from datetime import datetime

    extractor = None
    extractor_checked = False

    def _extract_display_domain(value: str) -> str:
        nonlocal extractor, extractor_checked
        if not value:
            return "-"
        raw = str(value).strip()
        if not raw or raw == "-":
            return "-"

        host = raw
        try:
            if "://" in raw:
                parsed = urlsplit(raw)
                host = parsed.hostname or raw
            else:
                host = raw.split("/")[0].split("?")[0].split("#")[0]
                if "@" in host:
                    host = host.split("@", 1)[1]
                if host.startswith("[") and "]" in host:
                    host = host[1:host.index("]")]
                elif ":" in host:
                    host = host.split(":", 1)[0]
        except Exception:
            host = raw

        host = host.strip().lower().rstrip(".")
        if not host:
            return "-"

        try:
            ipaddress.ip_address(host)
            return host
        except Exception:
            pass

        try:
            if not extractor_checked:
                extractor_checked = True
                try:
                    tldextract = import_module("tldextract")
                    extractor = tldextract.TLDExtract(suffix_list_urls=None)
                except Exception:
                    extractor = None
            if extractor:
                extracted = extractor(host)
                if extracted.registered_domain:
                    return extracted.registered_domain
        except Exception:
            pass

        if host.startswith("www.") and len(host) > 4:
            return host[4:]

        return host
    
    # Build journalctl command
    cmd = ["journalctl", "-k", "-n", "5000", "--output=short-iso", "--no-pager"]
    
    # Add date filters to journalctl if provided
    if start_date:
        cmd.extend(["--since", f"{start_date} 00:00:00"])
    if end_date:
        cmd.extend(["--until", f"{end_date} 23:59:59"])
    
    if search:
        # Improved search: grep for term OR any IP associated with term
        search_terms = [search]
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT ip_address FROM dns_cache WHERE domain LIKE ?", (f"%{search}%",))
            ips = [r[0] for r in c.fetchall()]
            conn.close()
            search_terms.extend(ips)
        except Exception as e:
            logger.error(f"Search cache lookup failed: {e}")
            
        # Join with OR operator for pcre2 grep
        grep_pattern = "|".join(search_terms)
        cmd.extend(["--grep", grep_pattern])
        
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        lines = proc.stdout.strip().splitlines()
        
        # Filter for WireGuard/WS-Audit related logs
        wg_lines = [l for l in lines if "wireguard:" in l or "WS-Audit" in l or "wg" in l.lower()]
        wg_lines.reverse()  # Newest first
        
        # Load client IP mapping for identification
        ip_to_client = {}
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT client_id, wg_ipv4, wg_ipv6 FROM users")
            for row in c.fetchall():
                if row[1]: ip_to_client[row[1]] = row[0]
                if row[2]: ip_to_client[row[2]] = row[0]
            conn.close()
        except Exception:
            pass
        
        # Parse logs into structured format
        structured = []
        for line in wg_lines:
            # Parse timestamp: 2023-10-20T10:00:00+00:00 hostname kernel: ...
            parts = line.split(" ", 3)
            ts_raw = parts[0] if parts else ""
            msg = parts[3] if len(parts) > 3 else line
            
            # Convert ISO timestamp to readable format (YYYY-MM-DD HH:MM:SS)
            ts = ts_raw
            try:
                if 'T' in ts_raw:
                    dt = datetime.fromisoformat(ts_raw.replace('Z', '+00:00'))
                    ts = dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass
            
            # Extract fields from iptables/nftables log format
            # Example: [WS-Audit] IN=wg0 OUT=eth0 MAC=... SRC=10.66.66.2 DST=1.1.1.1 ...
            entry = {
                "timestamp": ts,
                "client_id": None,
                "direction": None,
                "protocol": None,
                "src_ip": None,
                "src_port": None,
                "dst_ip": None,
                "dst_port": None
            }
            
            # Parse IN/OUT
            in_match = re.search(r'IN=(\S*)', msg)
            out_match = re.search(r'OUT=(\S*)', msg)
            if in_match and in_match.group(1):
                entry["direction"] = "IN"
            elif out_match and out_match.group(1):
                entry["direction"] = "OUT"
            
            # Parse SRC/DST
            src_match = re.search(r'SRC=(\S+)', msg)
            dst_match = re.search(r'DST=(\S+)', msg)
            if src_match:
                entry["src_ip"] = src_match.group(1)
                # Map to client
                if entry["src_ip"] in ip_to_client:
                    entry["client_id"] = ip_to_client[entry["src_ip"]]
            if dst_match:
                entry["dst_ip"] = dst_match.group(1)
                # Also check dst for client
                if not entry["client_id"] and entry["dst_ip"] in ip_to_client:
                    entry["client_id"] = ip_to_client[entry["dst_ip"]]
            
            # Parse ports
            spt_match = re.search(r'SPT=(\d+)', msg)
            dpt_match = re.search(r'DPT=(\d+)', msg)
            if spt_match: entry["src_port"] = spt_match.group(1)
            if dpt_match: entry["dst_port"] = dpt_match.group(1)
            
            # Parse protocol
            proto_match = re.search(r'PROTO=(\S+)', msg)
            if proto_match: entry["protocol"] = proto_match.group(1)
            
            # Apply client filter
            if client_filter and entry["client_id"] != client_filter:
                continue

            # Apply domain filter
            if domain_filter:
                try:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute("SELECT 1 FROM dns_cache WHERE ip_address = ? AND domain LIKE ?", (entry["dst_ip"], f"%{domain_filter}%"))
                    match = c.fetchone()
                    conn.close()
                    if not match:
                        continue
                except Exception:
                   pass

            structured.append(entry)
        
        # Pagination
        total = len(structured)
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        page_items = structured[start_idx:end_idx]

        # Resolve domains for visible items (async)
        async def resolve_domain(item):
            if item['direction'] == 'IN' and item['dst_ip']:
                try:
                    # 1. Try DNS Cache from Sniffer
                    try:
                        conn_cache = get_db()
                        cc = conn_cache.cursor()
                        cc.execute("SELECT domain FROM dns_cache WHERE ip_address = ?", (item['dst_ip'],))
                        row = cc.fetchone()
                        conn_cache.close()
                        if row and row[0]:
                            raw_domain = row[0]
                            item['dst_domain_raw'] = raw_domain
                            item['dst_domain'] = _extract_display_domain(raw_domain)
                            return item
                    except Exception:
                        pass
                        
                    # 2. Fallback to Reverse DNS
                    loop = asyncio.get_running_loop()
                    # Run blocking socket call in executor
                    domain_info = await loop.run_in_executor(None, socket.gethostbyaddr, item['dst_ip'])
                    raw_domain = domain_info[0]
                    item['dst_domain_raw'] = raw_domain
                    item['dst_domain'] = _extract_display_domain(raw_domain)
                    
                    # Cache the result for future filtering
                    try:
                        conn_cache = get_db()
                        cc = conn_cache.cursor()
                        cc.execute("INSERT OR IGNORE INTO dns_cache (ip_address, domain) VALUES (?, ?)", (item['dst_ip'], raw_domain))
                        conn_cache.commit()
                        conn_cache.close()
                    except Exception:
                        pass
                except Exception:
                    item['dst_domain'] = "-"
            else:
                item['dst_domain'] = "-"
            return item

        # Run lookups concurrently
        if page_items:
            page_items = await asyncio.gather(*[resolve_domain(item) for item in page_items])
        else:
            page_items = []
            
        return {
            "logs": page_items,
            "page": page,
            "pages": math.ceil(total / limit) if limit > 0 else 1,
            "total": total
        }
        
    except Exception as e:
        logger.error(f"Failed to fetch logs: {e}")
        return {"logs": [], "page": 1, "pages": 0, "total": 0}

@router.get("/api/console/dashboard-stats")
async def get_dashboard_stats(client_id: str = Depends(_check_console_access)):
    """Get dashboard statistics for the console."""
    from datetime import datetime, timedelta
    
    try:
        conn = get_db()
        c = conn.cursor()
        
        # --- User Statistics ---
        c.execute("SELECT COUNT(*) FROM users")
        total_users = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM users WHERE enabled = 1")
        active_users = c.fetchone()[0]
        
        # --- Session Statistics ---
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("SELECT COUNT(*) FROM sessions WHERE expires_at > ?", (now,))
        active_sessions = c.fetchone()[0]
        
        # --- 2FA Statistics (Last 24 hours) ---
        yesterday = (datetime.utcnow() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
        
        c.execute("""
            SELECT COUNT(*) FROM audit_log 
            WHERE action = 'TOTP_VERIFY' AND status = 'success' AND timestamp >= ?
        """, (yesterday,))
        successful_2fa = c.fetchone()[0]
        
        c.execute("""
            SELECT COUNT(*) FROM audit_log 
            WHERE action = 'TOTP_VERIFY' AND status = 'failed' AND timestamp >= ?
        """, (yesterday,))
        failed_2fa = c.fetchone()[0]
        
        # --- Security Alerts (Failed attempts in last 24h) ---
        c.execute("""
            SELECT COUNT(*) FROM audit_log 
            WHERE status IN ('failed', 'denied') AND timestamp >= ?
        """, (yesterday,))
        failed_attempts_24h = c.fetchone()[0]
        
        conn.close()
        
        return {
            "total_users": total_users,
            "active_sessions": active_sessions,
            "failed_attempts_24h": failed_attempts_24h,
            "bandwidth_24h": 0,  # Placeholder
            "new_users_24h": 0   # Placeholder
        }
    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {e}")
        return {
            "total_users": 0,
            "active_sessions": 0,
            "failed_attempts_24h": 0,
            "bandwidth_24h": 0,
            "new_users_24h": 0
        }

@router.get("/api/console/bandwidth-usage")
async def get_bandwidth_usage(days: int = 30, client_id: str = Depends(_check_console_access)):
    """Fetch daily bandwidth usage (RX+TX) per client for the last N days."""
    try:
        conn = get_db()
        c = conn.cursor()
        # Fetch records for last 'days' days
        c.execute(f"SELECT scan_date, client_id, rx_bytes, tx_bytes FROM bandwidth_usage WHERE scan_date >= date('now', '-{days} days') ORDER BY scan_date ASC")
        rows = [dict(row) for row in c.fetchall()]
        conn.close()

        # Structure: { labels: [d1, d2], upload: [...], download: [...] }
        data_map = {} # date -> { upload: total, download: total }
        dates = set()

        for r in rows:
            date_str = r['scan_date']
            # Convert bytes to MB
            upload_mb = (r['tx_bytes'] or 0) / (1024**2)
            download_mb = (r['rx_bytes'] or 0) / (1024**2)
            
            if date_str not in data_map: 
                data_map[date_str] = {"upload": 0, "download": 0}
            
            data_map[date_str]["upload"] += upload_mb
            data_map[date_str]["download"] += download_mb
            dates.add(date_str)
        
        sorted_dates = sorted(list(dates))
        upload_data = []
        download_data = []
        
        for d in sorted_dates:
            upload_data.append(data_map.get(d, {}).get("upload", 0))
            download_data.append(data_map.get(d, {}).get("download", 0))
            
        return {
            'labels': sorted_dates, 
            'upload': upload_data,
            'download': download_data
        }
    except Exception as e:
        logger.error(f"Bandwidth API error: {e}")
        return {'labels': [], 'upload': [], 'download': []}

@router.get("/api/console/dashboard-charts")
async def get_dashboard_charts(client_id: str = Depends(_check_console_access)):
    """Get chart data for the dashboard."""
    import re
    from datetime import datetime, timedelta
    from collections import defaultdict
    
    try:
        conn = get_db()
        c = conn.cursor()
        
        # --- 7-Day Activity Trend ---
        activity_trend = []
        for i in range(6, -1, -1):
            date = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
            c.execute("""
                SELECT COUNT(*) FROM audit_log 
                WHERE timestamp LIKE ?
            """, (f"{date}%",))
            count = c.fetchone()[0]
            activity_trend.append({
                "hour": (datetime.utcnow() - timedelta(days=i)).strftime("%a"),
                "count": count
            })
        
        # --- Action Distribution ---
        c.execute("""
            SELECT action, COUNT(*) as count FROM audit_log 
            GROUP BY action ORDER BY count DESC LIMIT 6
        """)
        actions = [{"action": row[0], "count": row[1]} for row in c.fetchall()]
        
        # --- Recent Security Events (last 8) ---
        c.execute("""
            SELECT client_id, action, status, ip_address, timestamp 
            FROM audit_log ORDER BY id DESC LIMIT 8
        """)
        recent_events = [{
            "client_id": row[0] or "System",
            "action": row[1],
            "outcome": row[2],
            "ip_address": row[3],
            "timestamp": row[4]
        } for row in c.fetchall()]
        
        conn.close()
        
        return {
            "activity_trend": activity_trend,
            "action_distribution": actions,
            "recent_events": recent_events
        }
    except Exception as e:
        logger.error(f"Error fetching dashboard charts: {e}")
        return {
            "activity_trend": [],
            "action_distribution": [],
            "recent_events": []
        }