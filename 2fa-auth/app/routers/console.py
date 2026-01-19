import math
import subprocess
import logging
import time
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Request, Depends, HTTPException
from datetime import datetime
from fastapi.responses import HTMLResponse

from app.core.database import get_db
from app.core.security import audit_log
from app.core.config import LOG_LEVEL, ACTIVITY_LOG_RETENTION_DAYS
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
        
        # Subquery to get active session start time (non-expired sessions only)
        query = """
            SELECT u.*, 
            (SELECT MAX(created_at)
             FROM sessions s
             WHERE s.client_id = u.client_id AND s.expires_at > datetime('now')) as active_session_start
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
            # Calculate active duration and status
            duration = "-"
            session_status = "Offline"
            if item.get('active_session_start'):
                try:
                    start = datetime.strptime(item['active_session_start'], "%Y-%m-%d %H:%M:%S")
                    diff = datetime.utcnow() - start
                    total_seconds = int(diff.total_seconds())
                    if total_seconds > 0:
                        hours = total_seconds // 3600
                        minutes = (total_seconds % 3600) // 60
                        duration = f"{hours}h {minutes}m"
                    session_status = "Active"
                except Exception:
                    pass
            item['active_duration'] = duration
            item['session_status'] = session_status
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
    """Fetch pre-ingested WireGuard/iptables logs from SQLite."""
    try:
        start_time = time.monotonic()
        conn = get_db()
        c = conn.cursor()

        conditions = []
        params: List[Any] = []

        if start_date:
            conditions.append("a.timestamp >= ?")
            params.append(f"{start_date} 00:00:00")
        if end_date:
            conditions.append("a.timestamp <= ?")
            params.append(f"{end_date} 23:59:59")
        if client_filter:
            conditions.append("a.client_id = ?")
            params.append(client_filter)

        if search:
            conditions.append("(a.client_id LIKE ? OR a.src_ip LIKE ? OR a.dst_ip LIKE ? OR a.protocol LIKE ? OR dc.domain LIKE ?)")
            term = f"%{search}%"
            params.extend([term, term, term, term, term])

        if domain_filter:
            conditions.append("dc.domain LIKE ?")
            params.append(f"%{domain_filter}%")

        query = (
            "SELECT a.timestamp, a.client_id, a.direction, a.protocol, a.src_ip, a.src_port, "
            "a.dst_ip, a.dst_port, dc.domain as dst_domain "
            "FROM activity_log a "
            "LEFT JOIN dns_cache dc ON dc.ip_address = a.dst_ip"
        )
        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        count_query = "SELECT COUNT(*) FROM activity_log a LEFT JOIN dns_cache dc ON dc.ip_address = a.dst_ip"
        if conditions:
            count_query += " WHERE " + " AND ".join(conditions)
            c.execute(count_query, tuple(params))
        else:
            c.execute(count_query)
        total = c.fetchone()[0]

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        offset = (page - 1) * limit
        params_with_paging = params + [limit, offset]
        c.execute(query, tuple(params_with_paging))

        rows = [dict(row) for row in c.fetchall()]
        conn.close()

        elapsed_ms = int((time.monotonic() - start_time) * 1000)
        logger.info("Activity logs query: total=%s page=%s elapsed=%sms", total, page, elapsed_ms)

        return {
            "logs": rows,
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


@router.get("/api/console/activity-metrics")
async def get_activity_metrics(client_id: str = Depends(_check_console_access)):
    try:
        conn = get_db()
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM activity_log")
        total = c.fetchone()[0]

        c.execute("SELECT MIN(timestamp), MAX(timestamp) FROM activity_log")
        oldest, newest = c.fetchone()

        c.execute(
            "SELECT last_cleanup_at, deleted_rows, remaining_rows FROM activity_log_metrics ORDER BY id DESC LIMIT 1"
        )
        row = c.fetchone()
        conn.close()

        return {
            "retention_days": ACTIVITY_LOG_RETENTION_DAYS,
            "total_logs": total,
            "oldest_log": oldest,
            "newest_log": newest,
            "last_cleanup_at": row[0] if row else None,
            "deleted_last_run": row[1] if row else 0,
            "remaining_after_cleanup": row[2] if row else total
        }
    except Exception as e:
        logger.error(f"Error fetching activity metrics: {e}")
        return {
            "retention_days": ACTIVITY_LOG_RETENTION_DAYS,
            "total_logs": 0,
            "oldest_log": None,
            "newest_log": None,
            "last_cleanup_at": None,
            "deleted_last_run": 0,
            "remaining_after_cleanup": 0
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