import math
import subprocess
import logging
import time
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Request, Depends, HTTPException
from datetime import datetime, timedelta, timezone
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel


class UserCreateRequest(BaseModel):
    client_id: str
    expiry_days: Optional[int] = None


class AgentCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    advertised_cidrs: Optional[List[str]] = None


class AgentPatchRequest(BaseModel):
    advertised_cidrs: Optional[List[str]] = None
    description: Optional[str] = None
    is_restricted: Optional[bool] = None

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
    """Dependency: require console_access=1 AND a non-expired 2FA session.

    Previously only the `console_access` flag was checked, which meant a
    user whose 2FA session had expired (but whose IP was still cached in
    the users table) could still reach /console. Now the join with sessions
    enforces that the user has a live authenticated session.
    """
    ip_address = request.client.host if request and request.client else "unknown"
    client_id = None

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(
            """
            SELECT u.client_id, u.console_access
            FROM users u
            JOIN sessions s ON u.client_id = s.client_id
            WHERE (u.wg_ipv4 = ? OR u.wg_ipv6 = ?)
              AND s.expires_at > datetime('now')
            ORDER BY s.created_at DESC
            LIMIT 1
            """,
            (ip_address, ip_address),
        )
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
    limit: int = 30,
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
    limit: int = 30,
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

        query += " ORDER BY a.timestamp DESC LIMIT ? OFFSET ?"
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
        
        # Estimate rolling last-24h bandwidth from daily aggregates.
        # bandwidth_usage is stored per UTC day (to match tasks.py), so combine all of today
        # and a proportional slice of yesterday based on current UTC time.
        now_utc = datetime.utcnow()
        today_utc = now_utc.strftime("%Y-%m-%d")
        yesterday_utc = (now_utc - timedelta(days=1)).strftime("%Y-%m-%d")

        c.execute("SELECT COALESCE(SUM(rx_bytes + tx_bytes), 0) FROM bandwidth_usage WHERE scan_date = ?", (today_utc,))
        today_total = c.fetchone()[0] or 0

        c.execute("SELECT COALESCE(SUM(rx_bytes + tx_bytes), 0) FROM bandwidth_usage WHERE scan_date = ?", (yesterday_utc,))
        yesterday_total = c.fetchone()[0] or 0

        hours_since_midnight = (
            now_utc.hour +
            (now_utc.minute / 60.0) +
            (now_utc.second / 3600.0)
        )
        yesterday_fraction = max(0.0, min(1.0, (24.0 - hours_since_midnight) / 24.0))
        bandwidth_24h = int(today_total + (yesterday_total * yesterday_fraction))
        
        # Get new users in last 24 hours
        c.execute("""
            SELECT COUNT(*) FROM users
            WHERE created_at >= ?
        """, (yesterday,))
        new_users_24h = c.fetchone()[0]

        conn.close()

        # Agent fleet stats — reuse the same helper /health uses so the
        # numbers are consistent across the two surfaces.
        try:
            from app.core.agents import stats as agent_stats
            agents = agent_stats()
        except Exception:
            agents = {"total": 0, "enrolled": 0, "pending": 0, "revoked": 0, "online": 0}

        return {
            "total_users": total_users,
            "active_sessions": active_sessions,
            "failed_attempts_24h": failed_attempts_24h,
            "bandwidth_24h": bandwidth_24h,
            "new_users_24h": new_users_24h,
            "agents": agents,
        }
    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {e}")
        return {
            "total_users": 0,
            "active_sessions": 0,
            "failed_attempts_24h": 0,
            "bandwidth_24h": 0,
            "new_users_24h": 0,
            "agents": {"total": 0, "enrolled": 0, "pending": 0, "revoked": 0, "online": 0},
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
async def get_bandwidth_usage(
    days: int = 30,
    user: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    client_id: str = Depends(_check_console_access)
):
    """Fetch daily bandwidth usage (RX+TX) per client with optional user/date filters."""
    try:
        conn = get_db()
        c = conn.cursor()

        conditions = []
        params: List[Any] = []

        if user and user != "all":
            conditions.append("client_id = ?")
            params.append(user)

        if start_date:
            conditions.append("scan_date >= ?")
            params.append(start_date)
        if end_date:
            conditions.append("scan_date <= ?")
            params.append(end_date)

        # Fallback to rolling N-day window when no explicit date range is provided.
        safe_days = max(1, min(days, 3650))
        if not start_date and not end_date:
            conditions.append("scan_date >= date('now', ?)")
            params.append(f"-{safe_days} days")

        query = "SELECT scan_date, client_id, rx_bytes, tx_bytes FROM bandwidth_usage"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY scan_date ASC"

        c.execute(query, tuple(params))
        rows = [dict(row) for row in c.fetchall()]
        conn.close()

        # Structure: { labels: [d1, d2], upload: [...], download: [...] }
        # Values are raw bytes for precise rendering at low volumes.
        data_map = {} # date -> { upload: total_bytes, download: total_bytes }

        for r in rows:
            date_str = r['scan_date']
            upload_bytes = int(r['tx_bytes'] or 0)
            download_bytes = int(r['rx_bytes'] or 0)

            if date_str not in data_map:
                data_map[date_str] = {"upload": 0, "download": 0}

            data_map[date_str]["upload"] += upload_bytes
            data_map[date_str]["download"] += download_bytes

        # Determine the complete date range and fill in missing dates with zeros
        _utc_now = datetime.now(timezone.utc)
        today_str = _utc_now.strftime('%Y-%m-%d')
        if start_date and end_date:
            range_start = start_date
            range_end = end_date
        elif start_date:
            range_start = start_date
            range_end = today_str
        else:
            range_start = (_utc_now - timedelta(days=safe_days)).strftime('%Y-%m-%d')
            range_end = end_date if end_date else today_str

        all_dates = []
        cur_dt = datetime.strptime(range_start, '%Y-%m-%d')
        end_dt = datetime.strptime(range_end, '%Y-%m-%d')
        while cur_dt <= end_dt:
            all_dates.append(cur_dt.strftime('%Y-%m-%d'))
            cur_dt += timedelta(days=1)

        for d in all_dates:
            if d not in data_map:
                data_map[d] = {"upload": 0, "download": 0}

        sorted_dates = sorted(all_dates)
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
        
        # --- 24-Hour Traffic Trend (hourly connection activity) ---
        activity_trend = []
        for i in range(23, -1, -1):  # Last 24 hours
            hour_start = datetime.utcnow() - timedelta(hours=i)
            hour_end = hour_start + timedelta(hours=1)
            
            # Count new connections per hour from activity_log
            c.execute("""
                SELECT COUNT(*) 
                FROM activity_log 
                WHERE timestamp >= ? AND timestamp < ?
            """, (hour_start.strftime("%Y-%m-%d %H:00:00"), hour_end.strftime("%Y-%m-%d %H:00:00")))
            
            connections = c.fetchone()[0]
            
            # Also get unique clients active in this hour
            c.execute("""
                SELECT COUNT(DISTINCT client_id) 
                FROM activity_log 
                WHERE timestamp >= ? AND timestamp < ? AND client_id IS NOT NULL
            """, (hour_start.strftime("%Y-%m-%d %H:00:00"), hour_end.strftime("%Y-%m-%d %H:00:00")))
            
            active_users = c.fetchone()[0]
            
            activity_trend.append({
                "hour": hour_start.strftime("%H:%M"),
                "connections": connections,
                "active_users": active_users
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

# ============================================================================
# User Management — create / download config / QR code / delete
# ============================================================================

@router.post("/api/console/users")
async def create_user(
    body: UserCreateRequest,
    client_id: str = Depends(_check_console_access),
):
    """Create a new WireGuard client (equivalent of CLI 'Create Client').

    Allocates IPs, generates keys, writes the [Peer] block to wg0.conf,
    live-syncs the interface, and registers the client in the 2FA users
    table (disabled — the client enables 2FA at first captive-portal visit).
    """
    from app.core.wireguard import create_client, validate_client_name

    try:
        validate_client_name(body.client_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if body.expiry_days is not None and (
        not isinstance(body.expiry_days, int) or body.expiry_days <= 0
    ):
        raise HTTPException(status_code=400, detail="expiry_days must be a positive integer")

    try:
        result = create_client(body.client_id, body.expiry_days)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except RuntimeError as e:
        logger.error(f"create_client runtime error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.exception("create_client unexpected error")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")

    # Audit log
    try:
        client_host = "console"
        audit_log(body.client_id, "CLIENT_CREATE", "success", client_host)
    except Exception:
        pass

    return {
        "success": True,
        "name": result["name"],
        "ipv4": result["ipv4"],
        "ipv6": result["ipv6"],
        "expires": result["expires"],
    }


@router.get("/api/console/users/{user_client_id}/config")
async def download_user_config(
    user_client_id: str,
    client_id: str = Depends(_check_console_access),
):
    """Download the client's WireGuard .conf file as an attachment."""
    from app.core.wireguard import get_client_config, validate_client_name

    try:
        validate_client_name(user_client_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    config_text = get_client_config(user_client_id)
    if not config_text:
        raise HTTPException(
            status_code=404,
            detail="Client .conf file not found on server",
        )

    filename = f"{user_client_id}.conf"
    return Response(
        content=config_text,
        media_type="application/x-wireguard-config",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/api/console/users/{user_client_id}/qrcode")
async def user_config_qrcode(
    user_client_id: str,
    client_id: str = Depends(_check_console_access),
):
    """Return a base64 PNG QR code of the client's WireGuard config."""
    import base64
    from io import BytesIO
    import qrcode
    from app.core.wireguard import get_client_config, validate_client_name

    try:
        validate_client_name(user_client_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    config_text = get_client_config(user_client_id)
    if not config_text:
        raise HTTPException(status_code=404, detail="Client .conf file not found on server")

    qr = qrcode.QRCode(
        version=None,
        box_size=5,
        border=2,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
    )
    qr.add_data(config_text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf)
    return {"qr_code": "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()}


@router.delete("/api/console/users/{user_client_id}")
async def delete_user(
    user_client_id: str,
    client_id: str = Depends(_check_console_access),
):
    """Revoke a WireGuard client (mirrors CLI 'Revoke Client')."""
    from app.core.wireguard import delete_client, validate_client_name

    try:
        validate_client_name(user_client_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if user_client_id == client_id:
        raise HTTPException(status_code=400, detail="Refusing to delete the currently authenticated admin")

    try:
        removed = delete_client(user_client_id)
    except Exception as e:
        logger.exception("delete_client error")
        raise HTTPException(status_code=500, detail=str(e))

    if not removed:
        raise HTTPException(status_code=404, detail="Client not found in WireGuard config")

    try:
        audit_log(user_client_id, "CLIENT_REVOKE", "success", "console")
    except Exception:
        pass

    return {"success": True}


# ============================================================================
# Agent management — admin console endpoints
# ============================================================================
#
# All endpoints here are guarded by _check_console_access, which requires
# (a) console_access=1 on the user and (b) a non-expired 2FA session. Creating
# an agent returns the enrollment token ONCE in the response body; it's never
# retrievable again. Callers that lose the token must delete and recreate.

@router.post("/api/console/agents")
async def create_agent_endpoint(
    body: AgentCreateRequest,
    request: Request,
    client_id: str = Depends(_check_console_access),
):
    """Create a pending agent and issue its one-time enrollment token."""
    from app.core.agents import create_agent
    try:
        result = create_agent(
            name=body.name,
            description=body.description,
            advertised_cidrs=body.advertised_cidrs,
            created_by=client_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # Most common: UNIQUE constraint on agent name
        msg = str(e).lower()
        if "unique" in msg or "integrityerror" in msg:
            raise HTTPException(status_code=409, detail=f"Agent name '{body.name}' already exists")
        logger.exception("create_agent failed")
        raise HTTPException(status_code=500, detail="Failed to create agent")

    # Audit log
    try:
        ip_address = request.client.host if request and request.client else "unknown"
        audit_log(client_id, "AGENT_CREATE", f"name={body.name} id={result['id']}", ip_address)
    except Exception:
        pass

    # Build the install command for the Go agent. The token is passed
    # via env var so it does not end up in shell history / proxy access logs.
    # The legacy Bash installer remains available at /api/agents/install
    # for operators with existing scripts.
    from app.core.config import UI_BASE_URL
    install_cmd = (
        f"curl -sSL {UI_BASE_URL}/api/agents/install-go | "
        f"sudo TOKEN={result['enrollment_token']} "
        f"WIRESHIELD_SERVER={UI_BASE_URL} bash"
    )

    return {
        "success": True,
        "agent": {
            "id": result["id"],
            "name": result["name"],
            "description": result["description"],
            "advertised_cidrs": result["advertised_cidrs"],
            "status": result["status"],
        },
        "enrollment_token": result["enrollment_token"],  # shown ONCE
        "token_expires_at": result["token_expires_at"],
        "install_command": install_cmd,
    }


@router.get("/api/console/agents")
async def list_agents_endpoint(
    include_revoked: bool = False,
    client_id: str = Depends(_check_console_access),
):
    """List all agents, optionally including soft-deleted ones."""
    from app.core.agents import list_agents
    try:
        agents = list_agents(include_revoked=include_revoked)
    except Exception:
        logger.exception("list_agents failed")
        raise HTTPException(status_code=500, detail="Failed to list agents")
    return {"agents": agents, "count": len(agents)}


@router.get("/api/console/agents/{agent_id}")
async def get_agent_endpoint(
    agent_id: int,
    client_id: str = Depends(_check_console_access),
):
    """Return full detail for a single agent. PSK is never included."""
    from app.core.agents import get_agent
    agent = get_agent(agent_id, include_secrets=False)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.patch("/api/console/agents/{agent_id}")
async def patch_agent_endpoint(
    agent_id: int,
    body: AgentPatchRequest,
    request: Request,
    client_id: str = Depends(_check_console_access),
):
    """Edit an agent's advertised CIDRs (live-synced to WireGuard) and/or
    its description. Other fields are immutable (name is identifier,
    public_key/wg_ipv4 come from enrollment)."""
    from app.core.agents import get_agent, update_agent_cidrs
    from app.core.database import get_db

    existing = get_agent(agent_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Agent not found")

    changed_cidrs = False
    if body.advertised_cidrs is not None:
        if existing["status"] != "enrolled":
            raise HTTPException(
                status_code=400,
                detail="CIDRs can only be updated on enrolled agents",
            )
        try:
            ok = update_agent_cidrs(agent_id, body.advertised_cidrs)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception:
            logger.exception("update_agent_cidrs failed")
            raise HTTPException(status_code=500, detail="Failed to update CIDRs")
        if not ok:
            raise HTTPException(
                status_code=409,
                detail="Agent state changed during update — refresh and retry",
            )
        changed_cidrs = True

    if body.description is not None:
        conn = get_db()
        try:
            c = conn.cursor()
            c.execute(
                "UPDATE agents SET description = ? WHERE id = ?",
                (body.description, agent_id),
            )
            conn.commit()
        finally:
            conn.close()

    restriction_changed = False
    if body.is_restricted is not None:
        from app.core.agents import set_agent_restriction
        restriction_changed = set_agent_restriction(agent_id, bool(body.is_restricted))
        if restriction_changed:
            try:
                from app.core.tasks import trigger_agent_acl_sync
                trigger_agent_acl_sync()
            except Exception:
                pass

    try:
        ip_address = request.client.host if request and request.client else "unknown"
        audit_log(
            client_id,
            "AGENT_UPDATE",
            f"id={agent_id} cidrs_changed={changed_cidrs} "
            f"restriction_changed={restriction_changed} "
            f"is_restricted={body.is_restricted}",
            ip_address,
        )
    except Exception:
        pass

    return {"success": True, "agent": get_agent(agent_id)}


@router.delete("/api/console/agents/{agent_id}")
async def delete_agent_endpoint(
    agent_id: int,
    request: Request,
    client_id: str = Depends(_check_console_access),
):
    """Revoke an agent: remove its WG peer, mark soft-deleted."""
    from app.core.agents import get_agent, revoke_agent
    existing = get_agent(agent_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Agent not found")
    if existing["status"] == "revoked":
        return {"success": True, "already_revoked": True}
    try:
        revoke_agent(agent_id)
    except Exception:
        logger.exception("revoke_agent failed")
        raise HTTPException(status_code=500, detail="Failed to revoke agent")

    try:
        ip_address = request.client.host if request and request.client else "unknown"
        audit_log(
            client_id,
            "AGENT_REVOKE",
            f"id={agent_id} name={existing['name']}",
            ip_address,
        )
    except Exception:
        pass
    return {"success": True}


@router.post("/api/console/agents/{agent_id}/rotate-token")
async def rotate_agent_token_endpoint(
    agent_id: int,
    request: Request,
    client_id: str = Depends(_check_console_access),
):
    """Reissue an enrollment token for a pending (not yet enrolled) agent.
    Useful if the first token expired or was lost. Refuses for agents that
    are already enrolled (they have a working WG keypair already) or
    revoked."""
    from app.core.agents import get_agent, issue_enrollment_token
    from app.core.config import UI_BASE_URL
    existing = get_agent(agent_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Agent not found")
    if existing["status"] != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot rotate token for agent in status={existing['status']}. "
                   "Delete and recreate to start fresh.",
        )

    raw_token, expires_at = issue_enrollment_token(agent_id)
    install_cmd = (
        f"curl -sSL {UI_BASE_URL}/api/agents/install-go | "
        f"sudo TOKEN={raw_token} "
        f"WIRESHIELD_SERVER={UI_BASE_URL} bash"
    )

    try:
        ip_address = request.client.host if request and request.client else "unknown"
        audit_log(
            client_id,
            "AGENT_TOKEN_ROTATE",
            f"id={agent_id} name={existing['name']}",
            ip_address,
        )
    except Exception:
        pass

    return {
        "success": True,
        "enrollment_token": raw_token,
        "token_expires_at": expires_at.isoformat() + "Z",
        "install_command": install_cmd,
    }


# ============================================================================
# Per-user agent allowlist admin API
#
# Default behaviour is unchanged (every agent has is_restricted=0 →
# all users can reach all agents). The admin opts a specific agent into
# restriction by PATCHing /api/console/agents/{id} with is_restricted=true,
# then grants access to specific users via POST/DELETE under
# /api/console/agents/{id}/access.
# ============================================================================


class AgentAccessRequest(BaseModel):
    client_id: str


@router.get("/api/console/agents/{agent_id}/access")
async def list_agent_access(
    agent_id: int,
    client_id: str = Depends(_check_console_access),
):
    """Return the per-user allowlist for an agent + current is_restricted flag."""
    from app.core.agents import get_agent, list_agent_users

    agent = get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    return {
        "agent_id": agent_id,
        "agent_name": agent.get("name"),
        "is_restricted": bool(agent.get("is_restricted") or 0),
        "users": list_agent_users(agent_id),
    }


@router.post("/api/console/agents/{agent_id}/access")
async def grant_agent_access_endpoint(
    agent_id: int,
    body: AgentAccessRequest,
    request: Request,
    client_id: str = Depends(_check_console_access),
):
    """Add a user to an agent's allowlist."""
    from app.core.agents import grant_agent_access, get_agent

    if get_agent(agent_id) is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    try:
        added = grant_agent_access(agent_id, body.client_id, granted_by=client_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    try:
        ip_address = request.client.host if request and request.client else "unknown"
        audit_log(
            client_id,
            "AGENT_ACCESS_GRANT",
            f"agent_id={agent_id} target_client={body.client_id} added={added}",
            ip_address,
        )
    except Exception:
        pass

    # Trigger an immediate firewall sync so the grant takes effect
    # without waiting for the 30s reconcile loop.
    try:
        from app.core.tasks import trigger_agent_acl_sync
        trigger_agent_acl_sync()
    except Exception:
        pass

    return {"success": True, "added": added, "agent_id": agent_id, "client_id": body.client_id}


@router.delete("/api/console/agents/{agent_id}/access/{target_client_id}")
async def revoke_agent_access_endpoint(
    agent_id: int,
    target_client_id: str,
    request: Request,
    client_id: str = Depends(_check_console_access),
):
    """Remove a user from an agent's allowlist. Idempotent: returns 200
    with removed=false if the row was already absent."""
    from app.core.agents import revoke_agent_access, get_agent

    if get_agent(agent_id) is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    removed = revoke_agent_access(agent_id, target_client_id)

    try:
        ip_address = request.client.host if request and request.client else "unknown"
        audit_log(
            client_id,
            "AGENT_ACCESS_REVOKE",
            f"agent_id={agent_id} target_client={target_client_id} removed={removed}",
            ip_address,
        )
    except Exception:
        pass

    try:
        from app.core.tasks import trigger_agent_acl_sync
        trigger_agent_acl_sync()
    except Exception:
        pass

    return {"success": True, "removed": removed, "agent_id": agent_id, "client_id": target_client_id}


# ============================================================================
# Agent traffic + uptime metrics
#
# /api/console/agents/{id}/metrics aggregates the existing
# agent_heartbeats table into evenly-spaced time buckets so the UI's
# detail drawer can render a sparkline + uptime %. No schema change —
# heartbeats already carry rx_bytes/tx_bytes per 30 s tick and are
# pruned by the housekeeping task per WS_AGENT_HEARTBEAT_RETENTION_HOURS.
# ============================================================================


@router.get("/api/console/agents/{agent_id}/metrics")
async def agent_metrics_endpoint(
    agent_id: int,
    window_hours: int = 24,
    bucket_minutes: int = 15,
    client_id: str = Depends(_check_console_access),
):
    """Return rx/tx delta time-series + uptime % for one agent.

    window_hours / bucket_minutes are clamped to safe-but-flexible
    ranges. Buckets that contain no heartbeat are emitted with zero
    deltas + counted toward downtime (matches what an operator
    interprets visually: gap = agent was offline).
    """
    if window_hours < 1:
        window_hours = 1
    if window_hours > 168:  # one week
        window_hours = 168
    if bucket_minutes < 1:
        bucket_minutes = 1
    if bucket_minutes > 60:
        bucket_minutes = 60

    from app.core.agents import get_agent
    agent = get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    conn = get_db()
    try:
        c = conn.cursor()
        # Pull every heartbeat in the window, ordered by time. We compute
        # rx/tx deltas client-side because the agent's bytes counter is a
        # cumulative counter that resets when wg-quick bounces; a per-row
        # SQL diff would mistake a counter reset for a negative delta.
        c.execute(
            """
            SELECT received_at, rx_bytes, tx_bytes
            FROM agent_heartbeats
            WHERE agent_id = ?
              AND received_at >= datetime('now', ?)
            ORDER BY received_at ASC
            """,
            (agent_id, f"-{window_hours} hours"),
        )
        rows = [dict(r) for r in c.fetchall()]
    finally:
        conn.close()

    # Bucket boundaries — UTC, anchored to "now" so the right edge of the
    # chart is always the most recent tick.
    from datetime import datetime, timedelta, timezone
    now = datetime.now(tz=timezone.utc).replace(microsecond=0)
    end = now
    start = end - timedelta(hours=window_hours)
    bucket = timedelta(minutes=bucket_minutes)
    n_buckets = int((end - start) / bucket)
    buckets = [start + bucket * i for i in range(n_buckets + 1)]

    # Pre-compute per-bucket cumulative-counter snapshots, then derive
    # deltas with monotonicity checks so a counter reset reads as zero.
    rx_seen = [None] * (n_buckets + 1)
    tx_seen = [None] * (n_buckets + 1)
    heartbeat_count = [0] * (n_buckets + 1)
    for r in rows:
        try:
            ts = datetime.fromisoformat(r["received_at"]).replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            continue
        idx = int((ts - start) / bucket)
        if idx < 0 or idx > n_buckets:
            continue
        # Within a bucket, the LAST heartbeat wins; that's the most
        # accurate snapshot of the cumulative counter at bucket-end.
        rx_seen[idx] = r.get("rx_bytes") or 0
        tx_seen[idx] = r.get("tx_bytes") or 0
        heartbeat_count[idx] += 1

    # Forward-fill the snapshots so a gap doesn't generate a false positive
    # delta. After fill, compute deltas. Negative deltas (counter reset)
    # are clamped to zero.
    last_rx, last_tx = 0, 0
    rx_filled = []
    tx_filled = []
    for i in range(n_buckets + 1):
        if rx_seen[i] is None:
            rx_filled.append(last_rx)
            tx_filled.append(last_tx)
        else:
            rx_filled.append(rx_seen[i])
            tx_filled.append(tx_seen[i])
            last_rx = rx_seen[i]
            last_tx = tx_seen[i]

    rx_delta = []
    tx_delta = []
    prev_rx, prev_tx = rx_filled[0], tx_filled[0]
    for i in range(1, n_buckets + 1):
        d_rx = max(0, rx_filled[i] - prev_rx)
        d_tx = max(0, tx_filled[i] - prev_tx)
        rx_delta.append(d_rx)
        tx_delta.append(d_tx)
        prev_rx, prev_tx = rx_filled[i], tx_filled[i]

    # Uptime %: a bucket is "up" when it received ≥1 heartbeat.
    # The first bucket is excluded from delta math (it's the baseline)
    # but is included in uptime counting since a heartbeat there means
    # the agent was alive at the start of the window.
    up_buckets = sum(1 for c in heartbeat_count if c > 0)
    uptime_pct = round(100.0 * up_buckets / max(1, len(heartbeat_count)), 2)

    return {
        "agent_id": agent_id,
        "agent_name": agent.get("name"),
        "window_hours": window_hours,
        "bucket_minutes": bucket_minutes,
        "uptime_percent": uptime_pct,
        "online_buckets": up_buckets,
        "total_buckets": len(heartbeat_count),
        # Bucket midpoints (ISO Z) for chart x-axis labels.
        "labels": [
            (start + bucket * (i + 1)).isoformat().replace("+00:00", "Z")
            for i in range(n_buckets)
        ],
        "rx_bytes_per_bucket": rx_delta,
        "tx_bytes_per_bucket": tx_delta,
    }
