import math
import subprocess
import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse

from app.core.database import get_db
from app.core.security import audit_log
from app.core.config import LOG_LEVEL
from app.templates import get_access_denied_html

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
        return get_access_denied_html()
        
    audit_log(client_id, "CONSOLE_ACCESS", "granted", request.client.host)
    
    # Simple dashboard HTML (embedded for single-file simplicity in this router, 
    # or could be moved to templates.py if too large)
    return HTMLResponse("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireShield Console</title>
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
    <style>
        :root { --bg: #f8fafc; --nav: #1e293b; --accent: #2563eb; --text: #334155; }
        body { font-family: -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; display: flex; height: 100vh; }
        nav { width: 240px; background: var(--nav); color: white; padding: 20px; display: flex; flex-direction: column; gap: 10px; }
        nav h1 { font-size: 18px; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }
        nav a { color: #cbd5e1; text-decoration: none; padding: 10px 12px; border-radius: 6px; display: block; font-size: 14px; }
        nav a:hover, nav a.active { background: #334155; color: white; }
        main { flex: 1; padding: 30px; overflow-y: auto; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }
        h2 { font-size: 16px; margin-bottom: 15px; color: #0f172a; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #e2e8f0; }
        th { font-weight: 600; color: #64748b; }
        .badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 500; }
        .badge.success { background: #dcfce7; color: #166534; }
        .badge.warning { background: #fef9c3; color: #854d0e; }
        .badge.error { background: #fee2e2; color: #991b1b; }
        .filters { display: flex; gap: 10px; margin-bottom: 20px; }
        input, select { padding: 8px 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 13px; }
        .pagination { display: flex; gap: 5px; justify-content: flex-end; margin-top: 15px; }
        button { padding: 6px 12px; border: 1px solid #cbd5e1; background: white; border-radius: 4px; cursor: pointer; }
        button:disabled { opacity: 0.5; cursor: default; }
    </style>
</head>
<body>
    <nav>
        <h1><img src="/static/logo.svg" width="24"> WireShield</h1>
        <a href="#" class="active" onclick="switchView('users')">Users & Sessions</a>
        <a href="#" onclick="switchView('activity')">Activity Logs</a>
        <a href="#" onclick="switchView('audit')">Audit Logs</a>
    </nav>
    <main id="content">
        <!-- Content loaded via JS -->
    </main>
    <script>
        let currentView = 'users';
        
        async function switchView(view) {
            currentView = view;
            document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
            event.target.classList.add('active');
            loadData();
        }
        
        async function loadData(page=1) {
            const main = document.getElementById('content');
            main.innerHTML = '<div style="padding:20px;">Loading...</div>';
            
            try {
                let url = `/api/console/${currentView}?page=${page}`;
                // Add filters if present
                const search = document.getElementById('searchInput')?.value;
                if (search) url += `&search=${encodeURIComponent(search)}`;
                
                const res = await fetch(url);
                const data = await res.json();
                
                if (!res.ok) {
                    throw new Error(data.detail || `Server error: ${res.status}`);
                }
                
                renderTable(data, page);
            } catch (e) {
                main.innerHTML = `<div style="color:red; padding:20px;">Error loading data: ${e.message}</div>`;
            }
        }
        
        function renderTable(data, page) {
            const main = document.getElementById('content');
            if (!data || !data.items) {
                main.innerHTML = '<div style="color:red; padding:20px;">Invalid data format received</div>';
                return;
            }

            let html = `
                <div class="card">
                    <div class="filters">
                        <input type="text" id="searchInput" placeholder="Search..." onchange="loadData(1)">
                        <button onclick="loadData(1)">Refresh</button>
                    </div>
                    <table>
                        <thead>${getHeaders()}</thead>
                        <tbody>
                            ${data.items.length > 0 ? data.items.map(row => getRowRequest(row)).join('') : '<tr><td colspan="5" style="text-align:center;color:#94a3b8;padding:20px">No records found</td></tr>'}
                        </tbody>
                    </table>
                    <div class="pagination">
                        <button ${page <= 1 ? 'disabled' : ''} onclick="loadData(${page-1})">Prev</button>
                        <span>Page ${page} of ${data.pages || 1}</span>
                        <button ${page >= (data.pages || 1) ? 'disabled' : ''} onclick="loadData(${page+1})">Next</button>
                    </div>
                </div>
            `;
            main.innerHTML = html;
        }

        function getHeaders() {
            if (currentView === 'users') return '<tr><th>Client ID</th><th>Status</th><th>IP (v4/v6)</th><th>Last Active</th></tr>';
            if (currentView === 'activity') return '<tr><th>Timestamp</th><th>Client</th><th>Message</th></tr>';
            if (currentView === 'audit') return '<tr><th>Timestamp</th><th>Client</th><th>Action</th><th>Status</th><th>IP</th></tr>';
        }

        function getRowRequest(row) {
            if (currentView === 'users') {
                return `<tr>
                    <td>${row.client_id}</td>
                    <td><span class="badge ${row.enabled ? 'success' : 'warning'}">${row.enabled ? 'Active' : 'Disabled'}</span></td>
                    <td>${row.wg_ipv4 || '-'}<br><span style="color:#94a3b8">${row.wg_ipv6 || '-'}</span></td>
                    <td>${row.updated_at}</td>
                </tr>`;
            }
            if (currentView === 'activity') {
                return `<tr>
                    <td style="white-space:nowrap">${row.timestamp}</td>
                    <td>${row.client_id || 'System'}</td>
                    <td>${row.message}</td>
                </tr>`;
            }
            if (currentView === 'audit') {
                 return `<tr>
                    <td style="white-space:nowrap">${row.timestamp}</td>
                    <td>${row.client_id}</td>
                    <td>${row.action}</td>
                    <td><span class="badge ${row.status === 'success' || row.status === 'granted' ? 'success' : 'error'}">${row.status}</span></td>
                    <td>${row.ip_address}</td>
                </tr>`;
            }
        }
        
        // Initial load
        loadData();
    </script>
</body>
</html>
    """)

@router.get("/api/console/users")
async def get_users(
    page: int = 1, 
    limit: int = 20, 
    search: str = None, 
    client_id: str = Depends(_check_console_access)
):
    try:
        offset = (page - 1) * limit
        conn = get_db()
        c = conn.cursor()
        
        query = "SELECT * FROM users"
        params = []
        if search:
            query += " WHERE client_id LIKE ?"
            params.append(f"%{search}%")
            
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        c.execute(query, tuple(params))
        rows = [dict(row) for row in c.fetchall()]
        
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
            "items": rows,
            "page": page,
            "pages": math.ceil(total / limit) if limit > 0 else 1,
            "total": total
        }
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return {"items": [], "page": 1, "pages": 0, "total": 0}

@router.get("/api/console/audit-logs")
async def get_audit_logs(
    page: int = 1,
    limit: int = 50,
    search: str = None,
    client_id: str = Depends(_check_console_access)
):
    try:
        offset = (page - 1) * limit
        conn = get_db()
        c = conn.cursor()
        
        query = "SELECT * FROM audit_log"
        params = []
        if search:
            query += " WHERE client_id LIKE ? OR action LIKE ?"
            params.extend([f"%{search}%", f"%{search}%"])
            
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        c.execute(query, tuple(params))
        rows = [dict(row) for row in c.fetchall()]
        
        # Count total
        count_query = "SELECT COUNT(*) FROM audit_log"
        if search:
            count_query += " WHERE client_id LIKE ? OR action LIKE ?"
            c.execute(count_query, (f"%{search}%", f"%{search}%"))
        else:
            c.execute(count_query)
            
        total = c.fetchone()[0]
        conn.close()
        
        return {
            "items": rows,
            "page": page,
            "pages": math.ceil(total / limit) if limit > 0 else 1,
            "total": total
        }
    except Exception as e:
        logger.error(f"Error fetching audit logs: {e}")
        return {"items": [], "page": 1, "pages": 0, "total": 0}

@router.get("/api/console/activity-logs")
async def get_activity_logs(
    page: int = 1,
    limit: int = 50,
    search: str = None,
    client_id: str = Depends(_check_console_access)
):
    """Fetch WireGuard kernel logs via journalctl."""
    # We need to parse journalctl output
    cmd = ["journalctl", "-k", "-n", "1000", "--output=short-iso", "--no-pager"]
    # If search provided, grep it first to reduce parsing load
    if search:
        cmd.extend(["--grep", search])
        
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        lines = proc.stdout.strip().splitlines()
        
        # Filter for WireGuard related logs only
        wg_lines = [l for l in lines if "wireguard:" in l or "wg" in l]
        wg_lines.reverse() # Newest first
        
        # Pagination
        start = (page - 1) * limit
        end = start + limit
        total = len(wg_lines)
        page_items = wg_lines[start:end]
        
        structured = []
        for line in page_items:
            # Basic parsing: 2023-10-20T10:00:00+00:00 hostname kernel: wireguard: ...
            parts = line.split(" ", 3)
            ts = parts[0]
            msg = parts[3] if len(parts) > 3 else line
            structured.append({"timestamp": ts, "message": msg, "client_id": None})
            
        return {
            "items": structured,
            "page": page,
            "pages": math.ceil(total / limit) if limit > 0 else 1,
            "total": total
        }
        
    except Exception as e:
        logger.error(f"Failed to fetch logs: {e}")
        return {"items": [], "page": 1, "pages": 0, "total": 0}
