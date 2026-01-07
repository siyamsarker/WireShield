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
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&amp;family=JetBrains+Mono:wght@400;500&amp;display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-body: #0f172a;
            --bg-nav: #1e293b;
            --bg-card: #1e293b;
            --bg-card-hover: #334155;
            --border: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --success: #22c55e;
            --warning: #eab308;
            --error: #ef4444;
            --glass: rgba(30, 41, 59, 0.7);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg-body);
            color: var(--text-main);
            height: 100vh;
            display: flex;
            overflow: hidden;
        }

        /* Sidebar */
        nav {
            width: 260px;
            background: var(--bg-nav);
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            padding: 24px;
            gap: 8px;
            flex-shrink: 0;
            position: relative;
            z-index: 20;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 32px;
            padding: 0 12px;
        }

        .brand-text {
            font-weight: 700;
            font-size: 18px;
            letter-spacing: -0.02em;
            background: linear-gradient(135deg, #fff 0%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            color: var(--text-muted);
            text-decoration: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.2s ease;
            border: 1px solid transparent;
        }

        .nav-item:hover {
            background: rgba(255, 255, 255, 0.03);
            color: var(--text-main);
        }

        .nav-item.active {
            background: rgba(59, 130, 246, 0.1);
            color: var(--accent);
            border-color: rgba(59, 130, 246, 0.2);
        }

        .nav-item svg { width: 18px; height: 18px; }

        /* Main Content */
        main {
            flex: 1;
            display: flex;
            flex-direction: column;
            position: relative;
            overflow: hidden;
        }

        header {
            height: 70px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 32px;
            background: rgba(15, 23, 42, 0.8);
            backdrop-filter: blur(12px);
            position: relative;
            z-index: 10;
        }

        .page-title {
            font-size: 16px;
            font-weight: 600;
            color: var(--text-main);
        }

        .header-controls {
            display: flex;
            gap: 16px;
            align-items: center;
        }

        /* Search */
        .search-wrapper {
            position: relative;
        }
        
        .search-icon {
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            pointer-events: none;
        }

        input[type="text"] {
            background: var(--bg-nav);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 8px 12px 8px 36px;
            border-radius: 8px;
            font-size: 13px;
            width: 320px;
            outline: none;
            transition: all 0.2s;
            font-family: 'Inter', sans-serif;
        }

        input[type="text"]:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
        }

        /* Toolbar Buttons */
        .btn {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
            border: 1px solid transparent;
        }

        .btn-secondary {
            background: var(--bg-nav);
            border: 1px solid var(--border);
            color: var(--text-main);
        }

        .btn-secondary:hover {
            border-color: var(--text-muted);
            background: var(--bg-card-hover);
        }

        .btn-primary {
            background: var(--accent);
            color: white;
        }
        
        .btn-primary:hover {
            background: var(--accent-hover);
            box-shadow: 0 2px 8px rgba(59, 130, 246, 0.3);
        }
        
        .btn.active {
            background: rgba(34, 197, 94, 0.1);
            color: var(--success);
            border-color: rgba(34, 197, 94, 0.3);
        }

        /* Content Area */
        .content-scroll {
            flex: 1;
            padding: 32px;
            overflow-y: auto;
        }

        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            overflow: hidden;
            animation: fadeIn 0.3s ease-out;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        th {
            text-align: left;
            padding: 16px 24px;
            color: var(--text-muted);
            font-weight: 500;
            border-bottom: 1px solid var(--border);
            background: rgba(0, 0, 0, 0.2);
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.05em;
        }

        td {
            padding: 16px 24px;
            color: var(--text-main);
            border-bottom: 1px solid var(--border);
        }

        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(255, 255, 255, 0.01); }

        .mono { font-family: 'JetBrains Mono', monospace; font-size: 12px; }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 8px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 500;
            border: 1px solid transparent;
        }

        .badge::before {
            content: '';
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: currentColor;
        }

        .badge.success { background: rgba(34, 197, 94, 0.1); color: var(--success); border-color: rgba(34, 197, 94, 0.1); }
        .badge.warning { background: rgba(234, 179, 8, 0.1); color: var(--warning); border-color: rgba(234, 179, 8, 0.1); }
        .badge.error { background: rgba(239, 68, 68, 0.1); color: var(--error); border-color: rgba(239, 68, 68, 0.1); }

        .footer {
            padding: 16px 24px;
            border-top: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(0, 0, 0, 0.2);
        }

        .footer-info { font-size: 12px; color: var(--text-muted); }
        .pagination { display: flex; gap: 8px; }

        .status-dot {
            width: 8px; height: 8px; border-radius: 50%; background: var(--text-muted);
            transition: all 0.3s;
        }
        .status-dot.live { background: var(--success); box-shadow: 0 0 8px var(--success); animation: pulse 2s infinite; }

        @keyframes fadeIn { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        
        /* Scrollbar */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }
    </style>
</head>
<body>
    <nav>
        <div class="brand">
            <img src="/static/logo.svg" alt="WS" style="width: 24px;">
            <span class="brand-text">WireShield</span>
        </div>
        <a href="#" class="nav-item active" data-view="users" onclick="app.setView('users')">
            <svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" /></svg>
            Users & Sessions
        </a>
        <a href="#" class="nav-item" data-view="activity" onclick="app.setView('activity')">
            <svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" /></svg>
            Activity Logs
        </a>
        <a href="#" class="nav-item" data-view="audit" onclick="app.setView('audit')">
            <svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            Audit Logs
        </a>
    </nav>

    <main>
        <header>
            <div class="page-title" id="pageTitle">Users & Sessions</div>
            <div class="header-controls">
                <div class="search-wrapper">
                    <svg class="search-icon" width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
                    <input type="text" id="searchInput" placeholder="Search..." oninput="app.handleSearch(this.value)">
                </div>
                <div id="liveToggle" style="display:none">
                    <button class="btn btn-secondary" id="liveBtn" onclick="app.toggleLive()">
                        <div class="status-dot" id="liveDot"></div>
                        Live
                    </button>
                </div>
                <button class="btn btn-primary" onclick="app.refresh()">
                    <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                    Refresh
                </button>
            </div>
        </header>

        <div class="content-scroll">
            <div class="card">
                <table id="dataTable">
                    <thead id="tableHead"></thead>
                    <tbody id="tableBody"></tbody>
                </table>
                <div class="footer">
                    <div class="footer-info" id="footerInfo">Loading...</div>
                    <div class="pagination" id="pagination"></div>
                </div>
            </div>
        </div>
    </main>

    <script>
        const app = {
            state: { view: 'users', page: 1, search: '', loading: false, live: false, timer: null },
            headers: {
                users: ['Client ID', 'Status', 'IP (Internal)', 'Last Active'],
                activity: ['Timestamp', 'Client', 'Message'],
                audit: ['Timestamp', 'Client', 'Action', 'Status', 'Origin IP']
            },
            
            init() {
                this.setView('users');
            },

            setView(view) {
                this.state.view = view;
                this.state.page = 1;
                this.state.search = '';
                this.state.live = false;
                if (this.state.timer) clearInterval(this.state.timer);
                
                // Update Nav UI
                document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
                const activeLink = document.querySelector(`.nav-item[data-view="${view}"]`);
                if (activeLink) activeLink.classList.add('active');
                
                // Update Header
                const titles = { users: 'Users & Sessions', activity: 'Activity Logs', audit: 'Audit Logs' };
                document.getElementById('pageTitle').textContent = titles[view];
                document.getElementById('searchInput').value = '';
                
                // Show/Hide Live Button
                const liveDiv = document.getElementById('liveToggle');
                const liveBtn = document.getElementById('liveBtn');
                if (view === 'activity') {
                    liveDiv.style.display = 'block';
                    liveBtn.classList.remove('active');
                    document.getElementById('liveDot').classList.remove('live');
                } else {
                    liveDiv.style.display = 'none';
                }

                this.renderHeaders();
                this.loadData();
            },

            renderHeaders() {
                const head = document.getElementById('tableHead');
                const cols = this.headers[this.state.view] || [];
                head.innerHTML = `<tr>${cols.map(c => `<th>${c}</th>`).join('')}</tr>`;
            },

            handleSearch: (function() {
                let timeout;
                return function(val) {
                    clearTimeout(timeout);
                    timeout = setTimeout(() => {
                        this.state.search = val;
                        this.state.page = 1;
                        this.loadData();
                    }, 300); // 300ms debounce
                };
            })(),

            toggleLive() {
                this.state.live = !this.state.live;
                const btn = document.getElementById('liveBtn');
                const dot = document.getElementById('liveDot');
                
                if (this.state.live) {
                    btn.classList.add('active');
                    dot.classList.add('live');
                    this.loadData();
                    this.state.timer = setInterval(() => this.loadData(), 5000);
                } else {
                    btn.classList.remove('active');
                    dot.classList.remove('live');
                    if (this.state.timer) clearInterval(this.state.timer);
                }
            },

            refresh() {
                this.loadData(this.state.page);
            },

            async loadData(page = 1) {
                this.state.page = page;
                this.state.loading = true;
                const tbody = document.getElementById('tableBody');
                
                if (!this.state.live) {
                    tbody.style.opacity = '0.5';
                }

                try {
                    let url = `/api/console/${this.state.view}?page=${page}`;
                    if (this.state.search) url += `&search=${encodeURIComponent(this.state.search)}`;
                    
                    const res = await fetch(url);
                    const data = await res.json();
                    
                    if (!res.ok) throw new Error(data.detail || 'Server error');
                    
                    this.renderTable(data);
                } catch (e) {
                    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--error); padding: 32px;">Error: ${e.message}</td></tr>`;
                } finally {
                    this.state.loading = false;
                    tbody.style.opacity = '1';
                }
            },

            renderTable(data) {
                const tbody = document.getElementById('tableBody');
                if (!data.items || data.items.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding: 32px;">No records found</td></tr>`;
                    document.getElementById('footerInfo').textContent = '0 items';
                    document.getElementById('pagination').innerHTML = '';
                    return;
                }

                tbody.innerHTML = data.items.map(item => this.getRowHtml(item)).join('');
                
                // Update Footer
                const start = (data.page - 1) * 20 + 1; // Approx logic since limit varies on backend but usually 20/50
                document.getElementById('footerInfo').textContent = `Page ${data.page} of ${data.pages} • Total ${data.total}`;
                
                // Pagination
                const pages = [];
                if (data.page > 1) pages.push(`<button class="btn btn-secondary" onclick="app.loadData(${data.page - 1})">Prev</button>`);
                if (data.page < data.pages) pages.push(`<button class="btn btn-secondary" onclick="app.loadData(${data.page + 1})">Next</button>`);
                document.getElementById('pagination').innerHTML = pages.join('');
            },

            getRowHtml(row) {
                if (this.state.view === 'users') {
                    return `
                        <tr>
                            <td class="mono" style="font-weight:600">${row.client_id}</td>
                            <td><span class="badge ${row.enabled ? 'success' : 'warning'}">${row.enabled ? 'Active' : 'Disabled'}</span></td>
                            <td class="mono" style="color:var(--text-muted)">${row.wg_ipv4 || '-'}<br>${row.wg_ipv6 || ''}</td>
                            <td style="color:var(--text-muted)">${row.updated_at}</td>
                        </tr>`;
                }
                if (this.state.view === 'activity') {
                    return `
                        <tr>
                            <td class="mono" style="color:var(--accent); width: 180px;">${row.timestamp}</td>
                            <td class="mono" style="font-weight:600; width: 150px;">${row.client_id || 'System'}</td>
                            <td>${row.message}</td>
                        </tr>`;
                }
                if (this.state.view === 'audit') {
                    const statusClass = (row.status === 'success' || row.status === 'granted') ? 'success' : 'error';
                    return `
                        <tr>
                            <td class="mono" style="color:var(--text-muted)">${row.timestamp}</td>
                            <td class="mono" style="font-weight:600">${row.client_id || '-'}</td>
                            <td>${row.action}</td>
                            <td><span class="badge ${statusClass}">${row.status}</span></td>
                            <td class="mono">${row.ip_address}</td>
                        </tr>`;
                }
            }
        };

        // Initialize only when DOM is ready
        document.addEventListener('DOMContentLoaded', () => app.init());
        // Handle direct script execution if already ready
        if (document.readyState === 'complete') app.init();
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
