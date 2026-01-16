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
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            /* Premium Light Theme */
            --bg-body: #f8fafc;        /* Slate 50 */
            --bg-nav: #ffffff;         /* White */
            --bg-card: #ffffff;        /* White */
            --bg-card-hover: #f1f5f9;  /* Slate 100 */
            --border: #e2e8f0;         /* Slate 200 */
            
            --text-main: #0f172a;      /* Slate 900 */
            --text-muted: #64748b;     /* Slate 500 */
            
            --accent: #2563eb;         /* Blue 600 */
            --accent-hover: #1d4ed8;   /* Blue 700 */
            --accent-light: #eff6ff;   /* Blue 50 */
            
            --success: #16a34a;        /* Green 600 */
            --success-bg: #dcfce7;     /* Green 100 */
            --warning: #ca8a04;        /* Yellow 600 */
            --warning-bg: #fef9c3;     /* Yellow 100 */
            --error: #dc2626;          /* Red 600 */
            --error-bg: #fee2e2;       /* Red 100 */
            
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
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
            color: var(--text-main);
        }

        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 16px;
            color: var(--text-muted);
            text-decoration: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.2s ease;
            border: 1px solid transparent;
        }

        .nav-item:hover {
            background: var(--bg-card-hover);
            color: var(--text-main);
        }

        .nav-item.active {
            background: var(--accent-light);
            color: var(--accent);
            border: 1px solid rgba(37, 99, 235, 0.1);
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
            background: rgba(255, 255, 255, 0.8);
            backdrop-filter: blur(12px);
            position: relative;
            z-index: 10;
        }

        .page-title {
            font-size: 18px;
            font-weight: 700;
            color: var(--text-main);
            letter-spacing: -0.02em;
        }

        .header-controls {
            display: flex;
            gap: 16px;
            align-items: center;
        }

        /* Search */
        .search-wrapper { position: relative; }
        
        .search-icon {
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            pointer-events: none;
        }

        input[type="text"] {
            background: white;
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 9px 12px 9px 38px;
            border-radius: 8px;
            font-size: 13px;
            width: 320px;
            outline: none;
            transition: all 0.2s;
            font-family: 'Inter', sans-serif;
            box-shadow: var(--shadow-sm);
        }

        input[type="text"]:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-light);
        }

        /* Buttons */
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
            box-shadow: var(--shadow-sm);
        }

        .btn-secondary {
            background: white;
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
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
        }
        
        .btn-primary:hover {
            background: var(--accent-hover);
            transform: translateY(-1px);
            box-shadow: 0 4px 6px -1px rgba(37, 99, 235, 0.2);
        }
        
        .btn.active {
            background: var(--success-bg);
            color: var(--success);
            border-color: var(--success);
        }

        /* Content */
        .content-scroll {
            flex: 1;
            padding: 32px;
            overflow-y: auto;
        }

        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            box-shadow: var(--shadow-md);
            overflow: hidden;
            animation: fadeIn 0.4s cubic-bezier(0.16, 1, 0.3, 1);
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
            font-weight: 600;
            border-bottom: 1px solid var(--border);
            background: var(--bg-card-hover);
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
        
        tr:hover td { 
            background: var(--bg-card-hover); 
        }

        .mono { font-family: 'JetBrains Mono', monospace; font-size: 12px; }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
        }

        .badge::before {
            content: '';
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: currentColor;
        }

        .badge.success { background: var(--success-bg); color: var(--success); }
        .badge.warning { background: var(--warning-bg); color: var(--warning); }
        .badge.error { background: var(--error-bg); color: var(--error); }

        /* Filter Bar */
        .filter-bar {
            padding: 16px 32px;
            background: var(--bg-card);
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: flex-end;
            gap: 24px;
            flex-wrap: wrap;
        }

        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .filter-group label {
            font-size: 11px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .filter-row {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        input[type="date"], select {
            background: white;
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 8px 12px;
            border-radius: 8px;
            font-size: 13px;
            font-family: 'Inter', sans-serif;
            box-shadow: var(--shadow-sm);
            outline: none;
            transition: all 0.2s;
        }

        input[type="date"]:focus, select:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-light);
        }

        select { min-width: 180px; cursor: pointer; }

        .footer {
            padding: 16px 24px;
            border-top: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: var(--bg-body);
        }

        .footer-info { font-size: 12px; color: var(--text-muted); font-weight: 500; }
        .pagination { display: flex; gap: 8px; }

        .status-dot {
            width: 8px; height: 8px; border-radius: 50%; background: var(--text-muted);
            transition: all 0.3s;
        }
        .status-dot.live { background: var(--success); box-shadow: 0 0 0 2px var(--success-bg); animation: pulse 2s infinite; }

        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        
        /* Scrollbar */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #94a3b8; }

        .clickable { cursor: pointer; }
        .clickable:hover { background: var(--bg-card-hover); }

        /* ============ Dashboard Styles ============ */
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 24px;
        }

        @media (max-width: 1200px) {
            .dashboard-grid { grid-template-columns: repeat(2, 1fr); }
        }

        @media (max-width: 600px) {
            .dashboard-grid { grid-template-columns: 1fr; }
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 24px 28px;
            display: flex;
            align-items: center;
            gap: 20px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
            z-index: 1;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 80%;
            height: 150%;
            background: radial-gradient(circle, var(--glow-color) 0%, transparent 70%);
            opacity: 0.12;
            transform: rotate(-15deg);
            z-index: -1;
            transition: opacity 0.3s;
            pointer-events: none;
        }

        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.08), 0 10px 10px -5px rgba(0, 0, 0, 0.03);
            border-color: var(--border-hover, var(--border));
        }
        
        .stat-card:hover::before { opacity: 0.25; }

        /* Card Variants */
        .card-users { --glow-color: var(--accent); --border-hover: rgba(37, 99, 235, 0.3); }
        .card-success { --glow-color: var(--success); --border-hover: rgba(22, 163, 74, 0.3); }
        .card-sessions { --glow-color: #0ea5e9; --border-hover: rgba(14, 165, 233, 0.3); }
        .card-system { --glow-color: #a855f7; --border-hover: rgba(168, 85, 247, 0.3); }

        .stat-icon {
            width: 56px;
            height: 56px;
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }
        
        .card-users .stat-icon { background: #eff6ff; color: #2563eb; }
        .card-success .stat-icon { background: #f0fdf4; color: #16a34a; }
        .card-sessions .stat-icon { background: #e0f2fe; color: #0284c7; }
        .card-system .stat-icon { background: #f3e8ff; color: #9333ea; }

        .stat-content { flex: 1; min-width: 0; }

        .stat-label {
            font-size: 13px;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 4px;
            letter-spacing: 0.02em;
        }

        .stat-value {
            font-size: 36px;
            font-weight: 800;
            color: var(--text-main);
            line-height: 1.1;
            margin-bottom: 4px;
            letter-spacing: -0.03em;
        }

        .stat-detail {
            font-size: 13px;
            font-weight: 500;
            color: var(--text-muted);
        }

        .charts-row {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 24px;
        }

        @media (max-width: 900px) {
            .charts-row { grid-template-columns: 1fr; }
        }

        .chart-card {
            background: var(--bg-card);
            border-radius: 16px;
            animation: fadeIn 0.6s cubic-bezier(0.16, 1, 0.3, 1);
        }

        .chart-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
        }

        .chart-header h3 {
            font-size: 14px;
            font-weight: 600;
            color: var(--text-main);
            letter-spacing: -0.01em;
        }

        .chart-body {
            padding: 20px 24px 24px;
            height: 280px;
            position: relative;
        }

        .events-row {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
        }

        @media (max-width: 900px) {
            .events-row { grid-template-columns: 1fr; }
        }

        .events-card {
            background: var(--bg-card);
            border-radius: 16px;
            animation: fadeIn 0.7s cubic-bezier(0.16, 1, 0.3, 1);
        }

        .events-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .events-header h3 {
            font-size: 14px;
            font-weight: 600;
            color: var(--text-main);
        }

        .events-link {
            font-size: 12px;
            color: var(--accent);
            text-decoration: none;
            font-weight: 500;
            transition: color 0.2s;
        }

        .events-link:hover { color: var(--accent-hover); }

        .events-list {
            max-height: 320px;
            overflow-y: auto;
        }

        .events-loading {
            padding: 32px;
            text-align: center;
            color: var(--text-muted);
            font-size: 13px;
        }

        .event-item {
            padding: 14px 24px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 14px;
            transition: background 0.2s;
            cursor: pointer;
        }

        .event-item:last-child { border-bottom: none; }
        .event-item:hover { background: var(--bg-card-hover); }

        .event-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            flex-shrink: 0;
        }

        .event-dot.success { background: var(--success); }
        .event-dot.warning { background: var(--warning); }
        .event-dot.error { background: var(--error); }
        .event-dot.info { background: var(--accent); }

        .event-content { flex: 1; min-width: 0; }

        .event-title {
            font-size: 13px;
            font-weight: 500;
            color: var(--text-main);
            margin-bottom: 3px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .event-meta {
            font-size: 11px;
            color: var(--text-muted);
        }

        .event-time {
            font-size: 11px;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
            white-space: nowrap;
        }

        .empty-state {
            padding: 40px 24px;
            text-align: center;
            color: var(--text-muted);
        }

        .empty-state svg {
            width: 48px;
            height: 48px;
            margin-bottom: 12px;
            opacity: 0.5;
        }

        .empty-state-text {
            font-size: 13px;
        }

        @keyframes shimmer {
            0% { background-position: -200px 0; }
            100% { background-position: calc(200px + 100%) 0; }
        }

        .loading-skeleton {
            background: linear-gradient(90deg, var(--bg-card-hover) 0px, #e2e8f0 40px, var(--bg-card-hover) 80px);
            background-size: 200px 100%;
            animation: shimmer 1.5s infinite;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <nav>
        <div class="brand">
            <img src="/static/logo.svg" alt="WS" style="width: 24px;">
            <span class="brand-text">WireShield</span>
        </div>
        <a href="#" class="nav-item active" data-view="dashboard" onclick="app.setView('dashboard')">
            <svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z" /></svg>
            Dashboard
        </a>
        <a href="#" class="nav-item" data-view="users" onclick="app.setView('users')">
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
        <header id="mainHeader">
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

        <!-- Filter Bar (visible for logs views) -->
        <div class="filter-bar" id="filterBar" style="display:none">
            <div class="filter-group">
                <label>Date Range</label>
                <div class="filter-row">
                    <input type="date" id="startDate" onchange="app.applyFilters()">
                    <span style="color:var(--text-muted)">to</span>
                    <input type="date" id="endDate" onchange="app.applyFilters()">
                </div>
            </div>
            <div class="filter-group">
                <select id="clientFilter" onchange="app.applyFilters()">
                    <option value="">All Clients</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Domain</label>
                <input type="text" id="domainFilter" placeholder="Filter domain..." oninput="app.handleFilterDebounce(this.value)">
            </div>
            <button class="btn btn-secondary" onclick="app.clearFilters()">Clear Filters</button>
        </div>

        <div class="content-scroll">
            <!-- Dashboard View -->
            <div id="dashboardView" style="display:none">
                <div class="dashboard-grid">
                    <!-- Stats Row -->
                    <div class="stat-card card-users">
                        <div class="stat-icon">
                            <svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" /></svg>
                        </div>
                        <div class="stat-content">
                            <div class="stat-label">Total Users</div>
                            <div class="stat-value" id="statUsers">-</div>
                            <div class="stat-detail" id="statUsersDetail">Loading...</div>
                        </div>
                    </div>
                    <div class="stat-card card-success">
                        <div class="stat-icon">
                            <svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
                        </div>
                        <div class="stat-content">
                            <div class="stat-label">2FA Success Rate</div>
                            <div class="stat-value" id="stat2FA">-</div>
                            <div class="stat-detail" id="stat2FADetail">Last 24 hours</div>
                        </div>
                    </div>
                    <div class="stat-card card-sessions clickable" onclick="app.setView('users')">
                        <div class="stat-icon">
                            <svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" /></svg>
                        </div>
                        <div class="stat-content">
                            <div class="stat-label">Active Sessions</div>
                            <div class="stat-value" id="statSessions">-</div>
                            <div class="stat-detail" id="statSessionsDetail">Currently active</div>
                        </div>
                    </div>
                    <div class="stat-card card-system">
                        <div class="stat-icon">
                            <svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                        </div>
                        <div class="stat-content">
                            <div class="stat-label">System Status</div>
                            <div class="stat-value" id="statStatus">-</div>
                            <div class="stat-detail" id="statStatusDetail">Checking...</div>
                        </div>
                    </div>
                </div>

                <!-- Charts Row -->
                <div class="charts-row">
                    <div class="card chart-card">
                        <div class="chart-header">
                            <h3>Activity Trend (Last 7 Days)</h3>
                        </div>
                        <div class="chart-body">
                            <canvas id="activityChart"></canvas>
                        </div>
                    </div>
                    <div class="card chart-card">
                        <div class="chart-header">
                            <h3>Action Distribution</h3>
                        </div>
                        <div class="chart-body">
                            <canvas id="actionChart"></canvas>
                        </div>
                    </div>
                </div>



                <!-- Bandwidth Chart (Full Width) -->
                <div class="card chart-card" style="margin-bottom: 24px;">
                    <div class="chart-header">
                        <h3>Bandwidth Usage (Last 30 Days)</h3>
                    </div>
                    <div class="chart-body">
                        <canvas id="bandwidthChart" style="max-height: 300px;"></canvas>
                    </div>
                </div>

                <!-- Recent Events Row -->
                <div class="events-row">
                    <div class="card events-card">
                        <div class="events-header">
                            <h3>Recent Security Events</h3>
                            <a href="#" onclick="app.setView('audit'); return false;" class="events-link">View All →</a>
                        </div>
                        <div class="events-list" id="recentAudit">
                            <div class="events-loading">Loading...</div>
                        </div>
                    </div>
                    <div class="card events-card">
                        <div class="events-header">
                            <h3>Latest Traffic</h3>
                            <a href="#" onclick="app.setView('activity'); return false;" class="events-link">View All →</a>
                        </div>
                        <div class="events-list" id="recentActivity">
                            <div class="events-loading">Loading...</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Table View (for other pages) -->
            <div id="tableView">
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
        </div>
    </main>

    <script>
        const app = {
            state: { 
                view: 'dashboard', 
                page: 1, 
                search: '', 
                loading: false, 
                live: false, 
                timer: null,
                dashboardTimer: null,
                startDate: '',
                endDate: '',
                clientFilter: '',
                clients: []
            },
            charts: {
                activity: null,
                action: null,
                bandwidth: null
            },
            headers: {
                users: ['Client ID', 'Role', 'Status', '2FA', 'Active Session', 'IP (Internal)', 'Last Active', 'Created'],
                activity: ['Timestamp', 'Client', 'Direction', 'Protocol', 'Source', 'Destination', 'Domain'],
                audit: ['Timestamp', 'Client', 'Action', 'Status', 'Origin IP']
            },
            
            async init() {
                // Load clients for filter dropdown
                await this.loadClients();
                
                // Initial view
                this.setView(this.state.view);
            },

            async loadClients() {
                try {
                    const res = await fetch('/api/console/users?limit=1000');
                    const data = await res.json();
                    if (data.items) {
                        this.state.clients = data.items;
                        const select = document.getElementById('clientFilter');
                        select.innerHTML = '<option value="">All Clients</option>' + 
                            data.items.map(c => `<option value="${c.client_id}">${c.client_id}</option>`).join('');
                    }
                } catch (e) {
                    console.error('Failed to load clients:', e);
                }
            },

            setView(view) {
                this.state.view = view;
                this.state.page = 1;
                this.state.search = '';
                this.state.live = false;
                this.state.startDate = '';
                this.state.endDate = '';
                this.state.clientFilter = '';
                this.state.domainFilter = '';
                if (this.state.timer) clearInterval(this.state.timer);
                if (this.state.dashboardTimer) clearInterval(this.state.dashboardTimer);
                
                // Destroy existing charts to prevent memory leaks
                if (this.charts.activity) { this.charts.activity.destroy(); this.charts.activity = null; }
                if (this.charts.action) { this.charts.action.destroy(); this.charts.action = null; }
                
                // Update Nav UI
                document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
                const activeLink = document.querySelector(`.nav-item[data-view="${view}"]`);
                if (activeLink) activeLink.classList.add('active');
                
                // Update Header
                const titles = { dashboard: 'Dashboard', users: 'Users & Sessions', activity: 'Activity Logs', audit: 'Audit Logs' };
                document.getElementById('pageTitle').textContent = titles[view];
                document.getElementById('searchInput').value = '';
                
                // Show/Hide Dashboard vs Table View
                const dashboardView = document.getElementById('dashboardView');
                const tableView = document.getElementById('tableView');
                
                if (view === 'dashboard') {
                    dashboardView.style.display = 'block';
                    tableView.style.display = 'none';
                    document.getElementById('mainHeader').style.display = 'none';
                    document.getElementById('filterBar').style.display = 'none';
                    document.getElementById('liveToggle').style.display = 'none';
                    this.loadDashboard();
                    // Auto-refresh dashboard every 30 seconds
                    this.state.dashboardTimer = setInterval(() => this.loadDashboard(), 30000);
                    return;
                }
                
                dashboardView.style.display = 'none';
                tableView.style.display = 'block';
                document.getElementById('mainHeader').style.display = 'flex';
                
                // Show/Hide Filter Bar (only for logs views)
                const filterBar = document.getElementById('filterBar');
                filterBar.style.display = (view === 'activity' || view === 'audit') ? 'flex' : 'none';
                
                // Reset filter inputs
                document.getElementById('startDate').value = '';
                document.getElementById('endDate').value = '';
                document.getElementById('clientFilter').value = '';
                const domFilter = document.getElementById('domainFilter');
                if (domFilter) domFilter.value = '';
                
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

            handleFilterDebounce: (function() {
                let timeout;
                return function(val) {
                    clearTimeout(timeout);
                    timeout = setTimeout(() => {
                        app.applyFilters();
                    }, 500);
                };
            })(),

            applyFilters() {
                this.state.startDate = document.getElementById('startDate').value;
                this.state.endDate = document.getElementById('endDate').value;
                this.state.clientFilter = document.getElementById('clientFilter').value;
                this.state.domainFilter = document.getElementById('domainFilter') ? document.getElementById('domainFilter').value : '';
                this.state.page = 1;
                this.loadData();
            },

            clearFilters() {
                document.getElementById('startDate').value = '';
                document.getElementById('endDate').value = '';
                document.getElementById('clientFilter').value = '';
                if(document.getElementById('domainFilter')) document.getElementById('domainFilter').value = '';
                this.state.startDate = '';
                this.state.endDate = '';
                this.state.clientFilter = '';
                this.state.domainFilter = '';
                this.state.page = 1;
                this.loadData();
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
                    // Map views to API endpoints
                    const endpoints = {
                        'users': 'users',
                        'activity': 'activity-logs',
                        'audit': 'audit-logs'
                    };
                    let url = `/api/console/${endpoints[this.state.view]}?page=${page}`;
                    if (this.state.search) url += `&search=${encodeURIComponent(this.state.search)}`;
                    if (this.state.startDate) url += `&start_date=${this.state.startDate}`;
                    if (this.state.endDate) url += `&end_date=${this.state.endDate}`;
                    if (this.state.clientFilter) url += `&client_filter=${encodeURIComponent(this.state.clientFilter)}`;
                    if (this.state.domainFilter) url += `&domain_filter=${encodeURIComponent(this.state.domainFilter)}`;
                    
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
                    // Role Badge
                    const roleBadge = row.console_access ? 
                        '<span class="badge" style="background:#dbeafe; color:#1e40af">Admin</span>' : 
                        '<span class="badge" style="background:#f1f5f9; color:#475569">VPN User</span>';
                        
                    // 2FA Badge
                    const twofaBadge = row.totp_secret ? 
                        '<span class="badge success">Enabled</span>' : 
                        '<span class="badge warning">Not Setup</span>';

                    return `
                        <tr>
                            <td class="mono" style="font-weight:600">${row.client_id}</td>
                            <td>${roleBadge}</td>
                            <td><span class="badge ${row.enabled ? 'success' : 'warning'}">${row.enabled ? 'Active' : 'Disabled'}</span></td>
                            <td>${twofaBadge}</td>
                            <td class="mono" style="font-weight:600; color: ${row.active_duration !== '-' ? 'var(--accent)' : 'var(--text-muted)'}">${row.active_duration}</td>
                            <td class="mono" style="color:var(--text-muted)">${row.wg_ipv4 || '-'}<br>${row.wg_ipv6 || ''}</td>
                            <td style="color:var(--text-muted)">${row.updated_at}</td>
                            <td class="mono" style="color:var(--text-muted); font-size:11px">${row.created_at || '-'}</td>
                        </tr>`;
                }
                if (this.state.view === 'activity') {
                    const dirClass = row.direction === 'IN' ? 'success' : 'warning';
                    return `
                        <tr>
                            <td class="mono" style="color:var(--accent); white-space:nowrap">${row.timestamp}</td>
                            <td class="mono" style="font-weight:600">${row.client_id || 'System'}</td>
                            <td><span class="badge ${dirClass}">${row.direction || '-'}</span></td>
                            <td class="mono">${row.protocol || '-'}</td>
                            <td class="mono" style="font-size:11px">${row.src_ip || '-'}${row.src_port ? ':' + row.src_port : ''}</td>
                            <td class="mono" style="font-size:11px">${row.dst_ip || '-'}${row.dst_port ? ':' + row.dst_port : ''}</td>
                            <td class="mono" style="font-size:11px; color:var(--text-secondary)">${row.dst_domain && row.dst_domain !== '-' ? row.dst_domain : '-'}</td>
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
            },

            // ============ Dashboard Methods ============
            async loadDashboard() {
                await Promise.all([
                    this.loadDashboardStats(),
                    this.loadDashboardCharts(),
                    this.loadBandwidthChart()
                ]);
            },

            async loadDashboardStats() {
                try {
                    const res = await fetch('/api/console/dashboard-stats');
                    const data = await res.json();
                    
                    // Update stat cards
                    document.getElementById('statUsers').textContent = data.users.total;
                    document.getElementById('statUsersDetail').textContent = data.users.detail;
                    
                    document.getElementById('stat2FA').textContent = data.twofa.success_rate + '%';
                    document.getElementById('stat2FADetail').textContent = data.twofa.detail;
                    
                    document.getElementById('statSessions').textContent = data.sessions.active;
                    document.getElementById('statSessionsDetail').textContent = data.sessions.detail;
                    
                    document.getElementById('statStatus').textContent = data.system.status;
                    document.getElementById('statStatusDetail').textContent = data.system.detail;
                } catch (e) {
                    console.error('Failed to load dashboard stats:', e);
                }
            },

            async loadDashboardCharts() {
                try {
                    const res = await fetch('/api/console/dashboard-charts');
                    const data = await res.json();
                    
                    // Initialize or update Activity Trend Chart
                    this.renderActivityChart(data.activity_trend);
                    
                    // Initialize or update Action Distribution Chart
                    this.renderActionChart(data.action_distribution);
                    
                    // Render Lists
                    this.renderRecentEvents(data.recent_events);
                    this.renderLatestTraffic(data.latest_traffic);
                    
                } catch (e) {
                    console.error('Failed to load dashboard charts:', e);
                }
            },

            async loadBandwidthChart() {
                try {
                    const res = await fetch('/api/console/bandwidth-usage');
                    const data = await res.json();
                    
                    const ctx = document.getElementById('bandwidthChart').getContext('2d');
                    if (this.charts.bandwidth) {
                        this.charts.bandwidth.destroy();
                    }
                    
                    // Colors for datasets
                    const colors = [
                        { bg: 'rgba(37, 99, 235, 0.7)', border: '#2563eb' }, // Blue
                        { bg: 'rgba(22, 163, 74, 0.7)', border: '#16a34a' }, // Green
                        { bg: 'rgba(219, 39, 119, 0.7)', border: '#db2777' }, // Pink
                        { bg: 'rgba(147, 51, 234, 0.7)', border: '#9333ea' }, // Purple
                        { bg: 'rgba(234, 88, 12, 0.7)', border: '#ea580c' }, // Orange
                    ];

                    const datasets = data.datasets.map((ds, index) => {
                        const color = colors[index % colors.length];
                        return {
                            label: ds.label,
                            data: ds.data.map(val => parseFloat(val.toFixed(4))), // 4 decimals for GB
                            backgroundColor: color.bg,
                            borderColor: color.border,
                            borderWidth: 1,
                            borderRadius: 4,
                            barPercentage: 0.6,
                        };
                    });

                    this.charts.bandwidth = new Chart(ctx, {
                        type: 'bar',
                        data: {
                            labels: data.dates,
                            datasets: datasets
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                x: { 
                                    stacked: true,
                                    grid: { display: false }
                                },
                                y: { 
                                    stacked: true,
                                    beginAtZero: true,
                                    title: { display: true, text: 'Usage (GB)' },
                                    grid: { borderDash: [2, 2] }
                                }
                            },
                            plugins: {
                                tooltip: {
                                    mode: 'index',
                                    intersect: false,
                                    callbacks: {
                                        label: function(context) {
                                            let label = context.dataset.label || '';
                                            if (label) {
                                                label += ': ';
                                            }
                                            if (context.parsed.y !== null) {
                                                label += context.parsed.y + ' GB';
                                            }
                                            return label;
                                        }
                                    }
                                }
                            }
                        }
                    });

                } catch (e) {
                    console.error('Failed to load bandwidth chart:', e);
                }
            },

            renderActivityChart(trendData) {
                const ctx = document.getElementById('activityChart').getContext('2d');
                const labels = trendData.map(d => d.label);
                const values = trendData.map(d => d.count);
                
                if (this.charts.activity) {
                    // Update existing chart
                    this.charts.activity.data.labels = labels;
                    this.charts.activity.data.datasets[0].data = values;
                    this.charts.activity.update();
                    return;
                }
                
                this.charts.activity = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Events',
                            data: values,
                            borderColor: '#2563eb',
                            backgroundColor: 'rgba(37, 99, 235, 0.1)',
                            borderWidth: 3,
                            fill: true,
                            tension: 0.4,
                            pointRadius: 4,
                            pointHoverRadius: 6,
                            pointBackgroundColor: '#2563eb',
                            pointBorderColor: '#fff',
                            pointBorderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                backgroundColor: '#0f172a',
                                titleFont: { family: 'Inter', size: 12 },
                                bodyFont: { family: 'Inter', size: 11 },
                                padding: 12,
                                cornerRadius: 8
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                grid: { color: '#e2e8f0' },
                                ticks: { font: { family: 'Inter', size: 11 }, color: '#64748b' }
                            },
                            x: {
                                grid: { display: false },
                                ticks: { font: { family: 'Inter', size: 11 }, color: '#64748b' }
                            }
                        },
                        interaction: { mode: 'index', intersect: false }
                    }
                });
            },

            renderActionChart(actionData) {
                const ctx = document.getElementById('actionChart').getContext('2d');
                const labels = actionData.map(d => d.action.replace('_', ' '));
                const values = actionData.map(d => d.count);
                const colors = ['#2563eb', '#16a34a', '#ca8a04', '#dc2626', '#8b5cf6', '#ec4899'];
                
                if (this.charts.action) {
                    this.charts.action.data.labels = labels;
                    this.charts.action.data.datasets[0].data = values;
                    this.charts.action.update();
                    return;
                }
                
                this.charts.action = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: values,
                            backgroundColor: colors.slice(0, values.length),
                            borderWidth: 0,
                            hoverOffset: 6
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        cutout: '65%',
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: {
                                    font: { family: 'Inter', size: 11 },
                                    color: '#64748b',
                                    padding: 16,
                                    usePointStyle: true,
                                    pointStyle: 'circle'
                                }
                            },
                            tooltip: {
                                backgroundColor: '#0f172a',
                                titleFont: { family: 'Inter', size: 12 },
                                bodyFont: { family: 'Inter', size: 11 },
                                padding: 12,
                                cornerRadius: 8
                            }
                        }
                    }
                });
            },

            renderRecentEvents(events) {
                const container = document.getElementById('recentAudit');
                if (!events || events.length === 0) {
                    container.innerHTML = `
                        <div class="empty-state">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                            <div class="empty-state-text">No recent events</div>
                        </div>`;
                    return;
                }
                
                container.innerHTML = events.map(e => {
                    const dotClass = (e.status === 'success' || e.status === 'granted') ? 'success' : 
                                     (e.status === 'failed' || e.status === 'denied') ? 'error' : 'info';
                    const time = e.timestamp ? e.timestamp.split(' ')[1] || e.timestamp : '';
                    return `
                        <div class="event-item" onclick="app.setView('audit')">
                            <div class="event-dot ${dotClass}"></div>
                            <div class="event-content">
                                <div class="event-title">${e.action} - ${e.client_id}</div>
                                <div class="event-meta">${e.status} • ${e.ip_address}</div>
                            </div>
                            <div class="event-time">${time}</div>
                        </div>`;
                }).join('');
            },

            renderLatestTraffic(traffic) {
                const container = document.getElementById('recentActivity');
                if (!traffic || traffic.length === 0) {
                    container.innerHTML = `
                        <div class="empty-state">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                            <div class="empty-state-text">No recent traffic</div>
                        </div>`;
                    return;
                }
                
                container.innerHTML = traffic.map(t => {
                    const dotClass = t.direction === 'IN' ? 'success' : 'warning';
                    return `
                        <div class="event-item" onclick="app.setView('activity')">
                            <div class="event-dot ${dotClass}"></div>
                            <div class="event-content">
                                <div class="event-title">${t.client} - ${t.direction}</div>
                                <div class="event-meta">${t.details}</div>
                            </div>
                            <div class="event-time">${t.time}</div>
                        </div>`;
                }).join('');
            },

            viewSecurityAlerts() {
                this.setView('audit');
                const searchInput = document.getElementById('searchInput');
                searchInput.value = 'failed';
                this.handleSearch('failed');
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
    start_date: str = None,
    end_date: str = None,
    client_filter: str = None,
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
    start_date: str = None,
    end_date: str = None,
    client_filter: str = None,
    domain_filter: str = None,
    client_id: str = Depends(_check_console_access)
):
    """Fetch WireGuard/iptables kernel logs via journalctl with enhanced parsing."""
    import re
    import socket
    import asyncio
    from datetime import datetime
    
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
                "dst_port": None,
                "details": msg[:100] if len(msg) > 100 else msg
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
                if not entry["client_id"] and entry["dst_ip"] in ip_to_client:
                    entry["client_id"] = ip_to_client[entry["dst_ip"]]
            
            # Apply client filter
            if client_filter and entry["client_id"] != client_filter:
                continue

            # Apply domain filter (requires DB lookup)
            if domain_filter:
                try:
                    # Quick check: does this dst_ip map to the requested domain?
                    # We can't do this efficiently in batch inside the loop easily without pre-fetching.
                    # Optimization: Pre-fetch filtering logic is better, but cache lookup is fast.
                    conn = get_db()
                    c = conn.cursor()
                    # Check if IP maps to a domain containing the filter string
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
                            item['dst_domain'] = row[0]
                            return item
                    except Exception:
                        pass
                        
                    # 2. Fallback to Reverse DNS
                    loop = asyncio.get_running_loop()
                    # Run blocking socket call in executor
                    domain_info = await loop.run_in_executor(None, socket.gethostbyaddr, item['dst_ip'])
                    item['dst_domain'] = domain_info[0]
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
            "items": page_items,
            "page": page,
            "pages": math.ceil(total / limit) if limit > 0 else 1,
            "total": total
        }
        
    except Exception as e:
        logger.error(f"Failed to fetch logs: {e}")
        return {"items": [], "page": 1, "pages": 0, "total": 0}

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
        
        c.execute("SELECT COUNT(*) FROM users WHERE console_access = 1")
        admin_users = c.fetchone()[0]
        
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
        
        total_2fa = successful_2fa + failed_2fa
        success_rate = round((successful_2fa / total_2fa * 100), 1) if total_2fa > 0 else 100.0
        
        # --- Security Alerts (Failed attempts in last 24h) ---
        c.execute("""
            SELECT COUNT(*) FROM audit_log 
            WHERE status IN ('failed', 'denied') AND timestamp >= ?
        """, (yesterday,))
        security_alerts = c.fetchone()[0]
        
        conn.close()
        
        # --- System Status (Check WireGuard) ---
        system_status = "Operational"
        status_detail = "All systems running"
        try:
            wg_check = subprocess.run(["wg", "show"], capture_output=True, text=True, timeout=5)
            if wg_check.returncode != 0:
                system_status = "Degraded"
                status_detail = "WireGuard offline"
        except Exception:
            system_status = "Unknown"
            status_detail = "Cannot verify"
        
        return {
            "users": {
                "total": total_users,
                "active": active_users,
                "admins": admin_users,
                "detail": f"{active_users} active, {admin_users} admins"
            },
            "sessions": {
                "active": active_sessions,
                "detail": f"{active_sessions} active sessions"
            },
            "twofa": {
                "success_rate": success_rate,
                "successful": successful_2fa,
                "failed": failed_2fa,
                "total": total_2fa,
                "detail": f"{successful_2fa}/{total_2fa} successful"
            },
            "alerts": {
                "count": security_alerts,
                "detail": f"{security_alerts} in last 24h"
            },
            "system": {
                "status": system_status,
                "detail": status_detail
            }
        }
    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {e}")
        return {
            "users": {"total": 0, "active": 0, "admins": 0, "detail": "Error loading"},
            "sessions": {"active": 0, "detail": "Error loading"},
            "twofa": {"success_rate": 0, "successful": 0, "failed": 0, "total": 0, "detail": "Error loading"},
            "alerts": {"count": 0, "detail": "Error loading"},
            "system": {"status": "Error", "detail": "Failed to load stats"}
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

        # Structure: { dates: [d1, d2], datasets: [{label: c1, data: [...]}] }
        data_map = {} # date -> { client: total_gb }
        clients = set()
        dates = set()

        for r in rows:
            date_str = r['scan_date']
            client = r['client_id']
            # Convert bytes to GB. 1 GB = 1024^3 bytes
            # Sum RX (Download) + TX (Upload) for total usage
            total_bytes = (r['rx_bytes'] or 0) + (r['tx_bytes'] or 0)
            total_gb = total_bytes / (1024**3)
            
            if date_str not in data_map: data_map[date_str] = {}
            data_map[date_str][client] = total_gb
            clients.add(client)
            dates.add(date_str)
        
        sorted_dates = sorted(list(dates))
        datasets = []
        
        for client in sorted(list(clients)):
            data_points = []
            for d in sorted_dates:
                # Get usage for this date, default 0
                val = data_map.get(d, {}).get(client, 0)
                data_points.append(val)
            datasets.append({'label': client, 'data': data_points})
            
        return {'dates': sorted_dates, 'datasets': datasets}
    except Exception as e:
        logger.error(f"Bandwidth API error: {e}")
        return {'dates': [], 'datasets': []}

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
                "date": date,
                "label": (datetime.utcnow() - timedelta(days=i)).strftime("%a"),
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
            "status": row[2],
            "ip_address": row[3],
            "timestamp": row[4]
        } for row in c.fetchall()]
        
        conn.close()
        
        # --- Latest Traffic (from journalctl) ---
        latest_traffic = []
        try:
            cmd = ["journalctl", "-k", "-n", "100", "--output=short-iso", "--no-pager"]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5)
            lines = proc.stdout.strip().splitlines()
            
            # Filter for WireGuard/WS-Audit related
            wg_lines = [l for l in lines if "wireguard:" in l or "WS-Audit" in l]
            wg_lines.reverse()
            
            # Load IP mapping
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
            
            for line in wg_lines[:8]:
                parts = line.split(" ", 3)
                ts_raw = parts[0] if parts else ""
                msg = parts[3] if len(parts) > 3 else line
                
                # Parse timestamp
                ts = ts_raw
                try:
                    if 'T' in ts_raw:
                        dt = datetime.fromisoformat(ts_raw.replace('Z', '+00:00'))
                        ts = dt.strftime("%H:%M:%S")
                except Exception:
                    pass
                
                # Extract source IP
                src_match = re.search(r'SRC=(\S+)', msg)
                src_ip = src_match.group(1) if src_match else None
                client = ip_to_client.get(src_ip, "Unknown")
                
                # Extract direction
                in_match = re.search(r'IN=(\S*)', msg)
                direction = "IN" if in_match and in_match.group(1) else "OUT"
                
                latest_traffic.append({
                    "time": ts,
                    "client": client,
                    "direction": direction,
                    "details": msg[:60] + "..." if len(msg) > 60 else msg
                })
        except Exception as e:
            logger.error(f"Error fetching traffic: {e}")
        
        return {
            "activity_trend": activity_trend,
            "action_distribution": actions,
            "recent_events": recent_events,
            "latest_traffic": latest_traffic
        }
    except Exception as e:
        logger.error(f"Error fetching dashboard charts: {e}")
        return {
            "activity_trend": [],
            "action_distribution": [],
            "recent_events": [],
            "latest_traffic": []
        }

