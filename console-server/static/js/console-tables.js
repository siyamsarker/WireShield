// console-tables.js — Table-related functions

// Filter data storage
let allAuditLogs = [];
let allActivityLogs = [];

async function loadUsers(page = 1) {
    try {
        usersPage = page;
        const tbody = document.getElementById('users-table');
        renderLoadingSkeleton(tbody, 8);

        const response = await fetch(`/api/console/users?page=${page}&limit=20`, { cache: 'no-store' });
        const data = await response.json();
        usersPages = data.pages || 1;

        if (!data.users || data.users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:40px;">No users found</td></tr>';
            renderPagination('users-pagination', usersPage, usersPages, `loadUsers(${usersPage - 1})`, `loadUsers(${usersPage + 1})`);
            return;
        }

        tbody.innerHTML = data.users.map(user => `
            <tr>
                <td>${user.client_id || user.id || 'Unknown'}</td>
                <td>${user.wg_ipv4 || user.ipv4 || 'N/A'}</td>
                <td>${user.wg_ipv6 || user.ipv6 || 'N/A'}</td>
                <td>
                    <span style="color: ${user.session_status === 'Active' ? 'var(--success)' : 'var(--text-muted)'}; font-weight: 600;">
                        ${user.session_status || 'Offline'}
                    </span>
                </td>
                <td>${user.active_duration || '-'}</td>
                <td>
                    <span style="color: ${user.totp_secret ? 'var(--success)' : 'var(--error)'}; font-weight: 600;">
                        ${user.totp_secret ? 'Enabled' : 'Not set'}
                    </span>
                </td>
                <td>
                    <span style="color: ${user.console_access ? 'var(--success)' : 'var(--text-muted)'}; font-weight: 600;">
                        ${user.console_access ? 'Granted' : 'Restricted'}
                    </span>
                </td>
                <td>${new Date(user.created_at).toLocaleString()}</td>
            </tr>
        `).join('');

        renderPagination('users-pagination', usersPage, usersPages, `loadUsers(${usersPage - 1})`, `loadUsers(${usersPage + 1})`);
    } catch (error) {
        console.error('Error loading users:', error);
        document.getElementById('users-table').innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--error);padding:40px;">Error loading users</td></tr>';
        renderPagination('users-pagination', 1, 1, '', '');
    }
}

async function loadAuditLogs(page = 1) {
    try {
        auditPage = page;
        const tbody = document.getElementById('audit-logs');
        renderLoadingSkeleton(tbody, 5);

        const searchTerm = document.getElementById('audit-search').value.trim();
        const userFilter = document.getElementById('audit-user-filter')?.value || 'all';
        const dateFrom = document.getElementById('audit-date-from').value;
        const dateTo = document.getElementById('audit-date-to').value;
        const params = new URLSearchParams({
            page: String(page),
            limit: '30'
        });
        if (searchTerm) params.append('search', searchTerm);
        if (userFilter && userFilter !== 'all') params.append('client_filter', userFilter);
        if (dateFrom) params.append('start_date', dateFrom);
        if (dateTo) params.append('end_date', dateTo);

        const response = await fetch(`/api/console/audit-logs?${params.toString()}`, { cache: 'no-store' });
        const data = await response.json();
        auditPages = data.pages || 1;

        // Store logs for filtering
        allAuditLogs = data.logs || [];

        // Display logs
        applyAuditFilters();

        renderPagination('audit-pagination', auditPage, auditPages, `loadAuditLogs(${auditPage - 1})`, `loadAuditLogs(${auditPage + 1})`);
    } catch (error) {
        console.error('Error loading audit logs:', error);
        document.getElementById('audit-logs').innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--error);padding:40px;">Error loading audit logs</td></tr>';
        renderPagination('audit-pagination', 1, 1, '', '');
    }
}

async function loadActivityLogs(page = 1) {
    try {
        activityPage = page;
        const tbody = document.getElementById('activity-logs');
        renderLoadingSkeleton(tbody, 4);

        const searchTerm = document.getElementById('activity-search').value.trim();
        const userFilter = document.getElementById('activity-user-filter')?.value || 'all';
        const dateFrom = document.getElementById('activity-date-from').value;
        const dateTo = document.getElementById('activity-date-to').value;
        const params = new URLSearchParams({
            page: String(page),
            limit: '30'
        });
        if (searchTerm) params.append('search', searchTerm);
        if (userFilter && userFilter !== 'all') params.append('client_filter', userFilter);
        if (dateFrom) params.append('start_date', dateFrom);
        if (dateTo) params.append('end_date', dateTo);

        const response = await fetch(`/api/console/activity-logs?${params.toString()}`, { cache: 'no-store' });
        const data = await response.json();
        activityPages = data.pages || 1;

        // Store logs for filtering
        allActivityLogs = (data.logs || []).map(log => {
            // Format connection details
            let details = '';
            if (log.direction === 'OUT' || log.direction === 'IN') {
                const proto = log.protocol || 'TCP';
                const srcInfo = log.src_ip + (log.src_port ? ':' + log.src_port : '');
                // Show domain if available, with IP in parentheses for context
                let dstInfo;
                if (log.dst_domain && log.dst_domain !== '-' && log.dst_domain !== log.dst_ip) {
                    // Domain available and different from IP - show both
                    dstInfo = log.dst_domain;
                } else {
                    // No domain or domain is same as IP - just show IP
                    dstInfo = log.dst_ip || '-';
                }
                dstInfo += (log.dst_port ? ':' + log.dst_port : '');
                details = `${srcInfo} → ${dstInfo} (${proto})`;
            } else {
                details = log.dst_ip || '-';
            }
            return {
                ...log,
                details: details,
                direction: log.direction ? log.direction.toLowerCase() : 'n/a'
            };
        });

        // Display logs
        applyActivityFilters();

        renderPagination('activity-pagination', activityPage, activityPages, `loadActivityLogs(${activityPage - 1})`, `loadActivityLogs(${activityPage + 1})`);
    } catch (error) {
        console.error('Error loading activity logs:', error);
        document.getElementById('activity-logs').innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--error);padding:40px;">Error loading activity logs</td></tr>';
        renderPagination('activity-pagination', 1, 1, '', '');
    }
}

function applyAuditFilters() {
    const searchTerm = document.getElementById('audit-search').value.toLowerCase();
    const userFilter = document.getElementById('audit-user-filter').value;
    const statusFilter = document.getElementById('audit-status-filter').value;
    const dateFrom = document.getElementById('audit-date-from').value;
    const dateTo = document.getElementById('audit-date-to').value;

    const filtered = allAuditLogs.filter(log => {
        const matchesSearch = !searchTerm ||
            (log.client_id && log.client_id.toLowerCase().includes(searchTerm)) ||
            (log.action && log.action.toLowerCase().includes(searchTerm)) ||
            (log.ip_address && log.ip_address.toLowerCase().includes(searchTerm));

        const matchesStatus = statusFilter === 'all' ||
            (log.status && log.status.toLowerCase() === statusFilter);

        const matchesUser = userFilter === 'all' || (log.client_id && log.client_id === userFilter);

        const matchesDate = isWithinDateRange(log.timestamp, dateFrom, dateTo);

        return matchesSearch && matchesStatus && matchesUser && matchesDate;
    });

    displayAuditLogs(filtered);
}

function applyActivityFilters() {
    const searchTerm = document.getElementById('activity-search').value.toLowerCase();
    const userFilter = document.getElementById('activity-user-filter').value;
    const directionFilter = document.getElementById('activity-direction-filter').value;
    const dateFrom = document.getElementById('activity-date-from').value;
    const dateTo = document.getElementById('activity-date-to').value;

    const filtered = allActivityLogs.filter(log => {
        const matchesSearch = !searchTerm ||
            (log.client_id && log.client_id.toLowerCase().includes(searchTerm)) ||
            (log.details && log.details.toLowerCase().includes(searchTerm)) ||
            (log.direction && log.direction.toLowerCase().includes(searchTerm));

        const logDir = log.direction ? log.direction.toLowerCase() : '';
        const matchesDirection = directionFilter === 'all' ||
            (directionFilter === 'in' && (logDir === 'in')) ||
            (directionFilter === 'out' && (logDir === 'out'));

        const matchesUser = userFilter === 'all' || (log.client_id && log.client_id === userFilter);

        const matchesDate = isWithinDateRange(log.timestamp, dateFrom, dateTo);

        return matchesSearch && matchesDirection && matchesUser && matchesDate;
    });

    displayActivityLogs(filtered);
}

function displayAuditLogs(logs) {
    const tbody = document.getElementById('audit-logs');
    const countBadge = document.getElementById('audit-count');

    // Update count badge
    if (countBadge) {
        countBadge.textContent = `${logs.length} record${logs.length !== 1 ? 's' : ''}`;
    }

    if (!logs || logs.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5">
                    <div class="empty-state">
                        <div class="empty-state-icon">
                            <svg fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
                                <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                            </svg>
                        </div>
                        <div class="empty-state-title">No audit logs found</div>
                        <div class="empty-state-text">Try adjusting your filters or date range</div>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = logs.map(log => {
        const statusClass = getStatusClass(log.status);
        return `
            <tr>
                <td>
                    <span style="color: var(--text-muted); font-size: 12px;">
                        ${new Date(log.timestamp).toLocaleString()}
                    </span>
                </td>
                <td>
                    <span style="font-weight: 600;">${log.client_id || 'System'}</span>
                </td>
                <td>${log.action}</td>
                <td>
                    <span class="status-pill ${statusClass}">
                        ${log.status}
                    </span>
                </td>
                <td>
                    <span style="font-family: monospace; font-size: 12px;">${log.ip_address}</span>
                </td>
            </tr>
        `;
    }).join('');
}

function displayActivityLogs(logs) {
    const tbody = document.getElementById('activity-logs');
    const countBadge = document.getElementById('activity-count');

    // Update count badge
    if (countBadge) {
        countBadge.textContent = `${logs.length} record${logs.length !== 1 ? 's' : ''}`;
    }

    if (!logs || logs.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4">
                    <div class="empty-state">
                        <div class="empty-state-icon">
                            <svg fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
                                <path d="M13 10V3L4 14h7v7l9-11h-7z"/>
                            </svg>
                        </div>
                        <div class="empty-state-title">No traffic activity found</div>
                        <div class="empty-state-text">Try adjusting your filters or enable live mode</div>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = logs.map(log => {
        const isInbound = log.direction === 'in';
        return `
            <tr>
                <td>
                    <span style="color: var(--text-muted); font-size: 12px;">
                        ${new Date(log.timestamp).toLocaleString()}
                    </span>
                </td>
                <td>
                    <span style="font-weight: 600;">${log.client_id || 'Unknown'}</span>
                </td>
                <td>
                    <span class="direction-badge ${isInbound ? 'inbound' : 'outbound'}">
                        ${isInbound ? `
                            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                <path d="M19 14l-7 7m0 0l-7-7m7 7V3"/>
                            </svg>
                        ` : `
                            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                <path d="M5 10l7-7m0 0l7 7m-7-7v18"/>
                            </svg>
                        `}
                        ${log.direction ? log.direction.toUpperCase() : 'N/A'}
                    </span>
                </td>
                <td>
                    <span style="font-family: monospace; font-size: 12px;">${log.details}</span>
                </td>
            </tr>
        `;
    }).join('');
}

function reloadAuditLogs() {
    loadAuditLogs(1);
}

function reloadActivityLogs() {
    loadActivityLogs(1);
}
