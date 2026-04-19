// console-tables.js — Table-related functions

// Filter data storage
let allAuditLogs = [];
let allActivityLogs = [];

function _usersEscape(s) {
    if (s === null || s === undefined) return '';
    return String(s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

async function loadUsers(page = 1) {
    try {
        usersPage = page;
        const tbody = document.getElementById('users-table');
        renderLoadingSkeleton(tbody, 9);

        const searchEl = document.getElementById('users-search');
        const searchTerm = searchEl ? searchEl.value.trim() : '';
        const params = new URLSearchParams({ page: String(page), limit: '20' });
        if (searchTerm) params.append('search', searchTerm);

        const response = await fetch(`/api/console/users?${params.toString()}`, { cache: 'no-store' });
        const data = await response.json();
        usersPages = data.pages || 1;

        if (!data.users || data.users.length === 0) {
            tbody.textContent = '';
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 9;
            td.style.cssText = 'text-align:center;color:var(--text-muted);padding:40px;';
            td.textContent = 'No users found';
            tr.appendChild(td);
            tbody.appendChild(tr);
            renderPagination('users-pagination', usersPage, usersPages, `loadUsers(${usersPage - 1})`, `loadUsers(${usersPage + 1})`);
            return;
        }

        const rowsHtml = data.users.map(user => {
            const cidEsc = _usersEscape(user.client_id || user.id || 'Unknown');
            const v4 = _usersEscape(user.wg_ipv4 || user.ipv4 || 'N/A');
            const v6 = _usersEscape(user.wg_ipv6 || user.ipv6 || 'N/A');
            const sessColor = user.session_status === 'Active' ? 'var(--success)' : 'var(--text-muted)';
            const sessText = _usersEscape(user.session_status || 'Offline');
            const durText = _usersEscape(user.active_duration || '-');
            const totpColor = user.totp_secret ? 'var(--success)' : 'var(--error)';
            const totpText = user.totp_secret ? 'Enabled' : 'Not set';
            const consColor = user.console_access ? 'var(--success)' : 'var(--text-muted)';
            const consText = user.console_access ? 'Granted' : 'Restricted';
            const createdText = user.created_at ? new Date(user.created_at).toLocaleString() : '-';
            return `
            <tr>
                <td>${cidEsc}</td>
                <td>${v4}</td>
                <td>${v6}</td>
                <td><span style="color:${sessColor};font-weight:600;">${sessText}</span></td>
                <td>${durText}</td>
                <td><span style="color:${totpColor};font-weight:600;">${totpText}</span></td>
                <td><span style="color:${consColor};font-weight:600;">${consText}</span></td>
                <td>${_usersEscape(createdText)}</td>
                <td style="white-space:nowrap;">
                    <button class="btn btn-ghost" style="padding:4px 8px;font-size:12px;" title="Download WireGuard config"
                        onclick="downloadUserConfig('${cidEsc}')">
                        Config
                    </button>
                    <button class="btn btn-ghost" style="padding:4px 8px;font-size:12px;color:var(--error);margin-left:4px;" title="Revoke client"
                        onclick="revokeUser('${cidEsc}')">
                        Revoke
                    </button>
                </td>
            </tr>`;
        }).join('');

        // All interpolated values are escaped via _usersEscape above. innerHTML is
        // safe here — values sourced from API are run through _usersEscape before
        // being inlined into the template literal.
        tbody.innerHTML = rowsHtml; // eslint-disable-line no-unsanitized/property

        renderPagination('users-pagination', usersPage, usersPages, `loadUsers(${usersPage - 1})`, `loadUsers(${usersPage + 1})`);
    } catch (error) {
        console.error('Error loading users:', error);
        const tbody = document.getElementById('users-table');
        tbody.textContent = '';
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 9;
        td.style.cssText = 'text-align:center;color:var(--error);padding:40px;';
        td.textContent = 'Error loading users';
        tr.appendChild(td);
        tbody.appendChild(tr);
        renderPagination('users-pagination', 1, 1, '', '');
    }
}

function reloadUsers() {
    loadUsers(1);
}

// ── User management actions ──────────────────────────────────────────────────

function downloadUserConfig(clientId) {
    const url = `/api/console/users/${encodeURIComponent(clientId)}/config`;
    fetch(url, { cache: 'no-store' })
        .then(r => {
            if (!r.ok) {
                if (r.status === 404) {
                    return r.json().then(d => { throw new Error(d.detail || 'Config not found'); });
                }
                throw new Error(`HTTP ${r.status}`);
            }
            const disp = r.headers.get('Content-Disposition') || '';
            const m = disp.match(/filename="?([^"]+)"?/);
            const filename = m ? m[1] : `${clientId}.conf`;
            return r.blob().then(blob => ({ blob, filename }));
        })
        .then(({ blob, filename }) => {
            const a = document.createElement('a');
            const blobUrl = URL.createObjectURL(blob);
            a.href = blobUrl;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
        })
        .catch(err => {
            alert(`Download failed: ${err.message}`);
        });
}

function revokeUser(clientId) {
    if (!confirm(`Revoke WireGuard client "${clientId}"?\n\nThis removes the peer from WireGuard, deletes their .conf file, and clears all 2FA sessions. This cannot be undone.`)) {
        return;
    }
    fetch(`/api/console/users/${encodeURIComponent(clientId)}`, {
        method: 'DELETE', cache: 'no-store',
    })
        .then(r => r.json().then(d => ({ ok: r.ok, data: d })))
        .then(({ ok, data }) => {
            if (ok && data.success) {
                loadUsers(usersPage);
            } else {
                alert(`Revoke failed: ${(data && data.detail) || 'Unknown error'}`);
            }
        })
        .catch(err => alert(`Revoke failed: ${err.message}`));
}

// ── Create User Modal ────────────────────────────────────────────────────────

function openCreateUserModal() {
    document.getElementById('new-user-name').value = '';
    document.getElementById('new-user-expiry').value = '';
    document.getElementById('create-user-error').style.display = 'none';
    const successEl = document.getElementById('create-user-success');
    successEl.style.display = 'none';
    while (successEl.firstChild) successEl.removeChild(successEl.firstChild);
    const submitBtn = document.getElementById('create-user-submit-btn');
    submitBtn.disabled = false;
    submitBtn.textContent = 'Create Client';
    submitBtn.onclick = submitCreateUser;
    document.getElementById('create-user-modal').style.display = 'flex';
    setTimeout(() => document.getElementById('new-user-name').focus(), 50);
}

function closeCreateUserModal() {
    document.getElementById('create-user-modal').style.display = 'none';
}

function _showCreateUserError(msg) {
    const el = document.getElementById('create-user-error');
    el.textContent = msg;
    el.style.display = 'block';
    document.getElementById('create-user-success').style.display = 'none';
}

function _renderCreateUserSuccess(data) {
    const successEl = document.getElementById('create-user-success');
    while (successEl.firstChild) successEl.removeChild(successEl.firstChild);

    const box = document.createElement('div');
    box.style.cssText = 'padding:12px;background:var(--success-light);border:1px solid var(--success);border-radius:8px;margin-top:8px;font-size:13px;color:var(--text-main);';

    const header = document.createElement('div');
    header.style.cssText = 'display:flex;align-items:center;gap:6px;font-weight:600;color:var(--success);margin-bottom:6px;';
    header.textContent = '✓ Client created';
    box.appendChild(header);

    function row(label, value, mono) {
        const d = document.createElement('div');
        const l = document.createTextNode(label + ': ');
        d.appendChild(l);
        const v = document.createElement(mono ? 'code' : 'strong');
        v.textContent = value;
        d.appendChild(v);
        return d;
    }
    box.appendChild(row('Name', data.name));
    box.appendChild(row('IPv4', data.ipv4, true));
    box.appendChild(row('IPv6', data.ipv6, true));
    if (data.expires) box.appendChild(row('Expires', data.expires));

    const btn = document.createElement('button');
    btn.className = 'btn btn-primary btn-block';
    btn.style.marginTop = '12px';
    btn.textContent = 'Download .conf file';
    btn.onclick = () => downloadUserConfig(data.name);
    box.appendChild(btn);

    successEl.appendChild(box);
    successEl.style.display = 'block';
}

function submitCreateUser() {
    const name = document.getElementById('new-user-name').value.trim();
    const expiryRaw = document.getElementById('new-user-expiry').value.trim();
    const submitBtn = document.getElementById('create-user-submit-btn');

    if (!name) {
        _showCreateUserError('Client name is required.');
        return;
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
        _showCreateUserError('Client name may only contain letters, digits, underscore, and dash.');
        return;
    }
    if (name.length > 15) {
        _showCreateUserError('Client name must be at most 15 characters.');
        return;
    }

    const payload = { client_id: name };
    if (expiryRaw) {
        const days = parseInt(expiryRaw, 10);
        if (isNaN(days) || days <= 0) {
            _showCreateUserError('Expiry must be a positive number of days.');
            return;
        }
        payload.expiry_days = days;
    }

    document.getElementById('create-user-error').style.display = 'none';
    submitBtn.disabled = true;
    submitBtn.textContent = 'Creating…';

    fetch('/api/console/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        cache: 'no-store',
    })
        .then(r => r.json().then(d => ({ ok: r.ok, data: d })))
        .then(({ ok, data }) => {
            if (!ok || !data.success) {
                _showCreateUserError((data && data.detail) || 'Failed to create client.');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Create Client';
                return;
            }
            _renderCreateUserSuccess(data);
            submitBtn.textContent = 'Done';
            submitBtn.onclick = closeCreateUserModal;
            loadUsers(usersPage);
        })
        .catch(err => {
            _showCreateUserError(`Network error: ${err.message}`);
            submitBtn.disabled = false;
            submitBtn.textContent = 'Create Client';
        });
}

// Escape-key close for the Create User modal
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
        const modal = document.getElementById('create-user-modal');
        if (modal && modal.style.display !== 'none') closeCreateUserModal();
    }
});

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
