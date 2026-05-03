// console-app.js — Core state, routing, utilities, auto-refresh, deduplicated helpers

let activityChart, actionsChart, bandwidthChart;
const autoRefreshState = {
    enabled: false,
    intervalMs: 30000,
    intervalId: null
};

// Pagination state
let usersPage = 1;
let usersPages = 1;
let auditPage = 1;
let auditPages = 1;
let activityPage = 1;
let activityPages = 1;

// ── Navigation ──────────────────────────────────────────────────────────────

function getSectionFromHash() {
    const raw = (window.location.hash || '').replace('#', '').trim();
    const allowed = ['dashboard', 'users', 'agents', 'logs', 'activity', 'bandwidth'];
    return allowed.includes(raw) ? raw : 'dashboard';
}

function showSection(section, event, fromHash = false) {
    if (event) {
        event.preventDefault();
    }

    const allowed = ['dashboard', 'users', 'agents', 'logs', 'activity', 'bandwidth'];
    if (!allowed.includes(section)) {
        section = 'dashboard';
    }

    if (!fromHash) {
        const nextHash = `#${section}`;
        if (window.location.hash !== nextHash) {
            window.location.hash = nextHash;
            return;
        }
    }

    // Hide all sections
    document.querySelectorAll('[id$="-section"]').forEach(el => el.style.display = 'none');

    // Remove active class from nav items
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));

    // Show selected section
    document.getElementById(section + '-section').style.display = 'block';

    // Add active class to clicked nav item
    const clickedItem = event ? event.target.closest('.nav-item') : null;
    if (clickedItem) {
        clickedItem.classList.add('active');
    } else {
        const navItem = document.querySelector(`.nav-item[data-section="${section}"]`);
        if (navItem) {
            navItem.classList.add('active');
        }
    }

    // Update page title
    const titles = {
        'dashboard': 'Overview',
        'users': 'Users & Access',
        'agents': 'Agents',
        'logs': 'Audit Trail',
        'activity': 'Traffic Activity',
        'bandwidth': 'Bandwidth Insights'
    };
    document.getElementById('page-title').textContent = titles[section] || 'Dashboard';

    // Toggle header actions based on section
    const defaultHeaderActions = document.getElementById('default-header-actions');
    const bandwidthHeaderActions = document.getElementById('bandwidth-header-actions');
    const resetViewBtn = document.getElementById('reset-view-btn');

    // Show Reset View button only for logs and activity sections
    if (resetViewBtn) {
        resetViewBtn.style.display = (section === 'logs' || section === 'activity') ? 'flex' : 'none';
    }

    if (section === 'bandwidth') {
        defaultHeaderActions.style.display = 'none';
        bandwidthHeaderActions.style.display = 'flex';
        initBandwidthEvents();
        loadUserFilter('bandwidth-user-filter');
    } else {
        defaultHeaderActions.style.display = 'flex';
        bandwidthHeaderActions.style.display = 'none';
    }

    // Load section data
    if (section === 'users') {
        loadUsers();
    } else if (section === 'agents') {
        if (typeof loadAgents === 'function') loadAgents();
    } else if (section === 'logs') {
        loadUserFilter('audit-user-filter');
        loadAuditLogs();
    } else if (section === 'activity') {
        loadUserFilter('activity-user-filter');
        loadActivityLogs();
    } else if (section === 'bandwidth') {
        loadBandwidthData();
    } else {
        loadDashboardData();
    }

    updateLastRefreshTimestamp();
}

// ── Utility functions ───────────────────────────────────────────────────────

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatBytesAnimated(bytes, decimals = 2) {
    if (bytes === 0) return { value: '0', unit: 'B' };

    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return {
        value: parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)),
        unit: sizes[i]
    };
}

function getStatusColor(status) {
    switch (status.toLowerCase()) {
        case 'success':
        case 'granted':
            return 'var(--success)';
        case 'failed':
        case 'denied':
            return 'var(--error)';
        case 'warning':
            return 'var(--warning)';
        default:
            return 'var(--text-muted)';
    }
}

function getStatusClass(status) {
    const s = (status || '').toLowerCase();
    if (['granted', 'success', 'verified'].includes(s)) return 'granted';
    if (['denied', 'failed', 'error'].includes(s)) return 'denied';
    if (['warning', 'pending'].includes(s)) return 'warning';
    return 'info';
}

function isWithinDateRange(timestamp, fromValue, toValue) {
    if (!fromValue && !toValue) return true;
    const ts = new Date(timestamp);
    if (Number.isNaN(ts.getTime())) return true;

    let fromDate = null;
    let toDate = null;

    if (fromValue) {
        fromDate = new Date(`${fromValue}T00:00:00`);
    }
    if (toValue) {
        toDate = new Date(`${toValue}T23:59:59.999`);
    }

    if (fromDate && ts < fromDate) return false;
    if (toDate && ts > toDate) return false;
    return true;
}

function renderPagination(containerId, page, pages, onPrev, onNext) {
    const container = document.getElementById(containerId);
    if (!container) return;
    if (pages <= 1) {
        container.innerHTML = `
            <div class="pagination-info">
                <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                    <path d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                Single page view
            </div>
            <div class="pagination-pages"></div>
        `;
        return;
    }
    container.innerHTML = `
        <div class="pagination-info">
            <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
            </svg>
            Showing page ${page} of ${pages}
        </div>
        <div class="pagination-pages">
            <button class="pagination-btn" ${page <= 1 ? 'disabled' : ''} onclick="${onPrev}">
                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                    <path d="M15 19l-7-7 7-7"/>
                </svg>
                Previous
            </button>
            <span class="page-indicator"><span>${page}</span> / ${pages}</span>
            <button class="pagination-btn" ${page >= pages ? 'disabled' : ''} onclick="${onNext}">
                Next
                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                    <path d="M9 5l7 7-7 7"/>
                </svg>
            </button>
        </div>
    `;
}

function getActiveSection() {
    const activeSection = document.querySelector('[id$="-section"]:not([style*="none"])');
    if (!activeSection) return getSectionFromHash();
    return activeSection.id.replace('-section', '');
}

function updateLastRefreshTimestamp() {
    const target = document.getElementById('last-refresh-text');
    if (!target) return;
    target.textContent = `Last update: ${new Date().toLocaleTimeString()}`;
}

// ── Auto-refresh ────────────────────────────────────────────────────────────

function setAutoRefreshEnabled(enabled) {
    autoRefreshState.enabled = enabled;

    const defaultToggle = document.getElementById('auto-refresh-toggle-default');
    const bandwidthToggle = document.getElementById('auto-refresh-toggle-bandwidth');
    const defaultContainer = document.getElementById('auto-refresh-toggle-container-default');
    const bandwidthContainer = document.getElementById('auto-refresh-toggle-container-bandwidth');
    const defaultIndicator = document.getElementById('auto-refresh-indicator-default');
    const bandwidthIndicator = document.getElementById('auto-refresh-indicator-bandwidth');

    if (defaultToggle) defaultToggle.checked = enabled;
    if (bandwidthToggle) bandwidthToggle.checked = enabled;

    if (defaultContainer) defaultContainer.classList.toggle('inactive', !enabled);
    if (bandwidthContainer) bandwidthContainer.classList.toggle('inactive', !enabled);

    if (defaultIndicator) defaultIndicator.classList.toggle('active', enabled);
    if (bandwidthIndicator) bandwidthIndicator.classList.toggle('active', enabled);

    if (autoRefreshState.intervalId) {
        clearInterval(autoRefreshState.intervalId);
        autoRefreshState.intervalId = null;
    }

    if (enabled) {
        autoRefreshState.intervalId = setInterval(() => {
            refreshData();
        }, autoRefreshState.intervalMs);
    }
}

function syncAutoRefreshFromHeader(source) {
    const toggle = source === 'bandwidth'
        ? document.getElementById('auto-refresh-toggle-bandwidth')
        : document.getElementById('auto-refresh-toggle-default');

    if (!toggle) return;
    setAutoRefreshEnabled(toggle.checked);
}

function resetCurrentSectionView() {
    const section = getActiveSection();

    if (section === 'users') {
        usersPage = 1;
        loadUsers(1);
    } else if (section === 'logs') {
        const auditSearch = document.getElementById('audit-search');
        const auditFrom = document.getElementById('audit-date-from');
        const auditTo = document.getElementById('audit-date-to');
        const auditStatus = document.getElementById('audit-status-filter');
        const auditUser = document.getElementById('audit-user-filter');
        if (auditSearch) auditSearch.value = '';
        if (auditFrom) auditFrom.value = '';
        if (auditTo) auditTo.value = '';
        if (auditStatus) auditStatus.value = 'all';
        if (auditUser) auditUser.value = 'all';
        loadAuditLogs(1);
    } else if (section === 'activity') {
        const activitySearch = document.getElementById('activity-search');
        const activityFrom = document.getElementById('activity-date-from');
        const activityTo = document.getElementById('activity-date-to');
        const activityDirection = document.getElementById('activity-direction-filter');
        const activityUser = document.getElementById('activity-user-filter');
        if (activitySearch) activitySearch.value = '';
        if (activityFrom) activityFrom.value = '';
        if (activityTo) activityTo.value = '';
        if (activityDirection) activityDirection.value = 'all';
        if (activityUser) activityUser.value = 'all';

        loadActivityLogs(1);
    } else {
        refreshData();
    }

    updateLastRefreshTimestamp();
}

function refreshData() {
    const section = getActiveSection();
    if (section === 'dashboard') {
        loadDashboardData();
    } else if (section === 'users') {
        loadUsers(usersPage);
    } else if (section === 'logs') {
        loadAuditLogs(auditPage);
    } else if (section === 'activity') {
        loadActivityLogs(activityPage);
    } else if (section === 'bandwidth') {
        loadBandwidthData();
    }

    updateLastRefreshTimestamp();
}

// ── Deduplicated helpers ────────────────────────────────────────────────────

// Replaces the 3 duplicate functions: loadBandwidthUserFilter, loadActivityUserFilter, loadAuditUserFilter
function loadUserFilter(selectId, preserveValue = true) {
    fetch('/api/console/users?page=1&limit=100', { cache: 'no-store' })
        .then(response => response.json())
        .then(data => {
            const select = document.getElementById(selectId);
            if (!select) return;

            const currentValue = preserveValue ? (select.value || 'all') : 'all';
            select.innerHTML = '<option value="all">All Users</option>';

            if (data.users && data.users.length > 0) {
                data.users.forEach(user => {
                    const option = document.createElement('option');
                    option.value = user.client_id;
                    option.textContent = user.client_id;
                    select.appendChild(option);
                });
            }

            if ([...select.options].some(opt => opt.value === currentValue)) {
                select.value = currentValue;
            }
        })
        .catch(error => {
            console.error('Error loading user filter:', error);
        });
}

// Replaces repeated loading shimmer HTML in table loading functions
function renderLoadingSkeleton(tbody, cols) {
    tbody.innerHTML = Array.from({ length: 3 }, () =>
        `<tr><td colspan="${cols}"><div class="loading" style="height: 50px; border-radius: 8px;"></div></td></tr>`
    ).join('');
}

// ── DOMContentLoaded ────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function() {
    initBandwidthEvents();
    setAutoRefreshEnabled(false);
    showSection(getSectionFromHash(), null, true);

    window.addEventListener('hashchange', () => {
        showSection(getSectionFromHash(), null, true);
    });

    document.addEventListener('keydown', function(e) {
        if (e.key !== 'Escape') return;
        const closers = [
            ['create-user-modal',  () => typeof closeCreateUserModal  === 'function' && closeCreateUserModal()],
            ['create-agent-modal', () => typeof closeCreateAgentModal === 'function' && closeCreateAgentModal()],
            ['edit-agent-modal',   () => typeof closeEditAgentModal   === 'function' && closeEditAgentModal()],
            ['agent-detail-modal', () => typeof closeAgentDetailModal === 'function' && closeAgentDetailModal()],
            ['agent-access-modal', () => typeof closeAgentAccessModal === 'function' && closeAgentAccessModal()],
        ];
        for (const [id, fn] of closers) {
            const el = document.getElementById(id);
            if (el && el.style.display !== 'none') { fn(); break; }
        }
    });

    // ── WireGuard sidebar status (dynamic) ───────────────────────────────
    (function initWgStatus() {
        const row  = document.getElementById('wg-status-row');
        const text = document.getElementById('wg-status-text');
        if (!row || !text) return;

        function applyState(status) {
            row.classList.remove('wg-down', 'wg-unknown');
            if (status === 'up') {
                text.textContent = 'WireGuard Active';
            } else if (status === 'down') {
                row.classList.add('wg-down');
                text.textContent = 'WireGuard Down';
            } else {
                row.classList.add('wg-unknown');
                text.textContent = status === 'missing' ? 'WireGuard Missing' : 'WireGuard Error';
            }
        }

        function poll() {
            fetch('/api/health', { credentials: 'same-origin' })
                .then(r => r.ok ? r.json() : Promise.reject(r.status))
                .then(d => applyState((d.wireguard || {}).status || 'error'))
                .catch(() => applyState('error'));
        }

        poll();
        setInterval(poll, 30000);
    })();
});
