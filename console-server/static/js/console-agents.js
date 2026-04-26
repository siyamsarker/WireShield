// console-agents.js — Phase 3 Agents tab controller.
//
// All dynamic content is inserted via DOM .textContent / element creation —
// no innerHTML on user-controlled values, anywhere. Static SVG/markup uses
// a one-time template element. Raw enrollment tokens are written only via
// element.textContent and are never re-rendered after the create modal
// closes.

(function () {
    let _agentsCache = [];

    function _formatRelative(iso) {
        if (!iso) return 'never';
        const t = new Date(iso);
        if (isNaN(t.getTime())) return String(iso);
        const diff = (Date.now() - t.getTime()) / 1000;
        if (diff < 5)     return 'just now';
        if (diff < 60)    return `${Math.floor(diff)}s ago`;
        if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    }

    function _formatBytesShort(n) {
        if (!n || n < 1024) return (n || 0) + ' B';
        const units = ['KB', 'MB', 'GB', 'TB'];
        let v = n / 1024;
        for (const u of units) {
            if (v < 1024) return v.toFixed(v < 10 ? 2 : 1) + ' ' + u;
            v /= 1024;
        }
        return v.toFixed(1) + ' PB';
    }

    function _el(tag, opts) {
        const el = document.createElement(tag);
        if (!opts) return el;
        if (opts.cls)   el.className = opts.cls;
        if (opts.text !== undefined) el.textContent = opts.text;
        if (opts.title) el.title = opts.title;
        if (opts.style) el.style.cssText = opts.style;
        if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) el.setAttribute(k, v);
        if (opts.on)    for (const [k, v] of Object.entries(opts.on))    el.addEventListener(k, v);
        return el;
    }

    // Build an inline SVG icon by namespace. The d-paths are hardcoded and
    // never sourced from user input.
    function _svg(paths, size) {
        const ns = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(ns, 'svg');
        svg.setAttribute('width', size || '14');
        svg.setAttribute('height', size || '14');
        svg.setAttribute('viewBox', '0 0 24 24');
        svg.setAttribute('fill', 'none');
        svg.setAttribute('stroke', 'currentColor');
        svg.setAttribute('stroke-width', '2');
        for (const p of paths) {
            const [tag, attrs] = p;
            const node = document.createElementNS(ns, tag);
            for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
            svg.appendChild(node);
        }
        return svg;
    }

    const ICON_INFO    = [['circle', { cx: '12', cy: '12', r: '10' }], ['line', { x1: '12', y1: '16', x2: '12', y2: '12' }], ['line', { x1: '12', y1: '8', x2: '12.01', y2: '8' }]];
    const ICON_EDIT    = [['path', { d: 'M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7' }], ['path', { d: 'M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z' }]];
    const ICON_REFRESH = [['path', { d: 'M3 12a9 9 0 1 0 3.41-7.06L3 8' }], ['path', { d: 'M3 4v4h4' }]];
    const ICON_TRASH   = [['path', { d: 'M3 6h18' }], ['path', { d: 'M19 6l-2 14a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2L5 6' }], ['path', { d: 'M10 11v6M14 11v6' }], ['path', { d: 'M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2' }]];
    const ICON_SHIELD  = [['path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' }]];

    // ── List + render ──────────────────────────────────────────────────────

    async function loadAgents() {
        const tbody = document.getElementById('agents-table');
        if (!tbody) return;
        if (typeof renderLoadingSkeleton === 'function') {
            renderLoadingSkeleton(tbody, 9);
        }
        const includeRevoked = document.getElementById('agents-include-revoked')?.checked ? 'true' : 'false';
        try {
            const r = await fetch(`/api/console/agents?include_revoked=${includeRevoked}`, { cache: 'no-store' });
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            const data = await r.json();
            _agentsCache = Array.isArray(data.agents) ? data.agents : [];
            renderAgents();
        } catch (err) {
            _renderError(tbody, `Failed to load agents: ${err.message}`);
        }
    }

    function _renderError(tbody, msg) {
        while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
        const tr = _el('tr');
        const td = _el('td', { cls: 'agent-table-empty', text: msg, style: 'color:var(--error);' });
        td.colSpan = 9;
        tr.appendChild(td);
        tbody.appendChild(tr);
    }

    function renderAgents() {
        const tbody = document.getElementById('agents-table');
        const summary = document.getElementById('agents-summary');
        if (!tbody) return;
        const term = (document.getElementById('agents-search')?.value || '').trim().toLowerCase();

        let agents = _agentsCache;
        if (term) {
            agents = agents.filter(a => {
                const haystack = [
                    a.name, a.hostname, a.wg_ipv4, a.description,
                    (a.advertised_cidrs || []).join(' '),
                ].join(' ').toLowerCase();
                return haystack.includes(term);
            });
        }

        if (summary) {
            const online = _agentsCache.filter(a => a.online).length;
            const enrolled = _agentsCache.filter(a => a.status === 'enrolled').length;
            summary.textContent = `${_agentsCache.length} total · ${enrolled} enrolled · ${online} online`;
        }

        while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

        if (agents.length === 0) {
            const tr = _el('tr');
            const td = _el('td', {
                cls: 'agent-table-empty',
                text: _agentsCache.length === 0
                    ? 'No agents registered yet. Click "Register Agent" to create one.'
                    : 'No agents match your filters.',
            });
            td.colSpan = 9;
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }

        for (const a of agents) tbody.appendChild(_buildRow(a));
    }

    function _buildRow(a) {
        const tr = _el('tr');

        // Name + description, with online dot for enrolled rows.
        const nameTd = _el('td');
        if (a.status === 'enrolled') {
            nameTd.appendChild(_el('span', {
                cls: 'agent-online-dot' + (a.online ? '' : ' agent-offline-dot'),
            }));
        }
        nameTd.appendChild(_el('strong', { text: a.name || '' }));
        if (a.is_restricted) {
            const pill = _el('span', { cls: 'agent-restricted-pill', title: 'Restricted — only allowlisted users can reach this agent' });
            pill.appendChild(_svg(ICON_SHIELD, 10));
            pill.appendChild(_el('span', { text: 'restricted' }));
            nameTd.appendChild(pill);
        }
        if (a.description) {
            nameTd.appendChild(_el('div', {
                text: a.description,
                style: 'font-size:11px;color:var(--text-muted);margin-top:2px;',
            }));
        }
        tr.appendChild(nameTd);

        // Status pill.
        const statusTd = _el('td');
        statusTd.appendChild(_el('span', {
            cls: `status-pill agent-${a.status || 'pending'}`,
            text: a.status || 'pending',
        }));
        tr.appendChild(statusTd);

        // WG IPv4.
        tr.appendChild(_buildMonoCell(a.wg_ipv4 || '—'));

        // Advertised CIDRs as tag list.
        const cidrTd = _el('td');
        const list = a.advertised_cidrs || [];
        if (list.length === 0) {
            cidrTd.appendChild(_el('span', { cls: 'agent-mono-muted', text: '—' }));
        } else {
            const wrap = _el('div', { cls: 'agent-cidrs-list' });
            for (const c of list) wrap.appendChild(_el('span', { cls: 'agent-cidr-tag', text: c }));
            cidrTd.appendChild(wrap);
        }
        tr.appendChild(cidrTd);

        // Hostname.
        const hostTd = _el('td');
        if (a.hostname) {
            hostTd.textContent = a.hostname;
        } else {
            hostTd.appendChild(_el('span', { cls: 'agent-mono-muted', text: '—' }));
        }
        tr.appendChild(hostTd);

        // Version.
        tr.appendChild(_buildMonoCell(a.agent_version || '—'));

        // Last seen relative.
        tr.appendChild(_el('td', { text: _formatRelative(a.last_seen) }));

        // RX / TX.
        const stTd = _el('td');
        stTd.appendChild(_el('span', { cls: 'agent-mono', text: '↓ ' + _formatBytesShort(a.rx_bytes) }));
        stTd.appendChild(_el('br'));
        stTd.appendChild(_el('span', { cls: 'agent-mono', text: '↑ ' + _formatBytesShort(a.tx_bytes) }));
        tr.appendChild(stTd);

        // Action buttons.
        const actTd = _el('td');
        const actWrap = _el('div', { cls: 'agent-actions' });

        actWrap.appendChild(_actionBtn(ICON_INFO, 'Details', false, () => openAgentDetailModal(a.id)));
        if (a.status === 'enrolled') {
            actWrap.appendChild(_actionBtn(ICON_EDIT, 'Update CIDRs', false, () => openEditAgentModal(a.id)));
            actWrap.appendChild(_actionBtn(ICON_SHIELD, 'Manage Access', false, () => openAgentAccessModal(a.id)));
        }
        if (a.status === 'pending') {
            actWrap.appendChild(_actionBtn(ICON_REFRESH, 'Reissue token', false, () => rotateAgentToken(a.id)));
        }
        if (a.status !== 'revoked') {
            actWrap.appendChild(_actionBtn(ICON_TRASH, 'Revoke agent', true, () => confirmRevokeAgent(a.id, a.name)));
        }
        actTd.appendChild(actWrap);
        tr.appendChild(actTd);

        return tr;
    }

    function _buildMonoCell(text) {
        const td = _el('td');
        td.appendChild(_el('span', { cls: 'agent-mono', text }));
        return td;
    }

    function _actionBtn(iconPaths, title, danger, handler) {
        const btn = _el('button', {
            cls: 'agent-action-btn' + (danger ? ' danger' : ''),
            title,
            attrs: { type: 'button' },
            on: { click: handler },
        });
        btn.appendChild(_svg(iconPaths, 14));
        return btn;
    }

    // ── Create-agent flow ──────────────────────────────────────────────────

    function openCreateAgentModal() {
        document.getElementById('new-agent-name').value = '';
        document.getElementById('new-agent-description').value = '';
        document.getElementById('new-agent-cidrs').value = '';
        document.getElementById('create-agent-error').style.display = 'none';
        document.getElementById('create-agent-form-fields').style.display = 'block';
        const successEl = document.getElementById('create-agent-success');
        successEl.style.display = 'none';
        while (successEl.firstChild) successEl.removeChild(successEl.firstChild);
        const cancelBtn = document.getElementById('create-agent-cancel-btn');
        cancelBtn.textContent = 'Cancel';
        cancelBtn.style.display = 'inline-flex';
        const submitBtn = document.getElementById('create-agent-submit-btn');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Generate Token';
        submitBtn.style.display = 'inline-flex';
        document.getElementById('create-agent-modal').style.display = 'flex';
        setTimeout(() => document.getElementById('new-agent-name').focus(), 50);
    }

    function closeCreateAgentModal() {
        document.getElementById('create-agent-modal').style.display = 'none';
        if (document.getElementById('create-agent-success').style.display !== 'none') {
            loadAgents();
        }
    }

    function _showCreateAgentError(msg) {
        const el = document.getElementById('create-agent-error');
        el.textContent = msg;
        el.style.display = 'block';
    }

    function _renderInstallSuccess(data) {
        const successEl = document.getElementById('create-agent-success');
        while (successEl.firstChild) successEl.removeChild(successEl.firstChild);

        const wrap = _el('div', {
            style: 'padding:16px;background:var(--success-light);border:1px solid var(--success);border-radius:10px;font-size:13px;color:var(--text-main);line-height:1.55;',
        });

        const header = _el('div', {
            style: 'display:flex;align-items:center;gap:8px;font-weight:600;color:var(--success);margin-bottom:10px;font-size:14px;',
        });
        header.appendChild(_el('span', {
            text: '✓',
            style: 'display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:50%;background:var(--success);color:#fff;font-size:13px;',
        }));
        header.appendChild(_el('span', { text: 'Agent registered — token shown ONCE' }));
        wrap.appendChild(header);

        const grid = _el('div', { cls: 'agent-detail-grid', style: 'margin-bottom:12px;' });
        function row(k, v) {
            grid.appendChild(_el('div', { cls: 'key', text: k }));
            const ve = _el('div', { cls: 'val' });
            if (Array.isArray(v)) v = v.length ? v.join(', ') : '—';
            ve.textContent = (v === null || v === undefined || v === '') ? '—' : String(v);
            grid.appendChild(ve);
        }
        row('Name', data.agent.name);
        row('Status', data.agent.status);
        row('Description', data.agent.description);
        row('CIDRs', data.agent.advertised_cidrs);
        if (data.token_expires_at) row('Token expires', data.token_expires_at);
        wrap.appendChild(grid);

        wrap.appendChild(_el('div', {
            style: 'font-weight:600;color:var(--text-main);margin-bottom:6px;font-size:12px;',
            text: 'Install command (copy + paste on the agent host):',
        }));

        // Token-bearing block: textContent only, never innerHTML.
        const block = _el('div', { cls: 'agent-install-block' });
        const code = _el('code', { style: 'background:transparent;padding:0;color:inherit;' });
        code.textContent = data.install_command || '';
        block.appendChild(code);

        const copyBtn = _el('button', {
            cls: 'agent-install-copy',
            attrs: { type: 'button' },
            text: 'Copy',
        });
        copyBtn.addEventListener('click', () => {
            const text = data.install_command || '';
            const ok = (msg) => {
                copyBtn.classList.add('copied');
                copyBtn.textContent = msg || 'Copied';
                setTimeout(() => { copyBtn.classList.remove('copied'); copyBtn.textContent = 'Copy'; }, 1600);
            };
            if (navigator.clipboard?.writeText) {
                navigator.clipboard.writeText(text).then(() => ok()).catch(() => ok('Select & copy'));
            } else {
                ok('Select & copy');
            }
        });
        block.appendChild(copyBtn);
        wrap.appendChild(block);

        wrap.appendChild(_el('div', {
            style: 'margin-top:10px;font-size:11px;color:var(--text-muted);',
            text: 'The token is single-use and IP-bound. It is not retrievable later — re-issue from the row actions if it expires before enrollment completes.',
        }));

        successEl.appendChild(wrap);
        successEl.style.display = 'block';
    }

    function submitCreateAgent() {
        const name = document.getElementById('new-agent-name').value.trim();
        const description = document.getElementById('new-agent-description').value.trim();
        const cidrsRaw = document.getElementById('new-agent-cidrs').value;
        const submitBtn = document.getElementById('create-agent-submit-btn');

        if (!name) { _showCreateAgentError('Agent name is required.'); return; }
        if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{2,31}$/.test(name)) {
            _showCreateAgentError('Name must be 3–32 chars: letters/digits/_/-, starting with a letter or digit.');
            return;
        }
        const advertised_cidrs = cidrsRaw
            .split(/[\n,]+/)
            .map(s => s.trim())
            .filter(Boolean);

        const body = { name };
        if (description) body.description = description;
        if (advertised_cidrs.length > 0) body.advertised_cidrs = advertised_cidrs;

        submitBtn.disabled = true;
        submitBtn.textContent = 'Generating…';
        document.getElementById('create-agent-error').style.display = 'none';

        fetch('/api/console/agents', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        })
            .then(async r => {
                if (!r.ok) {
                    const err = await r.json().catch(() => ({}));
                    throw new Error(err.detail || `HTTP ${r.status}`);
                }
                return r.json();
            })
            .then(data => {
                document.getElementById('create-agent-form-fields').style.display = 'none';
                _renderInstallSuccess(data);
                document.getElementById('create-agent-cancel-btn').textContent = 'Done';
                submitBtn.style.display = 'none';
            })
            .catch(err => {
                _showCreateAgentError(err.message || 'Failed to register agent.');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Generate Token';
            });
    }

    // ── Edit CIDRs ─────────────────────────────────────────────────────────

    let _editingAgentId = null;

    function openEditAgentModal(agentId) {
        const a = _agentsCache.find(x => x.id === agentId);
        if (!a) return;
        if (a.status !== 'enrolled') {
            alert('CIDR updates only apply to enrolled agents.');
            return;
        }
        _editingAgentId = agentId;
        document.getElementById('edit-agent-subtitle').textContent = `Updating "${a.name}" — applies live via wg syncconf`;
        document.getElementById('edit-agent-cidrs').value = (a.advertised_cidrs || []).join('\n');
        document.getElementById('edit-agent-error').style.display = 'none';
        const submitBtn = document.getElementById('edit-agent-submit-btn');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Apply';
        document.getElementById('edit-agent-modal').style.display = 'flex';
        setTimeout(() => document.getElementById('edit-agent-cidrs').focus(), 50);
    }

    function closeEditAgentModal() {
        document.getElementById('edit-agent-modal').style.display = 'none';
        _editingAgentId = null;
    }

    function submitEditAgent() {
        if (!_editingAgentId) return;
        const cidrsRaw = document.getElementById('edit-agent-cidrs').value;
        const advertised_cidrs = cidrsRaw.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
        const errEl = document.getElementById('edit-agent-error');
        const submitBtn = document.getElementById('edit-agent-submit-btn');
        submitBtn.disabled = true; submitBtn.textContent = 'Applying…';
        errEl.style.display = 'none';

        fetch(`/api/console/agents/${_editingAgentId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ advertised_cidrs }),
        })
            .then(async r => {
                if (!r.ok) {
                    const err = await r.json().catch(() => ({}));
                    throw new Error(err.detail || `HTTP ${r.status}`);
                }
                return r.json();
            })
            .then(() => {
                closeEditAgentModal();
                loadAgents();
            })
            .catch(err => {
                errEl.textContent = err.message || 'Update failed.';
                errEl.style.display = 'block';
                submitBtn.disabled = false; submitBtn.textContent = 'Apply';
            });
    }

    // ── Revoke ─────────────────────────────────────────────────────────────

    function confirmRevokeAgent(agentId, name) {
        if (!confirm(`Revoke agent "${name}"?\n\nThis removes the WG peer immediately and the agent's heartbeat will start failing. The local install on the agent host is untouched — the operator must run \`wireshield-agent revoke\` to clean up.`)) {
            return;
        }
        fetch(`/api/console/agents/${agentId}`, { method: 'DELETE' })
            .then(async r => {
                if (!r.ok) {
                    const err = await r.json().catch(() => ({}));
                    throw new Error(err.detail || `HTTP ${r.status}`);
                }
                return r.json();
            })
            .then(() => loadAgents())
            .catch(err => alert(`Revoke failed: ${err.message}`));
    }

    // ── Rotate token (pending agents) ─────────────────────────────────────

    function rotateAgentToken(agentId) {
        if (!confirm('Generate a new enrollment token for this pending agent? The old token (if still valid) will continue to work until it expires or is consumed.')) return;
        fetch(`/api/console/agents/${agentId}/rotate-token`, { method: 'POST' })
            .then(async r => {
                if (!r.ok) {
                    const err = await r.json().catch(() => ({}));
                    throw new Error(err.detail || `HTTP ${r.status}`);
                }
                return r.json();
            })
            .then(data => {
                openCreateAgentModal();
                document.getElementById('create-agent-form-fields').style.display = 'none';
                _renderInstallSuccess({
                    agent: data.agent || {
                        id: agentId,
                        name: data.name || `agent #${agentId}`,
                        status: 'pending',
                        advertised_cidrs: [],
                    },
                    enrollment_token: data.enrollment_token,
                    token_expires_at: data.token_expires_at,
                    install_command: data.install_command,
                });
                document.getElementById('create-agent-cancel-btn').textContent = 'Done';
                document.getElementById('create-agent-submit-btn').style.display = 'none';
            })
            .catch(err => alert(`Token rotation failed: ${err.message}`));
    }

    // ── Detail drawer ──────────────────────────────────────────────────────

    function openAgentDetailModal(agentId) {
        const modal = document.getElementById('agent-detail-modal');
        const body  = document.getElementById('agent-detail-body');
        document.getElementById('agent-detail-name').textContent = `agent #${agentId}`;
        document.getElementById('agent-detail-subtitle').textContent = 'Loading…';
        while (body.firstChild) body.removeChild(body.firstChild);
        body.appendChild(_el('div', { cls: 'agent-table-empty', text: 'Loading agent details…' }));
        modal.style.display = 'flex';

        fetch(`/api/console/agents/${agentId}`, { cache: 'no-store' })
            .then(async r => {
                if (!r.ok) {
                    const err = await r.json().catch(() => ({}));
                    throw new Error(err.detail || `HTTP ${r.status}`);
                }
                return r.json();
            })
            .then(data => {
                const a = data.agent || data;
                document.getElementById('agent-detail-name').textContent = a.name || `agent #${agentId}`;
                document.getElementById('agent-detail-subtitle').textContent =
                    `Status: ${a.status || 'unknown'}${a.online ? ' · online' : ''}`;

                const grid = _el('div', { cls: 'agent-detail-grid' });
                function add(k, v) {
                    grid.appendChild(_el('div', { cls: 'key', text: k }));
                    const ve = _el('div', { cls: 'val' });
                    if (v === null || v === undefined || v === '') v = '—';
                    if (Array.isArray(v)) v = v.length ? v.join(', ') : '—';
                    ve.textContent = String(v);
                    grid.appendChild(ve);
                }
                add('ID',           a.id);
                add('Description',  a.description);
                add('Status',       a.status);
                add('Online',       a.online ? 'yes' : 'no');
                add('WG IPv4',      a.wg_ipv4);
                add('Hostname',     a.hostname);
                add('LAN interface',a.lan_interface);
                add('Version',      a.agent_version);
                add('Public key',   a.public_key);
                add('Advertised',   a.advertised_cidrs);
                add('Created',      a.created_at);
                add('Created by',   a.created_by);
                add('Enrolled',     a.enrolled_at);
                add('Last seen',    a.last_seen ? `${a.last_seen} (${_formatRelative(a.last_seen)})` : 'never');
                add('Last seen IP', a.last_seen_ip);
                add('Revoked',      a.revoked_at);
                add('RX bytes',     _formatBytesShort(a.rx_bytes));
                add('TX bytes',     _formatBytesShort(a.tx_bytes));

                while (body.firstChild) body.removeChild(body.firstChild);
                body.appendChild(grid);

                // Attach the metrics section under the grid. Failures are
                // non-fatal — the detail drawer is still usable without
                // the chart if /metrics returns 404 or 500.
                _attachMetrics(body, agentId);
            })
            .catch(err => {
                while (body.firstChild) body.removeChild(body.firstChild);
                body.appendChild(_el('div', {
                    cls: 'agent-table-empty',
                    style: 'color:var(--error);',
                    text: `Failed to load agent: ${err.message}`,
                }));
            });
    }

    // Per-modal-open metrics chart. We destroy any prior chart instance
    // before drawing so re-opening the drawer for the same or another
    // agent doesn't leak Chart.js state.
    let _metricsChart = null;

    function _attachMetrics(parent, agentId) {
        const section = _el('div', { style: 'margin-top:18px;' });
        section.appendChild(_el('div', {
            style: 'font-weight:600;color:var(--text-main);font-size:13px;margin-bottom:6px;',
            text: 'Traffic — last 24 hours',
        }));
        const summary = _el('div', {
            style: 'font-size:11px;color:var(--text-muted);margin-bottom:8px;',
            text: 'Loading metrics…',
        });
        section.appendChild(summary);

        const canvasWrap = _el('div', {
            style: 'position:relative;height:160px;background:var(--bg-body);border:1px solid var(--border);border-radius:8px;padding:8px;',
        });
        const canvas = document.createElement('canvas');
        canvas.id = 'agent-metrics-chart';
        canvasWrap.appendChild(canvas);
        section.appendChild(canvasWrap);
        parent.appendChild(section);

        fetch(`/api/console/agents/${agentId}/metrics?window_hours=24&bucket_minutes=15`, { cache: 'no-store' })
            .then(async r => {
                if (!r.ok) {
                    const err = await r.json().catch(() => ({}));
                    throw new Error(err.detail || `HTTP ${r.status}`);
                }
                return r.json();
            })
            .then(m => {
                summary.textContent =
                    `Uptime ${m.uptime_percent}% · ${m.online_buckets}/${m.total_buckets} buckets reported a heartbeat`;
                if (typeof Chart === 'undefined') {
                    summary.textContent += ' (Chart.js not loaded)';
                    return;
                }
                if (_metricsChart) {
                    _metricsChart.destroy();
                    _metricsChart = null;
                }
                _metricsChart = new Chart(canvas.getContext('2d'), {
                    type: 'line',
                    data: {
                        labels: m.labels.map(s => s.replace('T', ' ').replace('Z', '')),
                        datasets: [
                            {
                                label: 'RX',
                                data: m.rx_bytes_per_bucket,
                                borderColor: '#3b82f6',
                                backgroundColor: 'rgba(59,130,246,0.10)',
                                fill: true,
                                tension: 0.25,
                                pointRadius: 0,
                                borderWidth: 1.5,
                            },
                            {
                                label: 'TX',
                                data: m.tx_bytes_per_bucket,
                                borderColor: '#10b981',
                                backgroundColor: 'rgba(16,185,129,0.10)',
                                fill: true,
                                tension: 0.25,
                                pointRadius: 0,
                                borderWidth: 1.5,
                            },
                        ],
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        animation: false,
                        plugins: {
                            legend: { display: true, position: 'bottom', labels: { font: { size: 11 } } },
                            tooltip: {
                                callbacks: {
                                    label: ctx => `${ctx.dataset.label}: ${_formatBytesShort(ctx.parsed.y)}`,
                                },
                            },
                        },
                        scales: {
                            x: { display: false },
                            y: {
                                beginAtZero: true,
                                ticks: {
                                    font: { size: 10 },
                                    callback: v => _formatBytesShort(v),
                                },
                            },
                        },
                    },
                });
            })
            .catch(err => {
                summary.textContent = `Metrics unavailable: ${err.message}`;
                summary.style.color = 'var(--error)';
            });
    }

    function closeAgentDetailModal() {
        document.getElementById('agent-detail-modal').style.display = 'none';
        if (_metricsChart) {
            _metricsChart.destroy();
            _metricsChart = null;
        }
    }

    // ── Manage Access (Phase 4) ────────────────────────────────────────────

    let _accessAgentId = null;

    function openAgentAccessModal(agentId) {
        _accessAgentId = agentId;
        const a = _agentsCache.find(x => x.id === agentId);
        document.getElementById('agent-access-title').textContent = a ? `Manage Access — ${a.name}` : `Manage Access — agent #${agentId}`;
        document.getElementById('agent-access-subtitle').textContent = 'Loading…';
        document.getElementById('agent-access-error').style.display = 'none';
        document.getElementById('agent-access-add-input').value = '';
        const usersDiv = document.getElementById('agent-access-users');
        while (usersDiv.firstChild) usersDiv.removeChild(usersDiv.firstChild);
        document.getElementById('agent-access-restricted-toggle').checked = !!(a && a.is_restricted);
        document.getElementById('agent-access-modal').style.display = 'flex';
        _loadAccessList();
    }

    function closeAgentAccessModal() {
        document.getElementById('agent-access-modal').style.display = 'none';
        _accessAgentId = null;
    }

    function _showAccessError(msg) {
        const el = document.getElementById('agent-access-error');
        el.textContent = msg;
        el.style.display = 'block';
    }

    function _loadAccessList() {
        if (!_accessAgentId) return;
        fetch(`/api/console/agents/${_accessAgentId}/access`, { cache: 'no-store' })
            .then(async r => {
                if (!r.ok) {
                    const err = await r.json().catch(() => ({}));
                    throw new Error(err.detail || `HTTP ${r.status}`);
                }
                return r.json();
            })
            .then(data => {
                document.getElementById('agent-access-restricted-toggle').checked = !!data.is_restricted;
                document.getElementById('agent-access-subtitle').textContent =
                    data.is_restricted
                        ? `Restricted — ${data.users.length} user(s) on the allowlist`
                        : 'Unrestricted — every VPN user can reach this agent';
                const usersDiv = document.getElementById('agent-access-users');
                while (usersDiv.firstChild) usersDiv.removeChild(usersDiv.firstChild);
                if (data.users.length === 0) {
                    usersDiv.appendChild(_el('div', {
                        cls: 'agent-table-empty',
                        style: 'padding:12px;font-size:12px;',
                        text: data.is_restricted
                            ? 'No users on the allowlist — every connection will be DROPPED until at least one is granted.'
                            : 'No grants. Toggle "Restrict access" ON to start gating users.',
                    }));
                } else {
                    for (const u of data.users) {
                        const row = _el('div', { cls: 'agent-access-user-row' });
                        const left = _el('div');
                        left.appendChild(_el('strong', { text: u.client_id }));
                        if (u.granted_by) left.appendChild(_el('span', { cls: 'meta', text: `by ${u.granted_by}` }));
                        if (u.granted_at) left.appendChild(_el('span', { cls: 'meta', text: u.granted_at }));
                        row.appendChild(left);
                        const rm = _el('button', { attrs: { type: 'button' }, text: 'Remove' });
                        rm.addEventListener('click', () => submitAgentAccessRemove(u.client_id));
                        row.appendChild(rm);
                        usersDiv.appendChild(row);
                    }
                }
            })
            .catch(err => _showAccessError(err.message || 'Failed to load access list.'));
    }

    function toggleAgentRestriction() {
        if (!_accessAgentId) return;
        const isRestricted = document.getElementById('agent-access-restricted-toggle').checked;
        document.getElementById('agent-access-error').style.display = 'none';
        fetch(`/api/console/agents/${_accessAgentId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ is_restricted: isRestricted }),
        })
            .then(async r => {
                if (!r.ok) {
                    const err = await r.json().catch(() => ({}));
                    throw new Error(err.detail || `HTTP ${r.status}`);
                }
                return r.json();
            })
            .then(() => {
                _loadAccessList();
                loadAgents(); // refresh row pill
            })
            .catch(err => {
                _showAccessError(err.message || 'Failed to update restriction.');
                // Revert the toggle on failure.
                document.getElementById('agent-access-restricted-toggle').checked = !isRestricted;
            });
    }

    function submitAgentAccessAdd() {
        if (!_accessAgentId) return;
        const inp = document.getElementById('agent-access-add-input');
        const cid = (inp.value || '').trim();
        if (!cid) { _showAccessError('client_id is required.'); return; }
        document.getElementById('agent-access-error').style.display = 'none';
        fetch(`/api/console/agents/${_accessAgentId}/access`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ client_id: cid }),
        })
            .then(async r => {
                if (!r.ok) {
                    const err = await r.json().catch(() => ({}));
                    throw new Error(err.detail || `HTTP ${r.status}`);
                }
                return r.json();
            })
            .then(() => {
                inp.value = '';
                _loadAccessList();
            })
            .catch(err => _showAccessError(err.message || 'Failed to add user.'));
    }

    function submitAgentAccessRemove(targetClientId) {
        if (!_accessAgentId) return;
        const url = `/api/console/agents/${_accessAgentId}/access/${encodeURIComponent(targetClientId)}`;
        fetch(url, { method: 'DELETE' })
            .then(async r => {
                if (!r.ok) {
                    const err = await r.json().catch(() => ({}));
                    throw new Error(err.detail || `HTTP ${r.status}`);
                }
                return r.json();
            })
            .then(() => _loadAccessList())
            .catch(err => _showAccessError(err.message || 'Failed to remove user.'));
    }

    // Public exports — referenced from inline onclick attributes in the
    // template, so they must live on `window`.
    window.loadAgents             = loadAgents;
    window.renderAgents           = renderAgents;
    window.openCreateAgentModal   = openCreateAgentModal;
    window.closeCreateAgentModal  = closeCreateAgentModal;
    window.submitCreateAgent      = submitCreateAgent;
    window.openEditAgentModal     = openEditAgentModal;
    window.closeEditAgentModal    = closeEditAgentModal;
    window.submitEditAgent        = submitEditAgent;
    window.confirmRevokeAgent     = confirmRevokeAgent;
    window.rotateAgentToken       = rotateAgentToken;
    window.openAgentDetailModal   = openAgentDetailModal;
    window.closeAgentDetailModal  = closeAgentDetailModal;
    window.openAgentAccessModal   = openAgentAccessModal;
    window.closeAgentAccessModal  = closeAgentAccessModal;
    window.toggleAgentRestriction = toggleAgentRestriction;
    window.submitAgentAccessAdd   = submitAgentAccessAdd;
    window.submitAgentAccessRemove= submitAgentAccessRemove;
})();
