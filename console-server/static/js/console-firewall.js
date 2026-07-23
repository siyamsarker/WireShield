// console-firewall.js — Firewall tab controller (policies) + per-user
// firewall modal (opened from the Users table).
//
// All dynamic content is inserted via DOM .textContent / element creation —
// no innerHTML on user-controlled values, anywhere, matching the invariant
// established in console-agents.js.

(function () {
    let _policiesCache = [];
    let _policiesSort = null; // {key, dir} or null (default: server order)
    let _manageAgentPolicyId = null; // policy currently open in the manage modal
    let _ufClientId = null;          // user currently open in the user-firewall modal

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

    async function _jsonFetch(url, opts) {
        const r = await fetch(url, opts);
        if (!r.ok) {
            const err = await r.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${r.status}`);
        }
        return r.json();
    }

    function _portsSummary(rule) {
        if (rule.port_start == null) return 'any port';
        return rule.port_start === rule.port_end ? `port ${rule.port_start}` : `ports ${rule.port_start}-${rule.port_end}`;
    }

    // Build one rule row: direction badge, protocol/ports/cidr summary,
    // action pill, remove button. Shared by both the policy-rules list and
    // the per-user override-rules list.
    function _buildRuleRow(rule, onRemove) {
        const row = _el('div', { cls: 'agent-access-user-row' });
        const left = _el('div');
        left.appendChild(_el('span', {
            cls: `direction-badge ${rule.direction}`,
            text: rule.direction === 'inbound' ? 'IN' : 'OUT',
        }));
        const proto = (rule.protocol || 'all').toUpperCase();
        const cidr = rule.remote_cidr || 'any';
        left.appendChild(_el('strong', { text: ` ${proto}`, style: 'margin-left:6px;' }));
        left.appendChild(_el('span', { cls: 'meta', text: `${_portsSummary(rule)} · ${cidr}` }));
        left.appendChild(_el('span', {
            cls: `status-pill ${rule.action === 'allow' ? 'success' : 'denied'}`,
            text: rule.action,
            style: 'margin-left:8px;',
        }));
        row.appendChild(left);
        const rm = _el('button', { attrs: { type: 'button' }, text: 'Remove' });
        rm.addEventListener('click', onRemove);
        row.appendChild(rm);
        return row;
    }

    function _readRuleForm(prefix) {
        const portStartRaw = document.getElementById(`${prefix}-port-start`).value;
        const portEndRaw = document.getElementById(`${prefix}-port-end`).value;
        return {
            direction: document.getElementById(`${prefix}-direction`).value,
            action: document.getElementById(`${prefix}-action`).value,
            protocol: document.getElementById(`${prefix}-protocol`).value,
            port_start: portStartRaw ? parseInt(portStartRaw, 10) : null,
            port_end: portEndRaw ? parseInt(portEndRaw, 10) : null,
            remote_cidr: document.getElementById(`${prefix}-cidr`).value.trim() || null,
        };
    }

    function _clearRuleForm(prefix) {
        document.getElementById(`${prefix}-port-start`).value = '';
        document.getElementById(`${prefix}-port-end`).value = '';
        document.getElementById(`${prefix}-cidr`).value = '';
    }

    // ── Policies list ─────────────────────────────────────────────────────

    function _policyCompare(a, b, key) {
        const NUM = { rule_count: x => x.rule_count || 0, assigned_user_count: x => x.assigned_user_count || 0 };
        if (NUM[key]) return NUM[key](a) - NUM[key](b);
        if (key === 'enabled') return (a.enabled ? 1 : 0) - (b.enabled ? 1 : 0);
        const sa = (a[key] == null ? '' : String(a[key])).toLowerCase();
        const sb = (b[key] == null ? '' : String(b[key])).toLowerCase();
        if (sa === sb) return 0;
        return sa < sb ? -1 : 1;
    }

    function setFirewallPoliciesSort(key, dir) {
        _policiesSort = { key, dir };
        renderFirewallPolicies();
    }

    async function loadFirewallPolicies() {
        const tbody = document.getElementById('firewall-policies-table');
        if (!tbody) return;
        renderLoadingSkeleton(tbody, 7);
        try {
            const data = await _jsonFetch('/api/console/firewall/policies', { cache: 'no-store' });
            _policiesCache = data.policies || [];
            renderFirewallPolicies();
        } catch (err) {
            while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
            const tr = _el('tr');
            const td = _el('td', { text: 'Error loading policies', style: 'text-align:center;color:var(--error);padding:40px;' });
            td.colSpan = 7;
            tr.appendChild(td);
            tbody.appendChild(tr);
        }
    }

    function renderFirewallPolicies() {
        const tbody = document.getElementById('firewall-policies-table');
        const summary = document.getElementById('firewall-summary');
        if (!tbody) return;
        if (summary) summary.textContent = `${_policiesCache.length} polic${_policiesCache.length === 1 ? 'y' : 'ies'}`;

        while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

        if (_policiesCache.length === 0) {
            const tr = _el('tr');
            const td = _el('td', {
                cls: 'agent-table-empty',
                text: 'No firewall policies yet. Click "New Policy" to create one.',
            });
            td.colSpan = 7;
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }

        let policies = _policiesCache;
        if (_policiesSort) {
            const { key, dir } = _policiesSort;
            const factor = dir === 'asc' ? 1 : -1;
            policies = policies.slice().sort((a, b) => _policyCompare(a, b, key) * factor);
        }

        for (const p of policies) tbody.appendChild(_buildPolicyRow(p));
    }

    function _buildPolicyRow(p) {
        const tr = _el('tr');
        tr.appendChild(_el('td', { text: p.name }));
        tr.appendChild(_el('td', { text: p.description || '—', style: 'color:var(--text-muted);' }));
        tr.appendChild(_el('td'));
        tr.lastChild.appendChild(_el('span', {
            cls: `status-pill ${p.default_action === 'allow' ? 'success' : 'denied'}`,
            text: p.default_action,
        }));
        tr.appendChild(_el('td', { text: String(p.rule_count || 0) }));
        tr.appendChild(_el('td', { text: String(p.assigned_user_count || 0) }));
        tr.appendChild(_el('td'));
        tr.lastChild.appendChild(_el('span', {
            cls: `status-pill ${p.enabled ? 'success' : 'warning'}`,
            text: p.enabled ? 'enabled' : 'disabled',
        }));

        const actTd = _el('td');
        const manageBtn = _el('button', {
            cls: 'btn btn-ghost', text: 'Manage Rules',
            style: 'padding:4px 8px;font-size:12px;',
        });
        manageBtn.addEventListener('click', () => openManagePolicyModal(p.id));
        actTd.appendChild(manageBtn);

        const deleteBtn = _el('button', {
            cls: 'btn btn-ghost', text: 'Delete',
            style: 'padding:4px 8px;font-size:12px;color:var(--error);margin-left:4px;',
        });
        deleteBtn.addEventListener('click', () => confirmDeletePolicy(p.id, p.name));
        actTd.appendChild(deleteBtn);

        tr.appendChild(actTd);
        return tr;
    }

    // ── Create policy modal ──────────────────────────────────────────────

    function openCreatePolicyModal() {
        document.getElementById('new-policy-name').value = '';
        document.getElementById('new-policy-description').value = '';
        document.getElementById('new-policy-default-action').value = 'deny';
        document.getElementById('new-policy-error').style.display = 'none';
        document.getElementById('firewall-policy-modal').style.display = 'flex';
        setTimeout(() => document.getElementById('new-policy-name').focus(), 50);
    }

    function closeCreatePolicyModal() {
        document.getElementById('firewall-policy-modal').style.display = 'none';
    }

    function _showCreatePolicyError(msg) {
        const el = document.getElementById('new-policy-error');
        el.textContent = msg;
        el.style.display = 'block';
    }

    async function submitCreatePolicy() {
        const name = document.getElementById('new-policy-name').value.trim();
        const description = document.getElementById('new-policy-description').value.trim() || null;
        const default_action = document.getElementById('new-policy-default-action').value;
        if (!name) { _showCreatePolicyError('Policy name is required.'); return; }

        try {
            await _jsonFetch('/api/console/firewall/policies', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ..._csrfHeaders() },
                body: JSON.stringify({ name, description, default_action }),
            });
            closeCreatePolicyModal();
            wsToast(`Policy "${name}" created.`, 'success');
            loadFirewallPolicies();
        } catch (err) {
            _showCreatePolicyError(err.message || 'Failed to create policy.');
        }
    }

    async function confirmDeletePolicy(policyId, name) {
        const confirmed = await wsConfirm({
            title: `Delete policy "${name}"?`,
            message: 'Users assigned to this policy fall back to unmanaged (full internet access) — they are not blocked. This cannot be undone.',
            confirmLabel: 'Delete policy',
            cancelLabel: 'Cancel',
            danger: true,
        });
        if (!confirmed) return;
        try {
            await _jsonFetch(`/api/console/firewall/policies/${policyId}`, {
                method: 'DELETE', headers: _csrfHeaders(),
            });
            wsToast(`Policy "${name}" deleted.`, 'success');
            loadFirewallPolicies();
        } catch (err) {
            wsToast(`Delete failed: ${err.message}`, 'error');
        }
    }

    // ── Manage policy modal (default action / enabled / rules) ──────────

    function openManagePolicyModal(policyId) {
        _manageAgentPolicyId = policyId;
        document.getElementById('fw-manage-error').style.display = 'none';
        document.getElementById('firewall-manage-modal').style.display = 'flex';
        _clearRuleForm('fw-manage-add');
        _loadManagedPolicy();
    }

    function closeManagePolicyModal() {
        document.getElementById('firewall-manage-modal').style.display = 'none';
        _manageAgentPolicyId = null;
    }

    function _showManageError(msg) {
        const el = document.getElementById('fw-manage-error');
        el.textContent = msg;
        el.style.display = 'block';
    }

    async function _loadManagedPolicy() {
        if (!_manageAgentPolicyId) return;
        try {
            const policy = await _jsonFetch(`/api/console/firewall/policies/${_manageAgentPolicyId}`, { cache: 'no-store' });
            document.getElementById('firewall-manage-title').textContent = `Manage Policy — ${policy.name}`;
            document.getElementById('firewall-manage-subtitle').textContent = policy.description || 'No description';
            document.getElementById('fw-manage-default-action').value = policy.default_action;
            document.getElementById('fw-manage-enabled-toggle').checked = !!policy.enabled;

            const list = document.getElementById('fw-manage-rules-list');
            while (list.firstChild) list.removeChild(list.firstChild);
            if ((policy.rules || []).length === 0) {
                list.appendChild(_el('div', {
                    style: 'padding:12px;font-size:12px;color:var(--text-muted);',
                    text: `No rules yet — the default action (${policy.default_action}) applies to all traffic.`,
                }));
            } else {
                for (const rule of policy.rules) {
                    list.appendChild(_buildRuleRow(rule, () => submitDeleteManagedPolicyRule(rule.id)));
                }
            }
        } catch (err) {
            _showManageError(err.message || 'Failed to load policy.');
        }
    }

    async function patchManagedPolicy() {
        if (!_manageAgentPolicyId) return;
        const default_action = document.getElementById('fw-manage-default-action').value;
        const enabled = document.getElementById('fw-manage-enabled-toggle').checked;
        try {
            await _jsonFetch(`/api/console/firewall/policies/${_manageAgentPolicyId}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json', ..._csrfHeaders() },
                body: JSON.stringify({ default_action, enabled }),
            });
            loadFirewallPolicies();
        } catch (err) {
            _showManageError(err.message || 'Failed to update policy.');
        }
    }

    async function submitManagePolicyRule() {
        if (!_manageAgentPolicyId) return;
        const body = _readRuleForm('fw-manage-add');
        try {
            await _jsonFetch(`/api/console/firewall/policies/${_manageAgentPolicyId}/rules`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ..._csrfHeaders() },
                body: JSON.stringify(body),
            });
            _clearRuleForm('fw-manage-add');
            _loadManagedPolicy();
            loadFirewallPolicies();
        } catch (err) {
            _showManageError(err.message || 'Failed to add rule.');
        }
    }

    async function submitDeleteManagedPolicyRule(ruleId) {
        if (!_manageAgentPolicyId) return;
        try {
            await _jsonFetch(`/api/console/firewall/policies/${_manageAgentPolicyId}/rules/${ruleId}`, {
                method: 'DELETE', headers: _csrfHeaders(),
            });
            _loadManagedPolicy();
            loadFirewallPolicies();
        } catch (err) {
            _showManageError(err.message || 'Failed to remove rule.');
        }
    }

    // ── Per-user firewall modal ──────────────────────────────────────────

    async function _ensurePoliciesLoaded() {
        if (_policiesCache.length === 0) {
            try {
                const data = await _jsonFetch('/api/console/firewall/policies', { cache: 'no-store' });
                _policiesCache = data.policies || [];
            } catch (err) {
                // Non-fatal — the select just stays empty besides "No policy".
            }
        }
    }

    function _populatePolicySelect(selectedPolicyId) {
        const select = document.getElementById('uf-policy-select');
        while (select.options.length > 1) select.remove(1);
        for (const p of _policiesCache) {
            const opt = document.createElement('option');
            opt.value = String(p.id);
            opt.textContent = p.name;
            select.appendChild(opt);
        }
        select.value = selectedPolicyId != null ? String(selectedPolicyId) : '';
    }

    async function openUserFirewallModal(clientId) {
        _ufClientId = clientId;
        document.getElementById('user-firewall-title').textContent = `Firewall — ${clientId}`;
        document.getElementById('uf-error').style.display = 'none';
        _clearRuleForm('uf-add');
        document.getElementById('user-firewall-modal').style.display = 'flex';
        await _ensurePoliciesLoaded();
        _populatePolicySelect(null);
        _loadUserFirewall();
    }

    function closeUserFirewallModal() {
        document.getElementById('user-firewall-modal').style.display = 'none';
        _ufClientId = null;
    }

    function _showUfError(msg) {
        const el = document.getElementById('uf-error');
        el.textContent = msg;
        el.style.display = 'block';
    }

    async function _loadUserFirewall() {
        if (!_ufClientId) return;
        try {
            const data = await _jsonFetch(`/api/console/users/${encodeURIComponent(_ufClientId)}/firewall`, { cache: 'no-store' });
            document.getElementById('uf-blocked-toggle').checked = !!data.blocked;
            _populatePolicySelect(data.policy_id);

            const list = document.getElementById('uf-rules-list');
            while (list.firstChild) list.removeChild(list.firstChild);
            const rules = data.override_rules || [];
            if (rules.length === 0) {
                list.appendChild(_el('div', {
                    style: 'padding:12px;font-size:12px;color:var(--text-muted);',
                    text: 'No override rules.',
                }));
            } else {
                for (const rule of rules) {
                    list.appendChild(_buildRuleRow(rule, () => submitUserFirewallRuleRemove(rule.id)));
                }
            }
        } catch (err) {
            _showUfError(err.message || 'Failed to load firewall assignment.');
        }
    }

    async function submitUserFirewallAssignment() {
        if (!_ufClientId) return;
        const policyRaw = document.getElementById('uf-policy-select').value;
        const policy_id = policyRaw ? parseInt(policyRaw, 10) : null;
        const blocked = document.getElementById('uf-blocked-toggle').checked;
        try {
            await _jsonFetch(`/api/console/users/${encodeURIComponent(_ufClientId)}/firewall`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json', ..._csrfHeaders() },
                body: JSON.stringify({ policy_id, blocked }),
            });
            wsToast('Firewall assignment updated.', 'success');
        } catch (err) {
            _showUfError(err.message || 'Failed to update assignment.');
        }
    }

    async function submitUserFirewallRuleAdd() {
        if (!_ufClientId) return;
        const body = _readRuleForm('uf-add');
        try {
            await _jsonFetch(`/api/console/users/${encodeURIComponent(_ufClientId)}/firewall/rules`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ..._csrfHeaders() },
                body: JSON.stringify(body),
            });
            _clearRuleForm('uf-add');
            _loadUserFirewall();
        } catch (err) {
            _showUfError(err.message || 'Failed to add rule.');
        }
    }

    async function submitUserFirewallRuleRemove(ruleId) {
        if (!_ufClientId) return;
        try {
            await _jsonFetch(`/api/console/users/${encodeURIComponent(_ufClientId)}/firewall/rules/${ruleId}`, {
                method: 'DELETE', headers: _csrfHeaders(),
            });
            _loadUserFirewall();
        } catch (err) {
            _showUfError(err.message || 'Failed to remove rule.');
        }
    }

    // Public exports — referenced from inline onclick attributes in the
    // template and from console-app.js/console-tables.js, so they must
    // live on `window`.
    window.loadFirewallPolicies        = loadFirewallPolicies;
    window.renderFirewallPolicies      = renderFirewallPolicies;
    window.setFirewallPoliciesSort     = setFirewallPoliciesSort;
    window.openCreatePolicyModal       = openCreatePolicyModal;
    window.closeCreatePolicyModal      = closeCreatePolicyModal;
    window.submitCreatePolicy          = submitCreatePolicy;
    window.openManagePolicyModal       = openManagePolicyModal;
    window.closeManagePolicyModal      = closeManagePolicyModal;
    window.patchManagedPolicy          = patchManagedPolicy;
    window.submitManagePolicyRule      = submitManagePolicyRule;
    window.openUserFirewallModal       = openUserFirewallModal;
    window.closeUserFirewallModal      = closeUserFirewallModal;
    window.submitUserFirewallAssignment= submitUserFirewallAssignment;
    window.submitUserFirewallRuleAdd   = submitUserFirewallRuleAdd;
})();
