// console-policies.js — Access Policies section logic

// ── Load & render ────────────────────────────────────────────────────────────

function loadPolicies() {
    const userFilter = document.getElementById('policies-user-filter');
    const clientFilter = userFilter ? userFilter.value : 'all';
    const url = clientFilter && clientFilter !== 'all'
        ? `/api/console/policies?client_filter=${encodeURIComponent(clientFilter)}`
        : '/api/console/policies';

    const tbody = document.getElementById('policies-table');
    if (tbody) {
        renderLoadingSkeleton(tbody, 8);
    }

    fetch(url, { cache: 'no-store' })
        .then(r => r.json())
        .then(data => renderPolicies(data.policies || []))
        .catch(err => {
            console.error('Error loading policies:', err);
            if (tbody) {
                tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:32px;">
                    Failed to load policies.</td></tr>`;
            }
        });
}

function renderPolicies(policies) {
    const tbody = document.getElementById('policies-table');
    const countEl = document.getElementById('policies-count');
    if (!tbody) return;

    if (countEl) {
        countEl.textContent = `${policies.length} rule${policies.length !== 1 ? 's' : ''}`;
    }

    if (policies.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8" style="text-align:center;padding:48px 16px;">
                    <div style="display:flex;flex-direction:column;align-items:center;gap:12px;color:var(--text-muted);">
                        <svg width="40" height="40" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="opacity:.4;">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                        </svg>
                        <span style="font-size:14px;">No policies yet. Click <strong>Add Policy</strong> to grant local access to a client.</span>
                    </div>
                </td>
            </tr>`;
        return;
    }

    tbody.innerHTML = policies.map(p => {
        const typeBadge = `<span class="policy-type-badge policy-type-${p.target_type}">${p.target_type.toUpperCase()}</span>`;

        const targetDisplay = p.target_type === 'domain' && p.resolved_ip
            ? `<span title="Resolves to ${p.resolved_ip}">${escapeHtml(p.target)}</span>
               <span style="color:var(--text-muted);font-size:11px;display:block;">${escapeHtml(p.resolved_ip)}</span>`
            : escapeHtml(p.target);

        const portDisplay  = p.port     ? escapeHtml(p.port)     : '<span style="color:var(--text-muted);">Any</span>';
        const protoDisplay = p.protocol !== 'any' ? p.protocol.toUpperCase()
                                                   : '<span style="color:var(--text-muted);">Any</span>';
        const descDisplay  = p.description ? escapeHtml(p.description)
                                           : '<span style="color:var(--text-muted);">—</span>';

        const isEnabled = parseInt(p.enabled) === 1;
        const toggleLabel = isEnabled ? 'Enabled' : 'Disabled';
        const toggleClass = isEnabled ? 'enabled' : 'disabled';

        return `
            <tr>
                <td><span class="client-badge">${escapeHtml(p.client_id)}</span></td>
                <td>${typeBadge}</td>
                <td style="font-family:monospace;font-size:13px;">${targetDisplay}</td>
                <td style="font-family:monospace;">${portDisplay}</td>
                <td>${protoDisplay}</td>
                <td>${descDisplay}</td>
                <td>
                    <button class="toggle-btn ${toggleClass}"
                            onclick="togglePolicy(${p.id}, this)"
                            title="${isEnabled ? 'Click to disable' : 'Click to enable'}">
                        ${toggleLabel}
                    </button>
                </td>
                <td>
                    <button class="btn btn-ghost" style="padding:4px 8px;font-size:12px;color:var(--error);"
                            onclick="deletePolicy(${p.id}, '${escapeHtml(p.client_id)}', '${escapeHtml(p.target)}')">
                        <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <polyline points="3,6 5,6 21,6"/>
                            <path d="M19,6l-1,14a2,2,0,0,1-2,2H8a2,2,0,0,1-2-2L5,6"/>
                            <path d="M10,11v6M14,11v6"/>
                            <path d="M9,6V4a1,1,0,0,1,1-1h4a1,1,0,0,1,1,1v2"/>
                        </svg>
                        Delete
                    </button>
                </td>
            </tr>`;
    }).join('');
}

// ── Toggle enabled/disabled ──────────────────────────────────────────────────

function togglePolicy(policyId, btn) {
    btn.disabled = true;
    fetch(`/api/console/policies/${policyId}/toggle`, { method: 'PATCH', cache: 'no-store' })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                const isEnabled = data.enabled;
                btn.textContent = isEnabled ? 'Enabled' : 'Disabled';
                btn.className = `toggle-btn ${isEnabled ? 'enabled' : 'disabled'}`;
                btn.title = isEnabled ? 'Click to disable' : 'Click to enable';
            }
            btn.disabled = false;
        })
        .catch(err => {
            console.error('Toggle error:', err);
            btn.disabled = false;
        });
}

// ── Delete ───────────────────────────────────────────────────────────────────

function deletePolicy(policyId, clientId, target) {
    if (!confirm(`Delete policy for ${clientId} → ${target}?\n\nThis will immediately revoke local network access if the client is connected.`)) {
        return;
    }
    fetch(`/api/console/policies/${policyId}`, { method: 'DELETE', cache: 'no-store' })
        .then(r => r.json())
        .then(data => {
            if (data.success) loadPolicies();
        })
        .catch(err => console.error('Delete error:', err));
}

// ── Add Policy Modal ─────────────────────────────────────────────────────────

function openAddPolicyModal() {
    // Populate client dropdown
    fetch('/api/console/users?page=1&limit=100', { cache: 'no-store' })
        .then(r => r.json())
        .then(data => {
            const sel = document.getElementById('policy-client');
            sel.innerHTML = '';
            (data.users || []).forEach(u => {
                const opt = document.createElement('option');
                opt.value = u.client_id;
                opt.textContent = u.client_id;
                sel.appendChild(opt);
            });

            // Pre-select current filter if set
            const filterVal = document.getElementById('policies-user-filter')?.value;
            if (filterVal && filterVal !== 'all') sel.value = filterVal;
        })
        .catch(() => {});

    // Reset form fields
    document.getElementById('policy-target-type').value = 'ip';
    document.getElementById('policy-target').value = '';
    document.getElementById('policy-port').value = '';
    document.getElementById('policy-protocol').value = 'any';
    document.getElementById('policy-description').value = '';
    document.getElementById('policy-modal-error').style.display = 'none';
    document.getElementById('policy-submit-btn').disabled = false;
    updateTargetPlaceholder();

    document.getElementById('add-policy-modal').style.display = 'flex';
}

function closeAddPolicyModal() {
    document.getElementById('add-policy-modal').style.display = 'none';
}

function closePolicyModalOnBackdrop(event) {
    if (event.target === document.getElementById('add-policy-modal')) {
        closeAddPolicyModal();
    }
}

function updateTargetPlaceholder() {
    const type = document.getElementById('policy-target-type').value;
    const input = document.getElementById('policy-target');
    const label = document.getElementById('policy-target-label');
    const placeholders = {
        ip:     { label: 'Target IP',         ph: 'e.g. 192.168.1.100' },
        cidr:   { label: 'IP Block (CIDR)',    ph: 'e.g. 192.168.1.0/24' },
        domain: { label: 'Domain',             ph: 'e.g. internal.example.com' },
    };
    const cfg = placeholders[type] || placeholders.ip;
    label.textContent = cfg.label;
    input.placeholder = cfg.ph;
}

function submitAddPolicy() {
    const clientId  = document.getElementById('policy-client').value;
    const targetType= document.getElementById('policy-target-type').value;
    const target    = document.getElementById('policy-target').value.trim();
    const port      = document.getElementById('policy-port').value.trim();
    const protocol  = document.getElementById('policy-protocol').value;
    const desc      = document.getElementById('policy-description').value.trim();
    const errEl     = document.getElementById('policy-modal-error');
    const submitBtn = document.getElementById('policy-submit-btn');

    errEl.style.display = 'none';

    if (!clientId) {
        showPolicyError('Please select a client.');
        return;
    }
    if (!target) {
        showPolicyError('Target is required.');
        return;
    }
    if (port && !/^\d+$/.test(port)) {
        showPolicyError('Port must be a number (e.g. 8000).');
        return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Adding…';

    const payload = {
        policy_client_id: clientId,
        target_type: targetType,
        target: target,
        protocol: protocol,
    };
    if (port) payload.port = port;
    if (desc) payload.description = desc;

    fetch('/api/console/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        cache: 'no-store',
    })
        .then(r => r.json().then(d => ({ ok: r.ok, data: d })))
        .then(({ ok, data }) => {
            if (ok && data.success) {
                closeAddPolicyModal();
                loadPolicies();
            } else {
                showPolicyError(data.detail || 'Failed to add policy.');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Add Policy';
            }
        })
        .catch(() => {
            showPolicyError('Network error — please try again.');
            submitBtn.disabled = false;
            submitBtn.textContent = 'Add Policy';
        });
}

function showPolicyError(msg) {
    const el = document.getElementById('policy-modal-error');
    el.textContent = msg;
    el.style.display = 'block';
}

// ── Utility ──────────────────────────────────────────────────────────────────

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// Close modal on Escape key
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
        const modal = document.getElementById('add-policy-modal');
        if (modal && modal.style.display !== 'none') closeAddPolicyModal();
    }
});
