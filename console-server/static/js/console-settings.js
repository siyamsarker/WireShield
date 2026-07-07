// console-settings.js — Server Settings section
// Renders the schema returned by GET /api/console/settings into one card
// per category, saves changes via POST, and (for restart-required fields)
// polls /health until the service comes back up.

const SETTINGS_CATEGORY_ORDER = ['wireguard', 'session', 'rate_limit', 'logging'];
const SETTINGS_CATEGORY_META = {
    wireguard: {
        title: 'WireGuard Client Defaults',
        subtitle: 'Applied to newly created clients immediately — existing clients are unaffected.',
    },
    session: {
        title: 'Session & Security',
        subtitle: "Changes require a brief service restart to take effect.",
    },
    rate_limit: {
        title: 'Rate Limiting',
        subtitle: "Changes require a brief service restart to take effect.",
    },
    logging: {
        title: 'Logging & Retention',
        subtitle: "Changes require a brief service restart to take effect.",
    },
};

let _settingsByKey = {};

function _settingsEscapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function _settingsFieldInputHtml(field) {
    const id = `setting-${field.key}`;
    if (field.type === 'enum') {
        const options = (field.choices || []).map(c =>
            `<option value="${c}"${c === field.value ? ' selected' : ''}>${c}</option>`
        ).join('');
        return `<select id="${id}" class="filter-select form-input-full">${options}</select>`;
    }
    if (field.type === 'int') {
        return `<input type="number" id="${id}" class="filter-input form-input-full" value="${_settingsEscapeHtml(field.value)}" min="${field.min}" max="${field.max}">`;
    }
    // ip, cidr_list, hostname
    return `<input type="text" id="${id}" class="filter-input form-input-full" value="${_settingsEscapeHtml(field.value)}" autocomplete="off">`;
}

function _settingsFieldGroupHtml(field) {
    const unit = field.unit ? ` <span class="form-label-optional">(${field.unit})</span>` : '';
    return `
        <div class="form-group">
            <label class="form-label">${_settingsEscapeHtml(field.label)}${unit}</label>
            ${_settingsFieldInputHtml(field)}
            <span class="form-hint">${_settingsEscapeHtml(field.description || '')}</span>
        </div>`;
}

function _settingsCategoryCardHtml(categoryKey, fields) {
    const meta = SETTINGS_CATEGORY_META[categoryKey] || { title: categoryKey, subtitle: '' };
    const fieldsHtml = fields.map(_settingsFieldGroupHtml).join('');
    return `
        <div class="chart-card" style="margin-bottom: 14px;">
            <div class="chart-card-header">
                <div>
                    <h3 class="chart-title">${_settingsEscapeHtml(meta.title)}</h3>
                    <div class="chart-subtitle">${_settingsEscapeHtml(meta.subtitle)}</div>
                </div>
            </div>
            <div style="padding: 20px;">
                ${fieldsHtml}
                <div id="settings-error-${categoryKey}" class="form-alert-error" style="display:none;" role="alert"></div>
                <button type="button" class="btn btn-primary" id="settings-save-${categoryKey}" onclick="saveSettingsCategory('${categoryKey}')">Save</button>
            </div>
        </div>`;
}

function loadSettings() {
    const loading = document.getElementById('settings-loading');
    const categories = document.getElementById('settings-categories');
    const sslCard = document.getElementById('settings-ssl-card');
    loading.style.display = 'flex';
    categories.style.display = 'none';
    sslCard.style.display = 'none';

    fetch('/api/console/settings', { cache: 'no-store' })
        .then(r => r.json().then(d => ({ ok: r.ok, data: d })))
        .then(({ ok, data }) => {
            if (!ok) throw new Error((data && data.detail) || 'Failed to load settings');

            _settingsByKey = {};
            const byCategory = {};
            (data.settings || []).forEach(field => {
                _settingsByKey[field.key] = field;
                (byCategory[field.category] = byCategory[field.category] || []).push(field);
            });

            categories.innerHTML = SETTINGS_CATEGORY_ORDER
                .filter(cat => byCategory[cat])
                .map(cat => _settingsCategoryCardHtml(cat, byCategory[cat]))
                .join('');

            _renderSslInfo(data.ssl_info || {});

            loading.style.display = 'none';
            categories.style.display = 'block';
            sslCard.style.display = 'block';
        })
        .catch(err => {
            loading.innerHTML = `<span>${_settingsEscapeHtml(err.message || 'Failed to load settings.')}</span>`;
        });
}

function _renderSslInfo(sslInfo) {
    const statusEl = document.getElementById('settings-ssl-status');
    const regenRow = document.getElementById('settings-ssl-regen-row');
    const regenBtn = document.getElementById('settings-regen-cert-btn');

    const enabledPill = sslInfo.enabled
        ? '<span class="status-pill success">Enabled</span>'
        : '<span class="status-pill denied">Disabled</span>';
    const target = sslInfo.domain || sslInfo.hostname || '—';
    statusEl.innerHTML = `${enabledPill} &nbsp; <span style="color: var(--ws-text-muted); font-size: 13px;">${_settingsEscapeHtml(sslInfo.type || 'unknown')} · ${_settingsEscapeHtml(target)}</span>`;

    const isSelfSigned = (sslInfo.type || '').toLowerCase().replace('-', '') === 'selfsigned';
    regenRow.style.display = isSelfSigned ? 'block' : 'none';
    if (regenBtn) regenBtn.disabled = !isSelfSigned;
}

function _settingsCollectCategoryChanges(categoryKey) {
    const changes = {};
    Object.values(_settingsByKey)
        .filter(field => field.category === categoryKey)
        .forEach(field => {
            const el = document.getElementById(`setting-${field.key}`);
            if (!el) return;
            const raw = field.type === 'enum' ? el.value.toUpperCase() : el.value;
            if (String(raw) !== String(field.value)) {
                changes[field.key] = raw;
            }
        });
    return changes;
}

function _settingsCategoryNeedsRestart(categoryKey) {
    return Object.values(_settingsByKey).some(f => f.category === categoryKey && f.restart_required);
}

async function saveSettingsCategory(categoryKey) {
    const changes = _settingsCollectCategoryChanges(categoryKey);
    const errorEl = document.getElementById(`settings-error-${categoryKey}`);
    errorEl.style.display = 'none';

    if (Object.keys(changes).length === 0) {
        wsToast('No changes to save.', 'info');
        return;
    }

    if (_settingsCategoryNeedsRestart(categoryKey)) {
        const ok = await wsConfirm({
            title: 'Apply and restart service?',
            message: 'This category requires a brief service restart (a few seconds) to apply. The admin console and captive portal will be briefly unavailable.',
            confirmLabel: 'Save & Restart',
            danger: true,
        });
        if (!ok) return;
    }

    const btn = document.getElementById(`settings-save-${categoryKey}`);
    btn.disabled = true;
    const originalText = btn.textContent;
    btn.textContent = 'Saving…';

    fetch('/api/console/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ..._csrfHeaders() },
        body: JSON.stringify({ changes }),
    })
        .then(r => r.json().then(d => ({ ok: r.ok, data: d })))
        .then(({ ok, data }) => {
            if (!ok) throw new Error((data && data.detail) || 'Failed to save settings.');

            Object.entries(data.applied || {}).forEach(([key, pair]) => {
                if (_settingsByKey[key]) _settingsByKey[key].value = pair[1];
                const el = document.getElementById(`setting-${key}`);
                if (el) el.value = pair[1];
            });

            if (data.restart_scheduled) {
                const dismissRestarting = wsToast('Settings saved — restarting service…', 'info', 0);
                _pollHealthUntilBackUp(backUp => {
                    dismissRestarting();
                    if (backUp) {
                        wsToast('Service restarted successfully.', 'success');
                    } else {
                        wsToast('Service restart is taking longer than expected — refresh the page shortly.', 'error');
                    }
                });
            } else if (data.restart_required) {
                wsToast('Settings saved, but the automatic restart could not be scheduled — restart the service manually for this change to take effect.', 'error', 0);
            } else {
                wsToast('Settings saved.', 'success');
            }
            btn.disabled = false;
            btn.textContent = originalText;
        })
        .catch(err => {
            errorEl.textContent = err.message || 'Failed to save settings.';
            errorEl.style.display = 'block';
            btn.disabled = false;
            btn.textContent = originalText;
        });
}

async function regenerateCertificate() {
    const hostnameInput = document.getElementById('settings-cert-hostname');
    const errorEl = document.getElementById('settings-ssl-error');
    errorEl.style.display = 'none';
    const hostname = hostnameInput.value.trim();

    const ok = await wsConfirm({
        title: 'Regenerate certificate and restart?',
        message: 'This replaces the current self-signed certificate and restarts the service to load it. If you get the hostname wrong, browsers will show a certificate warning until you fix it and regenerate again.',
        confirmLabel: 'Regenerate & Restart',
        danger: true,
    });
    if (!ok) return;

    const btn = document.getElementById('settings-regen-cert-btn');
    btn.disabled = true;
    const originalText = btn.textContent;
    btn.textContent = 'Regenerating…';

    fetch('/api/console/settings/regenerate-cert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ..._csrfHeaders() },
        body: JSON.stringify({ hostname: hostname || null }),
    })
        .then(r => r.json().then(d => ({ ok: r.ok, data: d })))
        .then(({ ok, data }) => {
            if (!ok) throw new Error((data && data.detail) || 'Failed to regenerate certificate.');
            if (data.restart_scheduled) {
                const dismissRestarting = wsToast('Certificate regenerated — restarting service…', 'info', 0);
                _pollHealthUntilBackUp(backUp => {
                    dismissRestarting();
                    if (backUp) {
                        wsToast('Service restarted with the new certificate.', 'success');
                        loadSettings();
                    } else {
                        // Expected after a cert change: the browser refuses the
                        // new self-signed cert until the user re-accepts it, so
                        // the poll can never succeed from this page.
                        wsToast('Service restarted with the new certificate, but this page can no longer reach it — reload the page and re-accept the certificate warning if your browser shows one.', 'info', 0);
                    }
                });
            } else {
                wsToast('Certificate regenerated, but the automatic restart could not be scheduled — restart the service manually to load it.', 'error', 0);
            }
            btn.disabled = false;
            btn.textContent = originalText;
        })
        .catch(err => {
            errorEl.textContent = err.message || 'Failed to regenerate certificate.';
            errorEl.style.display = 'block';
            btn.disabled = false;
            btn.textContent = originalText;
        });
}

// Polls /health until the service is back up, then calls onDone(true) —
// or onDone(false) after ~20s of failures. Two subtleties:
//   - The restart fires ~2s AFTER the save response (systemd-run
//     --on-active=2), so polling immediately would hit the OLD process
//     and report success for a restart that hasn't happened yet. The
//     first poll therefore waits 4s.
//   - A restarting service refuses connections / fails the TLS handshake
//     (especially right after a cert regen) — network-level rejections,
//     not HTTP errors. Only a successful fetch means "back up".
function _pollHealthUntilBackUp(onDone) {
    const maxAttempts = 20;
    let attempt = 0;

    function retry() {
        attempt += 1;
        if (attempt >= maxAttempts) {
            onDone(false);
            return;
        }
        setTimeout(poll, 1000);
    }

    function poll() {
        fetch('/health', { cache: 'no-store' })
            .then(r => { r.ok ? onDone(true) : retry(); })
            .catch(retry);
    }

    setTimeout(poll, 4000);
}
