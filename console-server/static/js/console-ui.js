// console-ui.js — shared UI component layer for the admin console.
//
// Provides three building blocks used across the other console modules and an
// automatic accessibility enhancer for the existing modals. Nothing here makes
// network calls or touches application state; it is pure presentation.
//
//   wsToast(message, type)      — transient bottom-right notification
//   wsConfirm(opts) -> Promise  — in-app replacement for window.confirm
//   wsDebounce(fn, wait)        — trailing-edge debounce wrapper
//
// The modal enhancer watches every `.ws-modal-overlay` and, whenever one is
// shown, remembers the element that opened it, moves focus inside, traps Tab,
// and restores focus on close. It hooks the existing show/hide mechanism
// (inline `style.display`) via a MutationObserver, so none of the existing
// open/close functions had to change.

(function () {
    'use strict';

    // ── Focusable-element helper ─────────────────────────────────────────────
    const FOCUSABLE = [
        'a[href]', 'button:not([disabled])', 'input:not([disabled])',
        'select:not([disabled])', 'textarea:not([disabled])',
        '[tabindex]:not([tabindex="-1"])',
    ].join(',');

    function focusableWithin(container) {
        return Array.from(container.querySelectorAll(FOCUSABLE))
            .filter(el => el.offsetParent !== null || el === document.activeElement);
    }

    // ── Toasts ───────────────────────────────────────────────────────────────
    let _toastRegion = null;

    function _ensureToastRegion() {
        if (_toastRegion && document.body.contains(_toastRegion)) return _toastRegion;
        _toastRegion = document.createElement('div');
        _toastRegion.className = 'ws-toast-region';
        _toastRegion.setAttribute('role', 'status');
        _toastRegion.setAttribute('aria-live', 'polite');
        _toastRegion.setAttribute('aria-atomic', 'false');
        document.body.appendChild(_toastRegion);
        return _toastRegion;
    }

    const _TOAST_ICONS = {
        success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>',
        error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
        info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
    };

    function wsToast(message, type = 'info', timeout = 4500) {
        const region = _ensureToastRegion();
        const variant = _TOAST_ICONS[type] ? type : 'info';

        const toast = document.createElement('div');
        toast.className = `ws-toast ws-toast--${variant}`;

        const icon = document.createElement('span');
        icon.className = 'ws-toast-icon';
        icon.innerHTML = _TOAST_ICONS[variant]; // static markup, never user input
        toast.appendChild(icon);

        const body = document.createElement('span');
        body.className = 'ws-toast-body';
        body.textContent = message; // user/server text via textContent only
        toast.appendChild(body);

        const close = document.createElement('button');
        close.type = 'button';
        close.className = 'ws-toast-close';
        close.setAttribute('aria-label', 'Dismiss notification');
        close.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
        toast.appendChild(close);

        let removed = false;
        function dismiss() {
            if (removed) return;
            removed = true;
            toast.classList.add('ws-toast--leaving');
            setTimeout(() => toast.remove(), 220);
        }
        close.addEventListener('click', dismiss);
        region.appendChild(toast);
        if (timeout > 0) setTimeout(dismiss, timeout);
        return dismiss;
    }

    // ── Confirm dialog ────────────────────────────────────────────────────────
    // wsConfirm({ title, message, confirmLabel, cancelLabel, danger }) -> Promise<boolean>
    function wsConfirm(opts = {}) {
        const {
            title = 'Are you sure?',
            message = '',
            confirmLabel = 'Confirm',
            cancelLabel = 'Cancel',
            danger = false,
        } = opts;

        return new Promise(resolve => {
            const overlay = document.createElement('div');
            overlay.className = 'ws-modal-overlay';
            overlay.style.display = 'flex';

            const modal = document.createElement('div');
            modal.className = 'ws-modal ws-confirm-modal';
            modal.setAttribute('role', 'alertdialog');
            modal.setAttribute('aria-modal', 'true');
            const titleId = 'ws-confirm-title-' + Math.random().toString(36).slice(2, 8);
            modal.setAttribute('aria-labelledby', titleId);

            const header = document.createElement('div');
            header.className = 'ws-modal-header';
            const titleEl = document.createElement('h3');
            titleEl.className = 'ws-modal-title';
            titleEl.id = titleId;
            titleEl.textContent = title;
            header.appendChild(titleEl);
            modal.appendChild(header);

            if (message) {
                const bodyEl = document.createElement('div');
                bodyEl.className = 'ws-modal-body';
                const p = document.createElement('p');
                p.className = 'ws-confirm-message';
                p.textContent = message;
                bodyEl.appendChild(p);
                modal.appendChild(bodyEl);
            }

            const footer = document.createElement('div');
            footer.className = 'ws-modal-footer';
            const cancelBtn = document.createElement('button');
            cancelBtn.type = 'button';
            cancelBtn.className = 'btn btn-ghost';
            cancelBtn.textContent = cancelLabel;
            const confirmBtn = document.createElement('button');
            confirmBtn.type = 'button';
            confirmBtn.className = danger ? 'btn btn-danger' : 'btn btn-primary';
            confirmBtn.textContent = confirmLabel;
            footer.appendChild(cancelBtn);
            footer.appendChild(confirmBtn);
            modal.appendChild(footer);
            overlay.appendChild(modal);

            const opener = document.activeElement;
            function settle(result) {
                document.removeEventListener('keydown', onKey, true);
                overlay.remove();
                if (opener && typeof opener.focus === 'function') opener.focus();
                resolve(result);
            }
            function onKey(e) {
                if (e.key === 'Escape') { e.preventDefault(); settle(false); }
                else if (e.key === 'Tab') _trapTab(e, modal);
            }
            cancelBtn.addEventListener('click', () => settle(false));
            confirmBtn.addEventListener('click', () => settle(true));
            overlay.addEventListener('mousedown', e => { if (e.target === overlay) settle(false); });
            document.addEventListener('keydown', onKey, true);

            document.body.appendChild(overlay);
            confirmBtn.focus();
        });
    }

    // ── Tab trap helper (shared by confirm + modal enhancer) ───────────────────
    function _trapTab(e, container) {
        const items = focusableWithin(container);
        if (items.length === 0) return;
        const first = items[0];
        const last = items[items.length - 1];
        if (e.shiftKey && document.activeElement === first) {
            e.preventDefault();
            last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
            e.preventDefault();
            first.focus();
        }
    }

    // ── Debounce ───────────────────────────────────────────────────────────────
    function wsDebounce(fn, wait = 300) {
        let timer = null;
        return function (...args) {
            clearTimeout(timer);
            timer = setTimeout(() => fn.apply(this, args), wait);
        };
    }

    // ── Modal accessibility enhancer ─────────────────────────────────────────────
    // Tracks show/hide of the static `.ws-modal-overlay` elements (driven by the
    // existing code via inline display) and layers focus management on top.
    const _modalState = new WeakMap(); // overlay -> { opener, keyHandler }

    function _isShown(overlay) {
        return overlay.style.display && overlay.style.display !== 'none';
    }

    function _onModalShown(overlay) {
        if (_modalState.has(overlay)) return;
        const dialog = overlay.querySelector('.ws-modal') || overlay;
        const opener = document.activeElement;

        function keyHandler(e) {
            if (e.key === 'Tab') _trapTab(e, dialog);
        }
        document.addEventListener('keydown', keyHandler, true);
        _modalState.set(overlay, { opener, keyHandler });

        // Focus the first sensible control (skip the close button so the user
        // lands on a primary input/action where possible).
        const items = focusableWithin(dialog);
        const preferred = items.find(el => !el.classList.contains('ws-modal-close')) || items[0];
        if (preferred) setTimeout(() => preferred.focus(), 30);
    }

    function _onModalHidden(overlay) {
        const state = _modalState.get(overlay);
        if (!state) return;
        document.removeEventListener('keydown', state.keyHandler, true);
        if (state.opener && typeof state.opener.focus === 'function'
            && document.body.contains(state.opener)) {
            state.opener.focus();
        }
        _modalState.delete(overlay);
    }

    function _initModalEnhancer() {
        const overlays = Array.from(document.querySelectorAll('.ws-modal-overlay'));
        overlays.forEach(overlay => {
            // Initial state (in case one is somehow already visible).
            if (_isShown(overlay)) _onModalShown(overlay);
            const obs = new MutationObserver(() => {
                if (_isShown(overlay)) _onModalShown(overlay);
                else _onModalHidden(overlay);
            });
            obs.observe(overlay, { attributes: true, attributeFilter: ['style'] });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _initModalEnhancer);
    } else {
        _initModalEnhancer();
    }

    // ── Exports ──────────────────────────────────────────────────────────────────
    window.wsToast = wsToast;
    window.wsConfirm = wsConfirm;
    window.wsDebounce = wsDebounce;
})();
