from fastapi.responses import HTMLResponse

def get_2fa_ui_html(client_id: str) -> HTMLResponse:
    return HTMLResponse(f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireShield — 2FA Setup</title>
    <style>
        @font-face {{ font-family: 'Inter'; font-weight: 400; src: url('/static/fonts/Inter-Regular.woff2') format('woff2'); font-display: swap; }}
        @font-face {{ font-family: 'Inter'; font-weight: 600; src: url('/static/fonts/Inter-SemiBold.woff2') format('woff2'); font-display: swap; }}
        @font-face {{ font-family: 'Inter'; font-weight: 700; src: url('/static/fonts/Inter-Bold.woff2') format('woff2'); font-display: swap; }}
        :root {{
            --bg: #f1f5f9;
            --card: #ffffff;
            --card-alt: #f8fafc;
            --text: #1e293b;
            --muted: #64748b;
            --accent: #2563eb;
            --accent-hover: #1d4ed8;
            --success: #16a34a;
            --error: #dc2626;
            --border: #e2e8f0;
            --radius: 12px;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 24px;
        }}
        .wrapper {{
            max-width: 880px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border);
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .logo {{
            width: 42px;
            height: 42px;
            border-radius: 10px;
            background: var(--accent);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 16px;
            color: #fff;
        }}
        .brand-text h1 {{
            font-size: 18px;
            font-weight: 600;
            color: var(--text);
        }}
        .brand-text p {{
            font-size: 13px;
            color: var(--muted);
            margin-top: 2px;
        }}
        .secure-badge {{
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 12px;
            color: var(--muted);
            background: var(--card);
            padding: 6px 12px;
            border-radius: 20px;
            border: 1px solid var(--border);
        }}
        .secure-badge svg {{ width: 14px; height: 14px; color: var(--success); }}
        .grid {{
            display: grid;
            grid-template-columns: 1fr 340px;
            gap: 20px;
        }}
        .card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 24px;
        }}
        .card-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
        }}
        .card-header h2 {{
            font-size: 15px;
            font-weight: 600;
        }}
        .badge {{
            font-size: 11px;
            font-weight: 500;
            padding: 4px 10px;
            border-radius: 20px;
            background: #dbeafe;
            color: var(--accent);
        }}
        .client-info {{
            background: var(--card-alt);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 14px;
            font-family: 'SF Mono', 'Consolas', monospace;
            font-size: 13px;
            color: var(--text);
            margin-bottom: 16px;
        }}
        .steps {{
            display: flex;
            gap: 8px;
            margin-bottom: 20px;
        }}
        .step {{
            flex: 1;
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 12px;
            background: var(--card-alt);
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 12px;
            color: var(--muted);
        }}
        .step.active {{
            background: #dbeafe;
            border-color: #93c5fd;
            color: var(--accent);
        }}
        .step-num {{
            width: 22px;
            height: 22px;
            border-radius: 6px;
            background: var(--card);
            border: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 11px;
        }}
        .step.active .step-num {{
            background: var(--accent);
            border-color: var(--accent);
            color: #fff;
        }}
        .section {{
            margin-bottom: 20px;
        }}
        .section-label {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 13px;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 10px;
        }}
        .section-label .num {{
            width: 20px;
            height: 20px;
            border-radius: 50%;
            background: var(--accent);
            color: #fff;
            font-size: 11px;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .btn {{
            width: 100%;
            padding: 11px 16px;
            font-size: 14px;
            font-weight: 500;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.15s ease;
        }}
        .btn-primary {{
            background: var(--accent);
            color: #fff;
        }}
        .btn-primary:hover {{ background: var(--accent-hover); }}
        .btn-primary:disabled {{ background: #94a3b8; cursor: not-allowed; }}
        .qr-box {{
            display: none;
            text-align: center;
            margin-top: 16px;
        }}
        .qr-box img {{
            width: 180px;
            height: 180px;
            border-radius: 10px;
            border: 1px solid var(--border);
            background: #fff;
            padding: 8px;
        }}
        .secret-box {{
            display: none;
            margin-top: 12px;
            background: var(--card-alt);
            border: 1px dashed var(--border);
            border-radius: 8px;
            padding: 12px;
            font-family: 'SF Mono', 'Consolas', monospace;
            font-size: 12px;
            color: var(--text);
            word-break: break-all;
            text-align: center;
        }}
        label {{
            display: block;
            font-size: 13px;
            font-weight: 500;
            color: var(--text);
            margin-bottom: 6px;
        }}
        input[type="text"] {{
            width: 100%;
            padding: 10px 14px;
            font-size: 14px;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: #fff;
            color: var(--text);
            outline: none;
            transition: border-color 0.15s, box-shadow 0.15s;
        }}
        input[type="text"]:focus {{
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }}
        .alert {{
            display: none;
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 13px;
            margin-top: 12px;
        }}
        .alert-success {{
            background: #dcfce7;
            border: 1px solid #bbf7d0;
            color: #166534;
        }}
        .alert-error {{
            background: #fee2e2;
            border: 1px solid #fecaca;
            color: #991b1b;
        }}
        .info-card {{
            background: var(--card-alt);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            font-size: 13px;
            color: var(--muted);
            line-height: 1.5;
            margin-bottom: 16px;
        }}
        .tags {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 16px;
        }}
        .tag {{
            font-size: 11px;
            padding: 5px 10px;
            border-radius: 6px;
            background: var(--card-alt);
            border: 1px solid var(--border);
            color: var(--muted);
        }}
        .spinner {{
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid rgba(255,255,255,0.3);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin-right: 8px;
            vertical-align: middle;
        }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        @media (max-width: 800px) {{
            .grid {{ grid-template-columns: 1fr; }}
            .header {{ flex-direction: column; align-items: flex-start; gap: 12px; }}
            .steps {{ flex-direction: column; }}
        }}
    </style>
</head>
<body onload="init()">
    <div class="wrapper">
        <div class="header">
            <div class="brand">
                <img src="/static/logo.svg" alt="WireShield" style="width:42px;height:42px;">
                <div class="brand-text">
                    <h1>WireShield 2FA Setup</h1>
                    <p>Configure two-factor authentication for VPN access</p>
                </div>
            </div>
            <div class="secure-badge">
                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                Secure TLS Connection
            </div>
        </div>
        <div class="grid">
            <div class="card">
                <div class="card-header">
                    <h2>Authentication Setup</h2>
                    <span class="badge">Required</span>
                </div>
                <div class="client-info">Client ID: {client_id}</div>
                <div class="steps">
                    <div class="step active"><span class="step-num">1</span>Generate QR</div>
                    <div class="step active"><span class="step-num">2</span>Scan Code</div>
                    <div class="step"><span class="step-num">3</span>Verify</div>
                </div>

                <div id="setupPhase">
                    <div class="section">
                        <div class="section-label"><span class="num">1</span>Generate QR Code</div>
                        <button class="btn btn-primary" onclick="generateQR()">Generate QR Code</button>
                        <div class="qr-box" id="qrBox">
                            <img id="qrImage" src="" alt="QR Code">
                        </div>
                        <div class="secret-box" id="secretBox"></div>
                    </div>

                    <div class="section">
                        <div class="section-label"><span class="num">2</span>Enter Verification Code</div>
                        <label for="code">6-digit code from your authenticator app</label>
                        <input type="text" id="code" placeholder="000000" maxlength="6" inputmode="numeric" autocomplete="one-time-code">
                        <button class="btn btn-primary" id="verifyBtn" onclick="verify()" style="margin-top: 12px;">Verify &amp; Continue</button>
                        <div id="successMsg" class="alert alert-success"></div>
                        <div id="errorMsg" class="alert alert-error"></div>
                    </div>

                    <div class="tags">
                        <span class="tag">24h session</span>
                        <span class="tag">No code stored server-side</span>
                        <span class="tag">Time drift tolerant</span>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2>Setup Guide</h2>
                </div>
                <div class="info-card">
                    <strong>Step 1:</strong> Click "Generate QR Code" to create your unique authentication code.
                </div>
                <div class="info-card">
                    <strong>Step 2:</strong> Open your authenticator app (Google Authenticator, 1Password, Authy, etc.) and scan the QR code.
                </div>
                <div class="info-card">
                    <strong>Step 3:</strong> Enter the 6-digit code displayed in your authenticator app to complete verification.
                </div>
                <div class="info-card" style="background: #fef9c3; border-color: #fde047;">
                    <strong>Note:</strong> Ensure your device clock is accurate. Codes refresh every 30 seconds.
                </div>
                <div class="tags">
                    <span class="tag">TLS enforced</span>
                    <span class="tag">Rate limited</span>
                    <span class="tag">Audit logged</span>
                </div>
            </div>
        </div>
    </div>

    <script>
        function init() {{
            document.getElementById('code').focus();
            document.addEventListener('keydown', e => {{ if (e.key === 'Enter') verify(); }});
        }}

        async function generateQR() {{
            hide('errorMsg'); hide('successMsg');
            const form = new FormData();
            form.append('client_id', '{client_id}');
            try {{
                const res = await fetch('/api/setup-start', {{ method: 'POST', body: form }});
                const data = await res.json();
                if (data.success) {{
                    document.getElementById('qrImage').src = data.qr_code;
                    document.getElementById('secretBox').textContent = 'Manual entry: ' + data.secret;
                    show('qrBox'); show('secretBox');
                    showSuccess('QR code generated. Scan it with your authenticator app.');
                }} else {{
                    showError(data.detail || 'Failed to generate QR code');
                }}
            }} catch (e) {{
                showError('Network error: ' + e.message);
            }}
        }}

        async function verify() {{
            const code = document.getElementById('code').value.trim();
            if (!/^\\d{{6}}$/.test(code)) {{ showError('Enter a valid 6-digit code'); return; }}
            hide('errorMsg'); hide('successMsg');
            const btn = document.getElementById('verifyBtn');
            const orig = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span>Verifying...';
            try {{
                const form = new FormData();
                form.append('client_id', '{client_id}');
                form.append('code', code);
                const res = await fetch('/api/setup-verify', {{ method: 'POST', body: form }});
                const data = await res.json();
                if (data.success) {{
                    localStorage.setItem('session_token', data.session_token);
                    localStorage.setItem('client_id', '{client_id}');
                    showSuccess('Verification successful! Redirecting...');
                    setTimeout(() => window.location.href = '/success?client_id={client_id}', 1200);
                }} else {{
                    showError(data.detail || 'Verification failed');
                    btn.disabled = false;
                    btn.innerHTML = orig;
                }}
            }} catch (e) {{
                showError('Network error: ' + e.message);
                btn.disabled = false;
                btn.innerHTML = orig;
            }}
        }}

        function show(id) {{ document.getElementById(id).style.display = 'block'; }}
        function hide(id) {{ document.getElementById(id).style.display = 'none'; }}
        function showError(msg) {{ const el = document.getElementById('errorMsg'); el.textContent = msg; el.style.display = 'block'; }}
        function showSuccess(msg) {{ const el = document.getElementById('successMsg'); el.textContent = msg; el.style.display = 'block'; }}
    </script>
</body>
</html>
    """)

def get_2fa_verify_only_html(client_id: str) -> HTMLResponse:
    return HTMLResponse(f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireShield — Verify Access</title>
    <style>
        @font-face {{ font-family: 'Inter'; font-weight: 400; src: url('/static/fonts/Inter-Regular.woff2') format('woff2'); font-display: swap; }}
        @font-face {{ font-family: 'Inter'; font-weight: 600; src: url('/static/fonts/Inter-SemiBold.woff2') format('woff2'); font-display: swap; }}
        @font-face {{ font-family: 'Inter'; font-weight: 700; src: url('/static/fonts/Inter-Bold.woff2') format('woff2'); font-display: swap; }}
        :root {{
            --bg: #f1f5f9;
            --card: #ffffff;
            --card-alt: #f8fafc;
            --text: #1e293b;
            --muted: #64748b;
            --accent: #2563eb;
            --accent-hover: #1d4ed8;
            --success: #16a34a;
            --error: #dc2626;
            --border: #e2e8f0;
            --radius: 12px;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }}
        .container {{
            width: 100%;
            max-width: 420px;
        }}
        .header {{
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            gap: 12px;
            margin-bottom: 24px;
        }}
        .logo {{
            width: 48px;
            height: 48px;
            border-radius: 12px;
            background: var(--accent);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 18px;
            color: #fff;
        }}
        .header-text h1 {{
            font-size: 20px;
            font-weight: 600;
            color: var(--text);
        }}
        .header-text p {{
            font-size: 13px;
            color: var(--muted);
            margin-top: 4px;
        }}
        .card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 24px;
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.06);
        }}
        .card-title {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
        }}
        .card-title h2 {{
            font-size: 15px;
            font-weight: 600;
        }}
        .badge {{
            font-size: 11px;
            font-weight: 500;
            padding: 4px 10px;
            border-radius: 20px;
            background: #dcfce7;
            color: var(--success);
        }}
        .client-info {{
            background: var(--card-alt);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px 14px;
            font-family: 'SF Mono', 'Consolas', monospace;
            font-size: 12px;
            color: var(--muted);
            margin-bottom: 16px;
        }}
        label {{
            display: block;
            font-size: 13px;
            font-weight: 500;
            color: var(--text);
            margin-bottom: 6px;
        }}
        input {{
            width: 100%;
            padding: 12px 14px;
            font-size: 16px;
            letter-spacing: 4px;
            text-align: center;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: #fff;
            color: var(--text);
            outline: none;
            transition: border-color 0.15s, box-shadow 0.15s;
        }}
        input:focus {{
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }}
        input::placeholder {{
            letter-spacing: 2px;
            color: #cbd5e1;
        }}
        .btn {{
            width: 100%;
            padding: 12px 16px;
            font-size: 14px;
            font-weight: 500;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.15s ease;
            margin-top: 12px;
            background: var(--accent);
            color: #fff;
        }}
        .btn:hover {{ background: var(--accent-hover); }}
        .btn:disabled {{ background: #94a3b8; cursor: not-allowed; }}
        .alert {{
            display: none;
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 13px;
            margin-top: 12px;
        }}
        .alert-success {{
            background: #dcfce7;
            border: 1px solid #bbf7d0;
            color: #166534;
        }}
        .alert-error {{
            background: #fee2e2;
            border: 1px solid #fecaca;
            color: #991b1b;
        }}
        .info {{
            background: var(--card-alt);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 14px;
            font-size: 13px;
            color: var(--muted);
            line-height: 1.5;
            margin-top: 16px;
        }}
        .tags {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 16px;
        }}
        .tag {{
            font-size: 11px;
            padding: 5px 10px;
            border-radius: 6px;
            background: var(--card-alt);
            border: 1px solid var(--border);
            color: var(--muted);
        }}
        .spinner {{
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid rgba(255,255,255,0.3);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin-right: 8px;
            vertical-align: middle;
        }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body onload="init()">
    <div class="container">
        <div class="header">
            <img src="/static/logo.svg" alt="WireShield" style="width:60px;height:60px;">
            <div class="header-text">
                <h1>WireShield Verification</h1>
                <p>Enter your authenticator code to connect</p>
            </div>
        </div>
        <div class="card">
            <div class="card-title">
                <h2>Two-Factor Authentication</h2>
                <span class="badge">Configured</span>
            </div>
            <div class="client-info">Client: {client_id}</div>
            <label for="code">Enter 6-digit code</label>
            <input type="text" id="code" maxlength="6" inputmode="numeric" placeholder="000000" autocomplete="one-time-code">
            <button class="btn" id="verifyBtn" onclick="verify()">Verify &amp; Connect</button>
            <div id="ok" class="alert alert-success"></div>
            <div id="err" class="alert alert-error"></div>
            <div class="info">
                Open your authenticator app and enter the current code for WireShield. Codes refresh every 30 seconds.
            </div>
            <div class="tags">
                <span class="tag">TLS secured</span>
                <span class="tag">Rate limited</span>
                <span class="tag">24h session</span>
            </div>
        </div>
    </div>
    <script>
        function init() {{
            document.getElementById('code').focus();
            document.addEventListener('keydown', e => {{ if (e.key === 'Enter') verify(); }});
        }}
        async function verify() {{
            const code = document.getElementById('code').value.trim();
            const ok = document.getElementById('ok');
            const err = document.getElementById('err');
            ok.style.display = 'none';
            err.style.display = 'none';
            if (!/^\\d{{6}}$/.test(code)) {{
                err.textContent = 'Please enter a valid 6-digit code';
                err.style.display = 'block';
                return;
            }}
            const btn = document.getElementById('verifyBtn');
            const orig = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span>Verifying...';
            try {{
                const form = new FormData();
                form.append('client_id', '{client_id}');
                form.append('code', code);
                const res = await fetch('/api/verify', {{ method: 'POST', body: form }});
                const data = await res.json();
                if (data.success) {{
                    localStorage.setItem('session_token', data.session_token);
                    localStorage.setItem('client_id', '{client_id}');
                    ok.textContent = 'Verification successful! Connecting...';
                    ok.style.display = 'block';
                    setTimeout(() => window.location.href = '/success?client_id={client_id}', 1000);
                }} else {{
                    err.textContent = data.detail || 'Invalid code. Please try again.';
                    err.style.display = 'block';
                    btn.disabled = false;
                    btn.innerHTML = orig;
                }}
            }} catch (e) {{
                err.textContent = 'Network error: ' + e.message;
                err.style.display = 'block';
                btn.disabled = false;
                btn.innerHTML = orig;
            }}
        }}
    </script>
</body>
</html>
    """)

def get_success_html() -> HTMLResponse:
    return HTMLResponse("""
<!DOCTYPE html>
<html lang="en">
<head>
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireShield — Connected</title>
    <style>
        @font-face { font-family: 'Inter'; font-weight: 400; src: url('/static/fonts/Inter-Regular.woff2') format('woff2'); font-display: swap; }
        @font-face { font-family: 'Inter'; font-weight: 600; src: url('/static/fonts/Inter-SemiBold.woff2') format('woff2'); font-display: swap; }
        @font-face { font-family: 'Inter'; font-weight: 700; src: url('/static/fonts/Inter-Bold.woff2') format('woff2'); font-display: swap; }
        :root {
            --bg: #f8fafc;
            --card: #ffffff;
            --text: #1e293b;
            --muted: #64748b;
            --accent: #2563eb;
            --success: #16a34a;
            --border: #e2e8f0;
            --radius: 12px;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }
        .container {
            width: 100%;
            max-width: 420px;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.06);
            padding: 32px;
            text-align: center;
        }
        .icon {
            width: 64px;
            height: 64px;
            margin: 0 auto 20px;
            background: #dcfce7;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .icon svg { width: 32px; height: 32px; color: var(--success); }
        h1 { font-size: 20px; font-weight: 600; margin-bottom: 8px; color: var(--text); }
        .subtitle { font-size: 14px; color: var(--muted); margin-bottom: 24px; }
        .status-box {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 20px;
        }
        .status-item { display: flex; align-items: center; gap: 8px; font-size: 14px; color: #166534; padding: 4px 0; }
        .status-item svg { width: 16px; height: 16px; flex-shrink: 0; }
        .note { font-size: 13px; color: var(--muted); line-height: 1.5; }
        .btn {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 24px;
            background: var(--accent);
            color: white;
            font-size: 14px;
            font-weight: 500;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            text-decoration: none;
        }
        .btn:hover { background: #1d4ed8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">
            <svg fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>
        </div>
        <h1>Verification Successful</h1>
        <p class="subtitle">Your two-factor authentication is complete.</p>
        <div class="status-box">
            <div class="status-item"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg> VPN connection is now active</div>
            <div class="status-item"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg> Full internet access enabled</div>
            <div class="status-item"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg> Session valid for 24 hours</div>
        </div>
        <p class="note">You can close this window and continue using your secure VPN connection.</p>
        <button class="btn" onclick="closeWindow();">Close Window</button>
    </div>
    <script>
        function closeWindow() {
            window.close();
            setTimeout(function() {
                if (!window.closed) {
                    alert('Please close this tab manually to continue.');
                }
            }, 100);
        }
    </script>
</body>
</html>
    """)

def get_access_denied_html() -> HTMLResponse:
    return HTMLResponse(
            """
<!DOCTYPE html>
<html lang="en">
<head>
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied | WireShield</title>
    <style>
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 400; font-display: swap; src: url('/static/fonts/Inter-Regular.woff2') format('woff2'); }
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 600; font-display: swap; src: url('/static/fonts/Inter-SemiBold.woff2') format('woff2'); }
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 700; font-display: swap; src: url('/static/fonts/Inter-Bold.woff2') format('woff2'); }
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 900; font-display: swap; src: url('/static/fonts/Inter-Black.woff2') format('woff2'); }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            min-height: 100vh;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 50%, #16213e 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            position: relative;
        }
        
        /* Animated background grid */
        body::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image: 
                linear-gradient(rgba(255,0,60,0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,0,60,0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            animation: gridPulse 4s ease-in-out infinite;
        }
        
        @keyframes gridPulse {
            0%, 100% { opacity: 0.3; }
            50% { opacity: 0.6; }
        }
        
        /* Glowing orb effect */
        .glow-orb {
            position: absolute;
            width: 400px;
            height: 400px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(220,38,38,0.15) 0%, transparent 70%);
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            animation: orbPulse 3s ease-in-out infinite;
        }
        
        @keyframes orbPulse {
            0%, 100% { transform: translate(-50%, -50%) scale(1); opacity: 0.5; }
            50% { transform: translate(-50%, -50%) scale(1.2); opacity: 0.8; }
        }
        
        .container {
            position: relative;
            z-index: 10;
            text-align: center;
            padding: 3rem;
            max-width: 520px;
        }
        
        /* Shield icon with warning */
        .shield-icon {
            width: 120px;
            height: 120px;
            margin: 0 auto 2rem;
            position: relative;
        }
        
        .shield-icon svg {
            width: 100%;
            height: 100%;
            filter: drop-shadow(0 0 30px rgba(220,38,38,0.5));
            animation: shieldGlow 2s ease-in-out infinite;
        }
        
        @keyframes shieldGlow {
            0%, 100% { filter: drop-shadow(0 0 20px rgba(220,38,38,0.4)); }
            50% { filter: drop-shadow(0 0 40px rgba(220,38,38,0.7)); }
        }
        
        .error-code {
            font-size: 0.875rem;
            font-weight: 600;
            letter-spacing: 0.3em;
            color: #dc2626;
            text-transform: uppercase;
            margin-bottom: 1rem;
            opacity: 0.9;
        }
        
        h1 {
            font-size: 2.5rem;
            font-weight: 900;
            color: #ffffff;
            margin-bottom: 1rem;
            letter-spacing: -0.02em;
            text-shadow: 0 0 40px rgba(220,38,38,0.3);
        }
        
        .subtitle {
            font-size: 1.125rem;
            color: #94a3b8;
            margin-bottom: 2.5rem;
            line-height: 1.6;
        }
        
        .warning-box {
            background: rgba(220,38,38,0.1);
            border: 1px solid rgba(220,38,38,0.3);
            border-radius: 12px;
            padding: 1.25rem 1.5rem;
            margin-bottom: 2rem;
        }
        
        .warning-box p {
            color: #f87171;
            font-size: 0.9rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }
        
        .info-text {
            font-size: 0.875rem;
            color: #64748b;
            line-height: 1.7;
        }
        
        .info-text strong {
            color: #94a3b8;
        }
        
        /* Decorative corners */
        .corner {
            position: fixed;
            width: 100px;
            height: 100px;
            border: 2px solid rgba(220,38,38,0.2);
        }
        
        .corner-tl { top: 20px; left: 20px; border-right: none; border-bottom: none; }
        .corner-tr { top: 20px; right: 20px; border-left: none; border-bottom: none; }
        .corner-bl { bottom: 20px; left: 20px; border-right: none; border-top: none; }
        .corner-br { bottom: 20px; right: 20px; border-left: none; border-top: none; }
        
        .brand {
            position: fixed;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 0.75rem;
            color: #475569;
            letter-spacing: 0.1em;
        }
    </style>
</head>
<body>
    <div class="glow-orb"></div>
    <div class="corner corner-tl"></div>
    <div class="corner corner-tr"></div>
    <div class="corner corner-bl"></div>
    <div class="corner corner-br"></div>
    
    <div class="container">
        <div class="shield-icon">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L3 7V12C3 17.55 6.84 22.74 12 24C17.16 22.74 21 17.55 21 12V7L12 2Z" 
                      fill="url(#shieldGrad)" stroke="#dc2626" stroke-width="0.5"/>
                <path d="M12 8V13M12 16V16.01" stroke="#ffffff" stroke-width="2" stroke-linecap="round"/>
                <defs>
                    <linearGradient id="shieldGrad" x1="12" y1="2" x2="12" y2="24" gradientUnits="userSpaceOnUse">
                        <stop offset="0%" stop-color="#7f1d1d"/>
                        <stop offset="100%" stop-color="#450a0a"/>
                    </linearGradient>
                </defs>
            </svg>
        </div>
        
        <div class="error-code">Security Alert</div>
        <h1>Access Denied</h1>
        <p class="subtitle">This portal is restricted to authorized VPN clients only.</p>
        
        <div class="warning-box">
            <p>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="12" y1="8" x2="12" y2="12"/>
                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                Your connection was not recognized
            </p>
        </div>
        
        <p class="info-text">
            To access this service, you must be connected through <strong>WireShield VPN</strong>. 
            If you believe this is an error, verify your VPN connection and try again.
        </p>
    </div>
    
    <div class="brand">WIRESHIELD SECURITY</div>
</body>
</html>
            """,
            status_code=403
        )
