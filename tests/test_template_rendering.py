"""Template rendering smoke-tests.

Verifies that every Jinja2 template (auth pages and portal pages) renders
without raising a 500 error after the CSS refactor (inline <style> blocks
replaced with external <link> tags).

Checks per page:
  - HTTP 200 response
  - Content-Type: text/html
  - Correct external CSS link present in the HTML body
  - Key JS-bound IDs present (proves the HTML block survived the rewrite)
"""
import os
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("WS_2FA_SECRET_KEY", "wireshield-test-secret-key")
os.environ.setdefault("WS_CSRF_DISABLE", "1")
service_root = Path(__file__).parent.parent / "console-server"
if str(service_root) not in sys.path:
    sys.path.insert(0, str(service_root))

from fastapi.testclient import TestClient
from app.main import app
from app.core import database
from app.core.security import hash_session_token, rate_limiter


_client = TestClient(app)


@pytest.fixture
def client(tmp_db):
    rate_limiter._hits.clear()
    return _client


def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Helpers to set up DB state
# ---------------------------------------------------------------------------

def _insert_user(conn, client_id, *, wg_ipv4="testclient",
                 totp_secret=None, enabled=1, console_access=0):
    conn.execute(
        "INSERT INTO users "
        "(client_id, totp_secret, enabled, wg_ipv4, console_access) "
        "VALUES (?, ?, ?, ?, ?)",
        (client_id, totp_secret, enabled, wg_ipv4, console_access),
    )
    conn.commit()


def _insert_session(conn, client_id, *, expired=False):
    delta = timedelta(hours=-1) if expired else timedelta(hours=2)
    conn.execute(
        "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) "
        "VALUES (?, ?, ?, ?)",
        (client_id, hash_session_token("tok_abc"), _fmt(_now() + delta), "testclient"),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# GET / — captive portal root
# ---------------------------------------------------------------------------

class TestCaptivePortalRoot:
    def test_unknown_ip_renders_access_denied(self, client, tmp_db):
        """No user with IP='testclient' → access denied page (403)."""
        resp = client.get("/")
        assert resp.status_code == 403
        assert "text/html" in resp.headers["content-type"]
        body = resp.text
        assert "ws-portal.css" in body
        assert "Access Denied" in body
        assert "deny-card" in body

    def test_user_without_totp_renders_setup_page(self, client, tmp_db):
        """User exists with matching IP but no TOTP configured → 2FA setup."""
        conn = database.get_db()
        _insert_user(conn, "newuser", totp_secret=None)
        conn.close()

        resp = client.get("/")
        assert resp.status_code == 200
        body = resp.text
        assert "ws-auth.css" in body
        # JS-bound IDs from 2fa_setup.html
        assert 'id="generateBtn"' in body
        assert 'id="qrPlaceholder"' in body
        assert 'id="verifySection"' in body
        assert 'id="statusMessage"' in body

    def test_user_with_totp_no_session_renders_verify_page(self, client, tmp_db):
        """TOTP configured, no live session → 2FA verify (enter code) page."""
        conn = database.get_db()
        _insert_user(conn, "configured", totp_secret="JBSWY3DPEHPK3PXP")
        conn.close()

        resp = client.get("/")
        assert resp.status_code == 200
        body = resp.text
        assert "ws-auth.css" in body
        # JS-bound IDs from 2fa_verify.html
        assert 'id="verifyBtn"' in body
        assert 'id="authCode"' in body
        assert 'id="statusMessage"' in body

    def test_user_with_expired_session_renders_verify_page(self, client, tmp_db):
        """Expired session → must NOT grant access; renders verify page again."""
        conn = database.get_db()
        _insert_user(conn, "expired_user", totp_secret="JBSWY3DPEHPK3PXP")
        _insert_session(conn, "expired_user", expired=True)
        conn.close()

        resp = client.get("/")
        assert resp.status_code == 200
        body = resp.text
        assert "ws-auth.css" in body
        assert 'id="verifyBtn"' in body


# ---------------------------------------------------------------------------
# GET /success — post-auth landing page
# ---------------------------------------------------------------------------

class TestSuccessPage:
    def test_unknown_ip_renders_access_denied(self, client, tmp_db):
        """No valid session for this IP → access denied page (403)."""
        resp = client.get("/success")
        assert resp.status_code == 403
        body = resp.text
        assert "ws-portal.css" in body
        assert "Access Denied" in body

    def test_user_with_live_session_renders_success(self, client, tmp_db):
        conn = database.get_db()
        _insert_user(conn, "verified_user", totp_secret="JBSWY3DPEHPK3PXP", enabled=1)
        _insert_session(conn, "verified_user", expired=False)
        conn.close()

        resp = client.get("/success")
        assert resp.status_code == 200
        body = resp.text
        assert "ws-portal.css" in body
        assert "success-card" in body
        assert "Access Granted" in body
        assert "close-note" in body


# ---------------------------------------------------------------------------
# CSS link integrity — both stylesheets serve without 404
# ---------------------------------------------------------------------------

class TestStaticCSSAssets:
    def test_ws_auth_css_is_served(self, client, tmp_db):
        resp = client.get("/static/css/ws-auth.css")
        assert resp.status_code == 200
        assert "text/css" in resp.headers["content-type"]
        # Spot-check a token that must be in the file
        assert "--wa-blue" in resp.text

    def test_ws_portal_css_is_served(self, client, tmp_db):
        resp = client.get("/static/css/ws-portal.css")
        assert resp.status_code == 200
        assert "text/css" in resp.headers["content-type"]
        assert "--wp-blue" in resp.text

    def test_ws_design_system_css_is_served(self, client, tmp_db):
        resp = client.get("/static/css/ws-design-system.css")
        assert resp.status_code == 200
        assert "text/css" in resp.headers["content-type"]
        assert "--ws-blue" in resp.text
