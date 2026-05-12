"""Tests for database initialisation, schema correctness, and WAL mode."""
import os
import sys
from pathlib import Path

os.environ.setdefault("WS_2FA_SECRET_KEY", "wireshield-test-secret-key")
service_root = Path(__file__).parent.parent / "console-server"
if str(service_root) not in sys.path:
    sys.path.insert(0, str(service_root))

from app.core import database


def test_init_db_creates_all_tables(tmp_db):
    conn = database.get_db()
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = {row[0] for row in c.fetchall()}
    conn.close()

    expected = {
        "users", "sessions", "bandwidth_usage", "audit_log", "dns_cache",
        "activity_log", "totp_used_codes", "activity_log_metrics",
        "network_policies", "agents", "agent_enrollment_tokens",
        "agent_heartbeats", "agent_user_access",
    }
    assert expected.issubset(tables)


def test_init_db_idempotent(tmp_path):
    """Calling init_db twice on the same file must not raise or corrupt the schema."""
    db_path = tmp_path / "idempotent.db"
    old_path = database.AUTH_DB_PATH
    database.AUTH_DB_PATH = str(db_path)
    try:
        database.init_db()
        database.init_db()  # second call must be a no-op
        conn = database.get_db()
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        conn.close()
        assert "users" in tables
    finally:
        database.AUTH_DB_PATH = old_path


def test_wal_mode_enabled(tmp_db):
    conn = database.get_db()
    row = conn.execute("PRAGMA journal_mode").fetchone()
    conn.close()
    assert row[0].lower() == "wal"


def test_synchronous_normal_set(tmp_db):
    conn = database.get_db()
    row = conn.execute("PRAGMA synchronous").fetchone()
    conn.close()
    # NORMAL = 1
    assert row[0] == 1


def test_foreign_keys_enabled(tmp_db):
    conn = database.get_db()
    row = conn.execute("PRAGMA foreign_keys").fetchone()
    conn.close()
    assert row[0] == 1


def test_performance_indexes_created(tmp_db):
    conn = database.get_db()
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='index'")
    indexes = {row[0] for row in c.fetchall()}
    conn.close()

    required = {
        "idx_sessions_client_expires",
        "idx_audit_log_timestamp",
        "idx_audit_log_client",
        "idx_activity_log_timestamp",
        "idx_activity_log_client",
        "idx_agents_status",
        "idx_agent_heartbeats_agent_time",
        "idx_totp_used_codes",
    }
    assert required.issubset(indexes)


def test_users_table_columns(tmp_db):
    conn = database.get_db()
    row = conn.execute("PRAGMA table_info(users)").fetchall()
    conn.close()
    cols = {r[1] for r in row}
    assert {"id", "client_id", "totp_secret", "enabled", "console_access",
            "wg_ipv4", "wg_ipv6", "created_at"}.issubset(cols)


def test_sessions_table_columns(tmp_db):
    conn = database.get_db()
    row = conn.execute("PRAGMA table_info(sessions)").fetchall()
    conn.close()
    cols = {r[1] for r in row}
    assert {"id", "client_id", "session_token", "expires_at", "device_ip"}.issubset(cols)


def test_agents_table_has_heartbeat_secret_hash(tmp_db):
    """Migration column must be present after init_db."""
    conn = database.get_db()
    row = conn.execute("PRAGMA table_info(agents)").fetchall()
    conn.close()
    cols = {r[1] for r in row}
    assert "heartbeat_secret_hash" in cols
    assert "is_restricted" in cols
