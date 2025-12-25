import importlib
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient


def _load_app(tmp_path, monkeypatch, max_requests=2, window_seconds=60):
    # Point the app at an isolated temp directory and configure rate limits.
    monkeypatch.setenv("2FA_DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setenv("2FA_SSL_ENABLED", "false")
    monkeypatch.setenv("2FA_SECRET_KEY", "test-key")
    monkeypatch.setenv("2FA_RATE_LIMIT_MAX_REQUESTS", str(max_requests))
    monkeypatch.setenv("2FA_RATE_LIMIT_WINDOW", str(window_seconds))

    service_root = Path(__file__).parent.parent
    if str(service_root) not in sys.path:
        sys.path.insert(0, str(service_root))

    # Ensure we reload a fresh copy so the limiter state resets per test.
    if "app" in sys.modules:
        sys.modules.pop("app")
    app_module = importlib.import_module("app")
    importlib.reload(app_module)
    app_module.init_db()
    return app_module.app


def test_rate_limit_blocks_burst(tmp_path, monkeypatch):
    app = _load_app(tmp_path, monkeypatch, max_requests=2, window_seconds=60)
    client = TestClient(app)

    payload = {"client_id": "client-1"}

    first = client.post("/api/setup-start", data=payload)
    second = client.post("/api/setup-start", data=payload)
    third = client.post("/api/setup-start", data=payload)

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429
    assert third.json()["detail"] == "Too many requests, slow down"


def test_rate_limit_allows_after_window(tmp_path, monkeypatch):
    app = _load_app(tmp_path, monkeypatch, max_requests=1, window_seconds=1)
    client = TestClient(app)

    payload = {"client_id": "client-2"}

    first = client.post("/api/setup-start", data=payload)
    assert first.status_code == 200

    second = client.post("/api/setup-start", data=payload)
    assert second.status_code == 429

    time.sleep(1.2)
    third = client.post("/api/setup-start", data=payload)
    assert third.status_code == 200
