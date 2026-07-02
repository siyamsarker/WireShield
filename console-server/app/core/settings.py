"""
Server settings — read/write the two flat KEY=value config files the app
and installer already use (/etc/wireshield/2fa/config.env, loaded into the
process via systemd's EnvironmentFile= at restart; /etc/wireguard/params,
re-read fresh by wireguard.py on every WireGuard operation), plus the
restart needed for a config.env change to take effect.

SETTINGS_SCHEMA is the single source of truth for every editable field —
its label, validation rule, target file, and whether it needs a restart.
GET /api/console/settings and POST /api/console/settings both drive off
this one list instead of duplicating that per field.

Security note: both config.env and params are `source`d as shell scripts
by root elsewhere (wireshield.sh, generate-certs.sh), so a value that
reaches disk unvalidated is a root command-injection vector the next time
either file is sourced. Every field type below has a strict validator that
must pass before anything is written — this is a hard requirement, not a
nicety.
"""
import ipaddress
import os
import re
import subprocess
from typing import Any, Dict, List, Optional

from app.core import config as cfg
from app.core.wireguard import _load_params as _load_wg_params
from app.core.wireguard import WG_PARAMS_PATH

CONFIG_ENV_PATH = "/etc/wireshield/2fa/config.env"

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))          # .../app/core
_SERVICE_ROOT = os.path.dirname(os.path.dirname(_THIS_DIR))      # .../console-server (or /etc/wireshield/2fa)
GENERATE_CERTS_SCRIPT = os.path.join(_SERVICE_ROOT, "generate-certs.sh")

_HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

SETTINGS_SCHEMA: List[Dict[str, Any]] = [
    # ── WireGuard Client Defaults — /etc/wireguard/params, live, new clients only ──
    {
        "key": "client_dns_1", "env_var": "CLIENT_DNS_1", "file": "wg_params",
        "category": "wireguard", "label": "Primary Client DNS",
        "description": "DNS server pushed to newly created clients. Existing clients keep their original config.",
        "type": "ip", "default": "1.1.1.1", "restart_required": False,
    },
    {
        "key": "client_dns_2", "env_var": "CLIENT_DNS_2", "file": "wg_params",
        "category": "wireguard", "label": "Secondary Client DNS",
        "description": "Fallback DNS server for newly created clients.",
        "type": "ip", "default": "1.0.0.1", "restart_required": False,
    },
    {
        "key": "allowed_ips", "env_var": "ALLOWED_IPS", "file": "wg_params",
        "category": "wireguard", "label": "Default Allowed IPs",
        "description": "Comma-separated CIDR ranges routed through the VPN for new clients (0.0.0.0/0,::/0 = full tunnel).",
        "type": "cidr_list", "default": "0.0.0.0/0,::/0", "restart_required": False,
    },
    # ── Session & Security — config.env, restart required ──
    {
        "key": "session_timeout_minutes", "env_var": "WS_2FA_SESSION_TIMEOUT", "file": "config_env",
        "category": "session", "label": "Session Lifetime",
        "description": "Minutes before a client must re-verify with TOTP.",
        "type": "int", "min": 5, "max": 43200, "unit": "minutes", "restart_required": True,
        "current": lambda: cfg.SESSION_TIMEOUT_MINUTES,
    },
    {
        "key": "session_idle_timeout_seconds", "env_var": "WS_2FA_SESSION_IDLE_TIMEOUT", "file": "config_env",
        "category": "session", "label": "Idle Timeout (Connected)",
        "description": "How stale a WireGuard handshake may be, while still connected, before the session is treated as idle.",
        "type": "int", "min": 60, "max": 86400, "unit": "seconds", "restart_required": True,
        "current": lambda: cfg.SESSION_IDLE_TIMEOUT_SECONDS,
    },
    {
        "key": "disconnect_grace_seconds", "env_var": "WS_2FA_DISCONNECT_GRACE_SECONDS", "file": "config_env",
        "category": "session", "label": "Disconnect Grace Period",
        "description": "Seconds without any handshake before a session is revoked.",
        "type": "int", "min": 60, "max": 86400, "unit": "seconds", "restart_required": True,
        "current": lambda: cfg.DISCONNECT_GRACE_SECONDS,
    },
    # ── Rate Limiting — config.env, restart required ──
    {
        "key": "rate_limit_max_requests", "env_var": "WS_2FA_RATE_LIMIT_MAX_REQUESTS", "file": "config_env",
        "category": "rate_limit", "label": "Max Requests",
        "description": "Maximum requests allowed per client within the rate-limit window.",
        "type": "int", "min": 1, "max": 10000, "restart_required": True,
        "current": lambda: cfg.RATE_LIMIT_MAX_REQUESTS,
    },
    {
        "key": "rate_limit_window_seconds", "env_var": "WS_2FA_RATE_LIMIT_WINDOW", "file": "config_env",
        "category": "rate_limit", "label": "Window Length",
        "description": "Length of the rate-limit window.",
        "type": "int", "min": 1, "max": 3600, "unit": "seconds", "restart_required": True,
        "current": lambda: cfg.RATE_LIMIT_WINDOW_SECONDS,
    },
    # ── Logging & Retention — config.env, restart required ──
    {
        "key": "log_level", "env_var": "WS_2FA_LOG_LEVEL", "file": "config_env",
        "category": "logging", "label": "Log Level",
        "description": "Verbosity of the service's application log.",
        "type": "enum", "choices": ["DEBUG", "INFO", "WARNING", "ERROR"], "restart_required": True,
        "current": lambda: cfg.LOG_LEVEL,
    },
    {
        "key": "activity_log_retention_days", "env_var": "WS_2FA_ACTIVITY_LOG_RETENTION_DAYS", "file": "config_env",
        "category": "logging", "label": "Activity Log Retention",
        "description": "Days of traffic activity log history to keep before automatic cleanup.",
        "type": "int", "min": 1, "max": 3650, "unit": "days", "restart_required": True,
        "current": lambda: cfg.ACTIVITY_LOG_RETENTION_DAYS,
    },
]

_BY_KEY = {f["key"]: f for f in SETTINGS_SCHEMA}


def _validate_value(ftype: str, raw: Any, *, label: str = "Value",
                     min_: Optional[int] = None, max_: Optional[int] = None,
                     choices: Optional[List[str]] = None) -> str:
    """Validate `raw` for `ftype` and return the normalized string to write
    to disk. Raises ValueError with a user-facing message on anything that
    isn't provably safe — see module docstring."""
    if ftype == "int":
        s = str(raw).strip()
        if not s.isdigit():
            raise ValueError(f"{label} must be a whole number")
        n = int(s)
        if min_ is not None and max_ is not None and not (min_ <= n <= max_):
            raise ValueError(f"{label} must be between {min_} and {max_}")
        return str(n)

    if ftype == "enum":
        s = str(raw).strip().upper()
        if not choices or s not in choices:
            raise ValueError(f"{label} must be one of: {', '.join(choices or [])}")
        return s

    if ftype == "ip":
        s = str(raw).strip()
        try:
            ipaddress.ip_address(s)
        except ValueError:
            raise ValueError(f"{label} must be a valid IP address")
        return s

    if ftype == "cidr_list":
        parts = [p.strip() for p in str(raw).split(",") if p.strip()]
        if not parts:
            raise ValueError(f"{label} must have at least one CIDR range")
        for p in parts:
            try:
                ipaddress.ip_network(p, strict=False)
            except ValueError:
                raise ValueError(f"{label}: '{p}' is not a valid CIDR range")
        return ",".join(parts)

    if ftype == "hostname":
        s = str(raw).strip()
        try:
            ipaddress.ip_address(s)
            return s
        except ValueError:
            pass
        if not s or not _HOSTNAME_RE.match(s):
            raise ValueError(f"{label} must be a valid IP address or hostname")
        return s

    raise ValueError(f"Unknown field type: {ftype}")


def _read_lines(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return f.readlines()


def _upsert_env_lines(path: str, updates: Dict[str, str]) -> None:
    """Atomically set multiple KEY=value pairs in one pass, preserving every
    other line (comments, unrelated keys, SECRET_KEY) verbatim. Appends any
    key not already present. Mirrors the write-temp + os.replace pattern
    already used in wireguard.py's create_client()/delete_client()."""
    lines = _read_lines(path)
    remaining = dict(updates)
    for i, line in enumerate(lines):
        stripped = line.strip()
        for key in list(remaining):
            if stripped.startswith(f"{key}="):
                lines[i] = f"{key}={remaining.pop(key)}\n"
                break
    if remaining:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        for key, value in remaining.items():
            lines.append(f"{key}={value}\n")

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        f.writelines(lines)
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)


def read_current_settings() -> List[Dict[str, Any]]:
    """Every schema field plus its current effective value, for rendering
    the Settings page. A missing/unreadable WireGuard params file (e.g. a
    fresh install that hasn't provisioned WireGuard yet) degrades to that
    category's defaults instead of taking down the config.env-backed
    fields, which have nothing to do with WireGuard."""
    params: Dict[str, str] = {}
    if any(f["file"] == "wg_params" for f in SETTINGS_SCHEMA):
        try:
            params = _load_wg_params()
        except Exception:
            params = {}
    result = []
    for field in SETTINGS_SCHEMA:
        if field["file"] == "wg_params":
            value = params.get(field["env_var"], field.get("default", ""))
        else:
            value = field["current"]()
        entry = {k: v for k, v in field.items() if k != "current"}
        entry["value"] = value
        result.append(entry)
    return result


def write_settings(changes: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and persist `changes` (schema `key` -> new raw value).
    Returns {"applied": {key: [old, new]}, "restart_required": bool}.
    Raises ValueError on the first invalid field — the caller maps this to
    an HTTP 400 before anything is written (validation happens before any
    file I/O, so a bad field in a batch cannot partially apply)."""
    validated: Dict[str, tuple] = {}
    for key, raw in changes.items():
        field = _BY_KEY.get(key)
        if field is None:
            raise ValueError(f"Unknown setting: {key}")
        normalized = _validate_value(
            field["type"], raw, label=field["label"],
            min_=field.get("min"), max_=field.get("max"), choices=field.get("choices"),
        )
        validated[key] = (field, normalized)

    try:
        wg_params_cache = _load_wg_params()
    except Exception:
        wg_params_cache = {}
    config_env_updates: Dict[str, str] = {}
    wg_params_updates: Dict[str, str] = {}
    applied: Dict[str, list] = {}
    restart_required = False

    for key, (field, normalized) in validated.items():
        old_value = (
            wg_params_cache.get(field["env_var"], field.get("default", ""))
            if field["file"] == "wg_params"
            else str(field["current"]())
        )
        if normalized == old_value:
            continue
        applied[key] = [old_value, normalized]
        if field["file"] == "wg_params":
            wg_params_updates[field["env_var"]] = normalized
        else:
            config_env_updates[field["env_var"]] = normalized
            restart_required = restart_required or field["restart_required"]

    if wg_params_updates:
        _upsert_env_lines(WG_PARAMS_PATH, wg_params_updates)
    if config_env_updates:
        _upsert_env_lines(CONFIG_ENV_PATH, config_env_updates)

    return {"applied": applied, "restart_required": restart_required}


def restart_service() -> bool:
    """Schedule a restart of the wireshield systemd unit, fully detached
    from this process's cgroup. This process IS wireshield.service's main
    PID (Type=simple) — a blocking `systemctl restart` or an in-process
    Timer+Popen risks systemd's KillMode=control-group taking the restart
    command down with us before it fires. `systemd-run` hands the timer to
    PID1 instead, so it fires regardless of what happens to this process
    right after the HTTP response is sent.

    Returns whether scheduling succeeded. The settings/cert change on disk
    already happened by the time this is called — a failure here (missing
    systemd-run, permission issue) must not surface as a crash on a request
    that otherwise succeeded; the caller reports it so the admin knows to
    restart manually instead of assuming the change is live."""
    try:
        subprocess.Popen(
            ["systemd-run", "--on-active=2", "systemctl", "restart", "wireshield"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return True
    except OSError:
        return False


def regenerate_self_signed_cert(hostname: Optional[str] = None) -> Dict[str, Any]:
    """Regenerate the self-signed cert via generate-certs.sh (already
    handles hostname auto-detection + subjectAltName correctly — reused
    here rather than re-implementing the openssl call). If a new hostname
    is given, persist it to config.env so future regenerations — and
    UI_BASE_URL — keep using it. Caller must call restart_service()
    afterward: uvicorn loads the cert files once at process start
    (run.py), so a regenerated cert has no effect until restart."""
    if hostname:
        hostname = _validate_value("hostname", hostname, label="Hostname")

    args = [GENERATE_CERTS_SCRIPT, "365"]
    if hostname:
        args.append(hostname)

    result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Certificate generation failed")

    if hostname:
        _upsert_env_lines(CONFIG_ENV_PATH, {"WS_HOSTNAME_2FA": hostname})

    return {"output": result.stdout.strip()}
