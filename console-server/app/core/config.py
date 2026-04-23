import os

def getenv_multi(default: str, *names: str) -> str:
    """Return the first found environment value among provided names."""
    for name in names:
        val = os.getenv(name)
        if val is not None and val != "":
            return val
    return default

LOG_LEVEL = getenv_multi("INFO", "WS_2FA_LOG_LEVEL", "2FA_LOG_LEVEL")
AUTH_DB_PATH = getenv_multi("/etc/wireshield/2fa/auth.db", "WS_2FA_DB_PATH", "2FA_DB_PATH")
AUTH_HOST = getenv_multi("0.0.0.0", "WS_2FA_HOST", "2FA_HOST")
AUTH_PORT = int(getenv_multi("443", "WS_2FA_PORT", "2FA_PORT"))
AUTH_HTTP_PORT = int(getenv_multi("80", "WS_2FA_HTTP_PORT", "2FA_HTTP_PORT"))
SSL_CERT = getenv_multi("/etc/wireshield/2fa/cert.pem", "WS_2FA_SSL_CERT", "2FA_SSL_CERT")
SSL_KEY = getenv_multi("/etc/wireshield/2fa/key.pem", "WS_2FA_SSL_KEY", "2FA_SSL_KEY")
SSL_ENABLED = getenv_multi("true", "WS_2FA_SSL_ENABLED", "2FA_SSL_ENABLED").lower() in ("true", "1", "yes")
SSL_TYPE = getenv_multi("self-signed", "WS_2FA_SSL_TYPE", "2FA_SSL_TYPE")  # self-signed, letsencrypt
TFA_DOMAIN = getenv_multi("", "WS_2FA_DOMAIN", "2FA_DOMAIN")
TFA_HOSTNAME = getenv_multi("127.0.0.1", "WS_HOSTNAME_2FA", "HOSTNAME_2FA")
SECRET_KEY = getenv_multi("", "WS_2FA_SECRET_KEY", "2FA_SECRET_KEY")  # Must be set in production

# Validate SECRET_KEY is set for security
if not SECRET_KEY:
    raise RuntimeError("WS_2FA_SECRET_KEY environment variable must be set for security. Please configure your installation.")
SESSION_TIMEOUT_MINUTES = int(getenv_multi("1440", "WS_2FA_SESSION_TIMEOUT", "2FA_SESSION_TIMEOUT"))  # 24h default
RATE_LIMIT_MAX_REQUESTS = int(getenv_multi("30", "WS_2FA_RATE_LIMIT_MAX_REQUESTS", "2FA_RATE_LIMIT_MAX_REQUESTS"))
RATE_LIMIT_WINDOW_SECONDS = int(getenv_multi("60", "WS_2FA_RATE_LIMIT_WINDOW", "2FA_RATE_LIMIT_WINDOW"))
WIREGUARD_PARAMS_PATH = getenv_multi("/etc/wireguard/params", "WS_WIREGUARD_PARAMS", "WIREGUARD_PARAMS")
WG_INTERFACE = getenv_multi("", "WS_WG_INTERFACE", "WG_INTERFACE", "WS_SERVER_WG_NIC")
# Idle timeout while connected: how recent a handshake must be to consider the peer active.
# Default 3600s (1 hour) to keep sessions for long idle periods while connected.
SESSION_IDLE_TIMEOUT_SECONDS = int(getenv_multi("3600", "WS_2FA_SESSION_IDLE_TIMEOUT", "2FA_SESSION_IDLE_TIMEOUT"))
# Disconnect grace: revoke session after this many seconds without any handshake.
DISCONNECT_GRACE_SECONDS = int(getenv_multi("3600", "WS_2FA_DISCONNECT_GRACE_SECONDS", "2FA_DISCONNECT_GRACE_SECONDS"))
ACTIVITY_LOG_RETENTION_DAYS = int(getenv_multi("30", "WS_2FA_ACTIVITY_LOG_RETENTION_DAYS", "2FA_ACTIVITY_LOG_RETENTION_DAYS"))

# ── Agent subsystem ──────────────────────────────────────────────────────
# Lifetime of an enrollment token issued by an admin (single-use).
AGENT_TOKEN_TTL_SECONDS = int(getenv_multi("3600", "WS_AGENT_TOKEN_TTL_SECONDS"))
# First octet of the IPv4 range reserved for agent peers in the WG subnet.
# Agents are assigned sequentially starting here, walking upward, skipping
# any IP already present in wg0.conf (client or existing agent).
AGENT_IP_START = int(getenv_multi("200", "WS_AGENT_IP_START"))
# Highest octet to try (inclusive) — default .254.
AGENT_IP_END = int(getenv_multi("254", "WS_AGENT_IP_END"))
# Retention for the agent_heartbeats sparkline table.
AGENT_HEARTBEAT_RETENTION_HOURS = int(getenv_multi("48", "WS_AGENT_HEARTBEAT_RETENTION_HOURS"))
# An agent is considered offline if the last heartbeat is older than this.
AGENT_OFFLINE_AFTER_SECONDS = int(getenv_multi("90", "WS_AGENT_OFFLINE_AFTER_SECONDS"))

# Determine UI access URL based on config
# Use http:// when SSL is disabled, https:// when enabled
# Include port if it's not the default for the scheme
_scheme = "https" if SSL_ENABLED else "http"
_default_port = 443 if SSL_ENABLED else 80
_port_suffix = "" if AUTH_PORT == _default_port else f":{AUTH_PORT}"
if TFA_DOMAIN:
    UI_BASE_URL = f"{_scheme}://{TFA_DOMAIN}{_port_suffix}"
else:
    UI_BASE_URL = f"{_scheme}://{TFA_HOSTNAME}{_port_suffix}"
