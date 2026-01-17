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

# Determine UI access URL based on config
if TFA_DOMAIN:
    UI_BASE_URL = f"https://{TFA_DOMAIN}"
else:
    UI_BASE_URL = f"https://{TFA_HOSTNAME}"
