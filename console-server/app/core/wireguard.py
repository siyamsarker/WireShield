"""
WireGuard client lifecycle management — pure Python mirror of the
ws_add_client / ws_revoke_client / ws_get_client_config bash functions
in wireshield.sh. Keeping these in Python avoids subprocess shenanigans
with sourcing the installer script from the FastAPI service.

Operations:
  - list_clients()       read all client names from wg0.conf
  - create_client()      allocate IP + keys, write [Peer] + client.conf,
                         live-sync wg, and register in 2FA users table
  - get_client_config()  return the client's .conf file contents
  - delete_client()      remove [Peer] block, sessions, files, live-sync

All file writes are atomic (write temp, os.replace) and the live
WireGuard reconcile uses `wg-quick strip | wg syncconf` so it never
bounces the interface.
"""
import os
import re
import glob
import subprocess
import logging
import ipaddress
from datetime import datetime, timedelta
from typing import Optional, List, Dict

from app.core.database import get_db

logger = logging.getLogger(__name__)

WG_PARAMS_PATH = "/etc/wireguard/params"
_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


# ============================================================================
# Params + config file helpers
# ============================================================================

def _load_params() -> Dict[str, str]:
    """Parse /etc/wireguard/params (shell-style key=value) into a dict."""
    params: Dict[str, str] = {}
    try:
        with open(WG_PARAMS_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                params[k.strip()] = v.strip()
    except FileNotFoundError:
        raise RuntimeError(f"WireGuard params file not found at {WG_PARAMS_PATH}")
    return params


def _iface(params: Dict[str, str]) -> str:
    return params.get("SERVER_WG_NIC") or "wg0"


def _server_conf_path(params: Dict[str, str]) -> str:
    return f"/etc/wireguard/{_iface(params)}.conf"


def _base_v4(params: Dict[str, str]) -> str:
    """Return first 3 octets of SERVER_WG_IPV4 (e.g., '10.66.66')."""
    server_v4 = params.get("SERVER_WG_IPV4", "")
    return ".".join(server_v4.split(".")[:3])


def _base_v6(params: Dict[str, str]) -> str:
    """Return IPv6 base (part before ::, e.g., 'fd42:42:42')."""
    server_v6 = params.get("SERVER_WG_IPV6", "")
    return server_v6.split("::")[0]


def _server_own_octet(params: Dict[str, str]) -> Optional[int]:
    """Server's own last octet (e.g., '1' for 10.66.66.1)."""
    v4 = params.get("SERVER_WG_IPV4", "")
    try:
        return int(v4.split(".")[3].split("/")[0])
    except (IndexError, ValueError):
        return None


# ============================================================================
# Read wg0.conf
# ============================================================================

def list_clients() -> List[Dict[str, str]]:
    """Return existing client metadata parsed from wg0.conf.

    Returns list of {name, ipv4, ipv6, expires, public_key} dicts.
    """
    params = _load_params()
    try:
        with open(_server_conf_path(params), "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return []

    clients: List[Dict[str, str]] = []
    current: Optional[Dict[str, str]] = None

    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith("### Client "):
            rest = stripped[len("### Client "):]
            name_part, _, tail = rest.partition(" | Expires: ")
            if current:
                clients.append(current)
            current = {"name": name_part.strip(), "expires": tail.strip() or None, "ipv4": "", "ipv6": "", "public_key": ""}
            continue
        if current is None:
            continue
        if stripped.startswith("PublicKey"):
            current["public_key"] = stripped.partition("=")[2].strip()
        elif stripped.startswith("AllowedIPs"):
            val = stripped.partition("=")[2].strip()
            for part in val.split(","):
                p = part.strip()
                if "/32" in p:
                    current["ipv4"] = p.split("/")[0]
                elif "/128" in p:
                    current["ipv6"] = p.split("/")[0]

    if current:
        clients.append(current)
    return clients


def _used_v4_octets(params: Dict[str, str]) -> set:
    """All last-octets already taken on the WG /24 subnet."""
    used = set()
    base = _base_v4(params)
    own = _server_own_octet(params)
    if own is not None:
        used.add(own)

    for c in list_clients():
        try:
            if c["ipv4"].startswith(base + "."):
                used.add(int(c["ipv4"].split(".")[3]))
        except (ValueError, IndexError):
            continue
    return used


# ============================================================================
# wg binary wrappers
# ============================================================================

def _wg_run(cmd: list, input_text: Optional[str] = None) -> str:
    """Run a `wg` subcommand and return stdout. Raises on failure."""
    result = subprocess.run(
        cmd, input=input_text, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def _generate_keypair() -> tuple:
    """Generate (private_key, public_key, preshared_key) using the wg binary."""
    priv = _wg_run(["wg", "genkey"])
    pub = _wg_run(["wg", "pubkey"], input_text=priv + "\n")
    psk = _wg_run(["wg", "genpsk"])
    return priv, pub, psk


def _wg_syncconf(iface: str) -> None:
    """Live-apply the current wg0.conf without bouncing the interface.

    Equivalent of: wg syncconf <iface> <(wg-quick strip <iface>)
    """
    try:
        strip = subprocess.run(
            ["wg-quick", "strip", iface],
            capture_output=True, check=True,
        )
        subprocess.run(
            ["wg", "syncconf", iface],
            input=strip.stdout, check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        logger.info(f"wg syncconf applied to {iface}")
    except subprocess.CalledProcessError as e:
        logger.warning(f"wg syncconf failed: {e.stderr!r}")
    except FileNotFoundError:
        logger.debug("wg/wg-quick not available (likely dev env)")


# ============================================================================
# Public operations
# ============================================================================

def validate_client_name(name: str) -> None:
    """Raise ValueError on invalid client names."""
    if not name or not isinstance(name, str):
        raise ValueError("Client name is required")
    if len(name) >= 16:
        raise ValueError("Client name must be at most 15 characters")
    if not _NAME_RE.match(name):
        raise ValueError("Client name may only contain letters, digits, underscore, and dash")


def _client_config_dir() -> str:
    """Canonical directory for saved client .conf files.

    Defaults to /etc/wireshield/clients so both the CLI (ws_add_client /
    newClient) and the console's create_client end up writing to the same
    place. Override with WS_CLIENT_CONFIG_DIR for tests or alternate
    deployments. Directory is created with 0700 perms (configs contain
    private keys).
    """
    path = os.environ.get("WS_CLIENT_CONFIG_DIR", "/etc/wireshield/clients")
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
        # In case the directory was pre-existing with looser perms, tighten.
        os.chmod(path, 0o700)
    except PermissionError:
        # Non-root dev/test — tolerate and keep going.
        pass
    return path


def _build_endpoint(params: Dict[str, str]) -> str:
    server_ip = params.get("SERVER_PUB_IP", "")
    port = params.get("SERVER_PORT", "51820")
    # Bracket IPv6 endpoints if not already
    if ":" in server_ip and "[" not in server_ip:
        server_ip = f"[{server_ip}]"
    return f"{server_ip}:{port}"


def _build_client_config(
    priv: str, psk: str, ipv4: str, ipv6: str, params: Dict[str, str]
) -> str:
    endpoint = _build_endpoint(params)
    server_pub = params.get("SERVER_PUB_KEY", "")
    dns1 = params.get("CLIENT_DNS_1", "1.1.1.1")
    dns2 = params.get("CLIENT_DNS_2", "1.0.0.1")
    allowed = params.get("ALLOWED_IPS", "0.0.0.0/0,::/0")

    return (
        f"[Interface]\n"
        f"PrivateKey = {priv}\n"
        f"Address = {ipv4}/32,{ipv6}/128\n"
        f"DNS = {dns1},{dns2}\n"
        f"\n"
        f"# MTU 1420 prevents fragmentation issues over VPN tunnels\n"
        f"MTU = 1420\n"
        f"\n"
        f"[Peer]\n"
        f"PublicKey = {server_pub}\n"
        f"PresharedKey = {psk}\n"
        f"Endpoint = {endpoint}\n"
        f"AllowedIPs = {allowed}\n"
        f"# Keep WireGuard handshakes active so 2FA session monitor stays accurate\n"
        f"PersistentKeepalive = 25\n"
    )


def _append_peer_to_server_conf(
    conf_path: str, name: str, pub: str, psk: str, ipv4: str, ipv6: str, expires: Optional[str]
) -> None:
    header = f"### Client {name} | Expires: {expires}" if expires else f"### Client {name}"
    peer_block = (
        f"\n{header}\n"
        f"[Peer]\n"
        f"PublicKey = {pub}\n"
        f"PresharedKey = {psk}\n"
        f"AllowedIPs = {ipv4}/32,{ipv6}/128\n"
    )
    with open(conf_path, "a") as f:
        f.write(peer_block)


def create_client(name: str, expiry_days: Optional[int] = None) -> Dict[str, str]:
    """Create a new WireGuard client end-to-end.

    Steps (mirrors ws_add_client in wireshield.sh):
      1. Validate name, reject duplicates
      2. Allocate next free IPv4 + matching IPv6
      3. Generate WireGuard keypair + preshared key
      4. Write client .conf file (chmod 600)
      5. Append [Peer] block to server wg0.conf
      6. Live-apply via wg syncconf
      7. Register client_id in 2FA users table (disabled pending 2FA setup)

    Returns dict with {name, ipv4, ipv6, expires, config, config_path}.
    Raises ValueError on user error, RuntimeError on system error.
    """
    validate_client_name(name)
    params = _load_params()
    server_conf = _server_conf_path(params)

    existing_names = {c["name"] for c in list_clients()}
    if name in existing_names:
        raise ValueError(f"Client '{name}' already exists")

    # Allocate IPs
    used = _used_v4_octets(params)
    octet: Optional[int] = None
    for candidate in range(2, 255):
        if candidate not in used:
            octet = candidate
            break
    if octet is None:
        raise RuntimeError("No available IPv4 address in WireGuard subnet (all 253 taken)")

    ipv4 = f"{_base_v4(params)}.{octet}"
    ipv6 = f"{_base_v6(params)}::{octet}"

    # Validate addresses parse (defense in depth)
    ipaddress.ip_address(ipv4)
    ipaddress.ip_address(ipv6)

    # Expiry
    expires: Optional[str] = None
    if expiry_days is not None:
        if not isinstance(expiry_days, int) or expiry_days <= 0:
            raise ValueError("expiry_days must be a positive integer")
        expires = (datetime.utcnow() + timedelta(days=expiry_days)).strftime("%Y-%m-%d")

    # Keypair
    try:
        priv, pub, psk = _generate_keypair()
    except FileNotFoundError:
        raise RuntimeError("wg binary not found — WireGuard tools must be installed")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"wg keygen failed: {e.stderr!r}")

    # Client config text
    client_config = _build_client_config(priv, psk, ipv4, ipv6, params)

    # Save client .conf file
    save_dir = _client_config_dir()
    client_conf_path = os.path.join(save_dir, f"{name}.conf")
    tmp_path = client_conf_path + ".tmp"
    try:
        with open(tmp_path, "w") as f:
            f.write(client_config)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, client_conf_path)
    except OSError as e:
        raise RuntimeError(f"Failed to write client config: {e}")

    # Append peer to server conf
    _append_peer_to_server_conf(server_conf, name, pub, psk, ipv4, ipv6, expires)

    # Live-apply (non-fatal if wg binaries are absent)
    _wg_syncconf(_iface(params))

    # Register client in 2FA users table (idempotent). The client is disabled
    # until they complete 2FA setup via the portal.
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT OR IGNORE INTO users (client_id, enabled, wg_ipv4, wg_ipv6) VALUES (?, 0, ?, ?)",
            (name, ipv4, ipv6),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Users-table insert failed for {name}: {e}")

    logger.info(f"Created WireGuard client '{name}' with {ipv4} / {ipv6}")
    return {
        "name": name,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "expires": expires,
        "config": client_config,
        "config_path": client_conf_path,
    }


def _find_client_conf_file(name: str) -> Optional[str]:
    """Look up the saved client .conf file across the likely locations."""
    candidates = [
        os.path.join(_client_config_dir(), f"{name}.conf"),
        f"/root/{name}.conf",
        f"/etc/wireshield/clients/{name}.conf",
    ]
    candidates.extend(glob.glob(f"/home/*/{name}.conf"))
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def get_client_config(name: str) -> Optional[str]:
    """Return the contents of the client's .conf file, or None if missing."""
    validate_client_name(name)
    path = _find_client_conf_file(name)
    if not path:
        return None
    try:
        with open(path, "r") as f:
            return f.read()
    except OSError:
        return None


def delete_client(name: str) -> bool:
    """Remove a client from wg0.conf, delete .conf files, live-sync.

    Returns True if any change was made (peer block found + removed).
    """
    validate_client_name(name)
    params = _load_params()
    conf_path = _server_conf_path(params)

    try:
        with open(conf_path, "r") as f:
            original = f.read()
    except FileNotFoundError:
        return False

    lines = original.splitlines(keepends=True)
    out: list = []
    skip = False
    removed = False

    for line in lines:
        stripped = line.strip()
        if stripped == f"### Client {name}" or stripped.startswith(f"### Client {name} |"):
            skip = True
            removed = True
            continue
        if skip:
            # End the skip block when we hit a blank line (end of peer block)
            if stripped == "":
                skip = False
                continue
            # Also end if we encounter the next peer header without seeing a blank
            if stripped.startswith("### Client ") or stripped == "[Interface]":
                skip = False
                # fall through to append this line
            else:
                continue
        out.append(line)

    if not removed:
        return False

    # Atomic write
    tmp = conf_path + ".tmp"
    with open(tmp, "w") as f:
        f.writelines(out)
    os.replace(tmp, conf_path)

    # Delete client .conf files in known locations
    for path in (
        [os.path.join(_client_config_dir(), f"{name}.conf"),
         f"/root/{name}.conf",
         f"/etc/wireshield/clients/{name}.conf"]
        + glob.glob(f"/home/*/{name}.conf")
    ):
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass

    # Live-apply
    _wg_syncconf(_iface(params))

    # Remove from 2FA users / sessions (cascade their cleanup)
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("DELETE FROM sessions WHERE client_id = ?", (name,))
        c.execute("DELETE FROM users WHERE client_id = ?", (name,))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"DB cleanup failed for {name}: {e}")

    logger.info(f"Deleted WireGuard client '{name}'")
    return True
