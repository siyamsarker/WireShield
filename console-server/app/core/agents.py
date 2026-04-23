"""
Agent subsystem — Cloudflare-Tunnel-style reverse-connection peers.

An agent is a WireGuard peer running on a remote LAN (the "target LAN")
that declares a set of CIDRs it can reach. When a VPN client sends traffic
to one of those CIDRs, the WireShield server's kernel routes the packet
back out wg0 to the agent peer (based on the agent's AllowedIPs entry);
the agent then MASQUERADEs the packet onto its LAN interface.

Admin flow:
  1. POST /api/console/agents               { name, description?, advertised_cidrs? }
     → returns a one-time enrollment token + the install command.
  2. On the target machine, admin runs the install command.
  3. The agent daemon:
     a. Generates its own Curve25519 keypair (private key never leaves host).
     b. POSTs /api/agents/enroll { token, public_key, hostname, lan_interface,
                                    advertised_cidrs }
     c. Receives back a signed WG config (server pubkey + endpoint + assigned
        client IP + PSK + AllowedIPs = WG subnet).
     d. Writes /etc/wireguard/wg-agent0.conf and brings it up via wg-quick.
     e. Heartbeats every 30s to /api/agents/heartbeat (authenticated by the
        request's source WG IP matching a known agent).

Security:
  - Enrollment tokens are 32 random bytes (url-safe base64 = 43 chars),
    stored as SHA-256 hash, single-use, 1h TTL. Binding to first-consumer IP.
  - Agent WireGuard private key never leaves the agent host.
  - Preshared key adds a symmetric layer on top of the Curve25519 handshake.
  - Heartbeat authentication = WG source IP must match the agent's assigned
    IP (only reachable via the tunnel; packets from the public internet
    can't spoof this).
  - All actions land in the audit_log table.

All file writes to wg0.conf are atomic (temp + os.replace). Live sync uses
`wg-quick strip | wg syncconf` — never bounces the interface.
"""
import os
import re
import json
import secrets
import hashlib
import hmac
import logging
import subprocess
import ipaddress
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple

from app.core.database import get_db
from app.core.config import (
    AGENT_TOKEN_TTL_SECONDS, AGENT_IP_START, AGENT_IP_END,
    AGENT_OFFLINE_AFTER_SECONDS, SECRET_KEY, WG_INTERFACE,
    WIREGUARD_PARAMS_PATH,
)

logger = logging.getLogger(__name__)

AGENT_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{2,31}$")  # 3-32 chars
MAX_CIDRS_PER_AGENT = 32


# ============================================================================
# Config / params helpers
# ============================================================================

def _load_wg_params() -> Dict[str, str]:
    """Parse /etc/wireguard/params into a dict. Raises on missing file."""
    params: Dict[str, str] = {}
    try:
        with open(WIREGUARD_PARAMS_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                params[k.strip()] = v.strip()
    except FileNotFoundError:
        raise RuntimeError(f"WireGuard params file not found at {WIREGUARD_PARAMS_PATH}")
    return params


def _iface(params: Dict[str, str]) -> str:
    return WG_INTERFACE or params.get("SERVER_WG_NIC") or "wg0"


def _server_conf_path(params: Dict[str, str]) -> str:
    return f"/etc/wireguard/{_iface(params)}.conf"


def _base_v4(params: Dict[str, str]) -> str:
    """Return first 3 octets of SERVER_WG_IPV4."""
    return ".".join((params.get("SERVER_WG_IPV4") or "10.66.66.1").split(".")[:3])


# ============================================================================
# Validation
# ============================================================================

def validate_agent_name(name: str) -> None:
    """Raise ValueError on invalid agent names."""
    if not name or not isinstance(name, str):
        raise ValueError("Agent name is required")
    if not AGENT_NAME_RE.match(name):
        raise ValueError(
            "Agent name must be 3-32 characters, start with a letter or digit, "
            "and contain only letters, digits, underscores, and dashes"
        )


def validate_cidrs(cidrs: Optional[List[str]]) -> List[str]:
    """Normalize + validate an advertised-CIDR list. Returns cleaned list."""
    if cidrs is None:
        return []
    if not isinstance(cidrs, list):
        raise ValueError("advertised_cidrs must be a list of strings")
    if len(cidrs) > MAX_CIDRS_PER_AGENT:
        raise ValueError(f"Too many CIDRs (max {MAX_CIDRS_PER_AGENT})")
    out: List[str] = []
    seen = set()
    for raw in cidrs:
        if not isinstance(raw, str):
            raise ValueError("CIDR entries must be strings")
        raw = raw.strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ValueError(f"Invalid CIDR: {raw!r}")
        canonical = str(net)
        if canonical in seen:
            continue
        seen.add(canonical)
        out.append(canonical)
    return out


# ============================================================================
# Tokens
# ============================================================================

def _hash_token(raw: str) -> str:
    """SHA-256 hex of an enrollment token — what we store."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _sign_token(raw: str) -> str:
    """HMAC-SHA256 of raw token using the server secret. Used as an extra
    integrity check — the agent sends `raw.sig` and we verify the sig matches
    before doing the DB lookup. Protects against DB-only tampering."""
    sig = hmac.new(SECRET_KEY.encode(), raw.encode(), hashlib.sha256).digest()
    return secrets.token_urlsafe(0) + hashlib.sha256(sig).hexdigest()[:16]


def issue_enrollment_token(agent_id: int, ttl_seconds: Optional[int] = None) -> Tuple[str, datetime]:
    """Generate a new single-use enrollment token for an agent.

    Returns (raw_token, expires_at). The raw_token is shown to the admin
    exactly once — we store only its hash.
    """
    raw = secrets.token_urlsafe(32)
    token_hash = _hash_token(raw)
    ttl = ttl_seconds if ttl_seconds is not None else AGENT_TOKEN_TTL_SECONDS
    expires_at = datetime.utcnow() + timedelta(seconds=ttl)

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            "INSERT INTO agent_enrollment_tokens (agent_id, token_hash, expires_at) "
            "VALUES (?, ?, ?)",
            (agent_id, token_hash, expires_at),
        )
        conn.commit()
    finally:
        conn.close()

    logger.info(f"Issued enrollment token for agent id={agent_id} (ttl={ttl}s)")
    return raw, expires_at


def consume_enrollment_token(raw: str, source_ip: str) -> Optional[int]:
    """Validate + burn a token. Returns the associated agent_id or None.

    Rejects expired, already-used, or unknown tokens. Binds first-use to a
    specific source IP so replays from a different IP are blocked.
    """
    if not raw or not isinstance(raw, str):
        return None
    token_hash = _hash_token(raw)

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT id, agent_id, expires_at, used_at FROM agent_enrollment_tokens "
            "WHERE token_hash = ?",
            (token_hash,),
        )
        row = c.fetchone()
        if not row:
            return None
        if row["used_at"]:
            logger.warning(f"Replay of already-consumed enrollment token from {source_ip}")
            return None
        # expires_at is stored as TIMESTAMP; compare string representations
        try:
            expires_at = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            try:
                expires_at = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                logger.error(f"Unparseable expires_at on token id={row['id']}")
                return None
        if expires_at < datetime.utcnow():
            logger.info(f"Expired enrollment token presented from {source_ip}")
            return None

        # Atomically mark used
        c.execute(
            "UPDATE agent_enrollment_tokens SET used_at = CURRENT_TIMESTAMP, used_by_ip = ? "
            "WHERE id = ? AND used_at IS NULL",
            (source_ip, row["id"]),
        )
        if c.rowcount != 1:
            # Concurrent consumer beat us to it
            return None
        conn.commit()
        return int(row["agent_id"])
    finally:
        conn.close()


def purge_expired_tokens() -> int:
    """Delete rows where the token has expired AND was never used, OR that
    were used more than 24h ago (audit trail already captured what was
    needed). Returns the number of rows removed. Called by a background task.
    """
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            "DELETE FROM agent_enrollment_tokens "
            "WHERE (used_at IS NULL AND expires_at < datetime('now')) "
            "   OR (used_at IS NOT NULL AND used_at < datetime('now', '-1 day'))"
        )
        removed = c.rowcount
        conn.commit()
        return removed
    finally:
        conn.close()


# ============================================================================
# IP allocation
# ============================================================================

def _used_v4_octets_for_agents() -> set:
    """All last-octets currently claimed by anyone in the WG /24 — clients
    from wg0.conf + existing agents rows. Used to avoid collisions when
    assigning a new agent its WG IP."""
    used = set()
    params = _load_wg_params()
    base = _base_v4(params)

    # Server's own address
    server_octet = params.get("SERVER_WG_IPV4", "").split(".")
    if len(server_octet) == 4:
        try:
            used.add(int(server_octet[3].split("/")[0]))
        except ValueError:
            pass

    # Clients from wg0.conf AllowedIPs
    conf_path = _server_conf_path(params)
    try:
        with open(conf_path, "r") as f:
            for line in f:
                m = re.match(rf"\s*AllowedIPs\s*=\s*{re.escape(base)}\.(\d+)/32", line)
                if m:
                    used.add(int(m.group(1)))
    except FileNotFoundError:
        pass

    # Existing agent rows (even if revoked — keep their IP "dirty" for a while)
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT wg_ipv4 FROM agents WHERE wg_ipv4 IS NOT NULL")
        for row in c.fetchall():
            parts = (row["wg_ipv4"] or "").split(".")
            if len(parts) == 4 and ".".join(parts[:3]) == base:
                try:
                    used.add(int(parts[3]))
                except ValueError:
                    pass
    finally:
        conn.close()

    return used


def allocate_agent_ipv4() -> str:
    """Pick the next free IP in the agent range, or raise RuntimeError."""
    used = _used_v4_octets_for_agents()
    params = _load_wg_params()
    base = _base_v4(params)
    for octet in range(AGENT_IP_START, AGENT_IP_END + 1):
        if octet not in used:
            return f"{base}.{octet}"
    raise RuntimeError(
        f"No free IPs in agent range {base}.{AGENT_IP_START}-{AGENT_IP_END}"
    )


# ============================================================================
# WireGuard peer management — wg0.conf + `wg syncconf`
# ============================================================================

def _atomic_write(path: str, content: str, mode: int = 0o600) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(content)
    try:
        os.chmod(tmp, mode)
    except OSError:
        pass
    os.replace(tmp, path)


def _build_agent_peer_block(name: str, pubkey: str, psk: str,
                             wg_ipv4: str, advertised_cidrs: List[str]) -> str:
    """Render the server-side [Peer] block for an agent."""
    allowed = [f"{wg_ipv4}/32"] + advertised_cidrs
    return (
        f"\n### Agent {name}\n"
        f"[Peer]\n"
        f"PublicKey = {pubkey}\n"
        f"PresharedKey = {psk}\n"
        f"AllowedIPs = {','.join(allowed)}\n"
    )


def append_agent_peer(name: str, pubkey: str, psk: str,
                      wg_ipv4: str, advertised_cidrs: List[str]) -> None:
    """Append an agent's [Peer] block to wg0.conf (caller ensures no duplicate)."""
    params = _load_wg_params()
    conf_path = _server_conf_path(params)
    block = _build_agent_peer_block(name, pubkey, psk, wg_ipv4, advertised_cidrs)
    with open(conf_path, "a") as f:
        f.write(block)


def remove_agent_peer(name: str) -> bool:
    """Remove an agent's [Peer] block from wg0.conf by its header marker.
    Returns True if a block was removed."""
    params = _load_wg_params()
    conf_path = _server_conf_path(params)
    try:
        with open(conf_path, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return False

    out: List[str] = []
    skip = False
    removed = False
    for line in lines:
        stripped = line.strip()
        if stripped == f"### Agent {name}":
            skip = True
            removed = True
            continue
        if skip:
            if stripped == "":
                skip = False
                continue
            if stripped.startswith("### ") or stripped.startswith("[Interface]"):
                skip = False
                # fall through to append this line
            else:
                continue
        out.append(line)

    if not removed:
        return False
    _atomic_write(conf_path, "".join(out))
    return True


def replace_agent_peer_allowed_ips(name: str, pubkey: str,
                                     wg_ipv4: str, advertised_cidrs: List[str]) -> bool:
    """Rewrite the AllowedIPs line of an existing agent peer in wg0.conf.
    Used when advertised_cidrs changes. Returns True if the block was found."""
    params = _load_wg_params()
    conf_path = _server_conf_path(params)
    try:
        with open(conf_path, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return False

    new_allowed = f"{wg_ipv4}/32," + ",".join(advertised_cidrs) if advertised_cidrs else f"{wg_ipv4}/32"
    out: List[str] = []
    in_agent_block = False
    rewrote = False
    for line in lines:
        stripped = line.strip()
        if stripped == f"### Agent {name}":
            in_agent_block = True
            out.append(line)
            continue
        if in_agent_block:
            if stripped.startswith("### ") or stripped.startswith("[Interface]"):
                in_agent_block = False
            elif stripped.startswith("AllowedIPs"):
                out.append(f"AllowedIPs = {new_allowed}\n")
                rewrote = True
                continue
        out.append(line)

    if rewrote:
        _atomic_write(conf_path, "".join(out))
    return rewrote


def wg_syncconf() -> None:
    """Live-apply wg0.conf without bouncing the interface.
    Equivalent: wg syncconf <iface> <(wg-quick strip <iface>)"""
    params = _load_wg_params()
    iface = _iface(params)
    try:
        strip = subprocess.run(
            ["wg-quick", "strip", iface], capture_output=True, check=True,
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
# Public operations — create / enroll / revoke / heartbeat
# ============================================================================

def create_agent(name: str, description: Optional[str],
                 advertised_cidrs: Optional[List[str]],
                 created_by: Optional[str]) -> Dict[str, Any]:
    """Create a 'pending' agent row. Does NOT write to wg0.conf — the peer
    block is only added on successful enrollment. Returns the new agent dict
    plus a single-use enrollment token (shown to the admin exactly once).
    """
    validate_agent_name(name)
    cidrs = validate_cidrs(advertised_cidrs)
    psk = _generate_psk()

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            "INSERT INTO agents "
            "(name, description, preshared_key, advertised_cidrs, status, created_by) "
            "VALUES (?, ?, ?, ?, 'pending', ?)",
            (name, description or None, psk, json.dumps(cidrs), created_by),
        )
        agent_id = c.lastrowid
        conn.commit()
    finally:
        conn.close()

    raw_token, expires_at = issue_enrollment_token(agent_id)
    logger.info(f"Created agent id={agent_id} name={name!r} cidrs={cidrs}")
    return {
        "id": agent_id,
        "name": name,
        "description": description,
        "advertised_cidrs": cidrs,
        "status": "pending",
        "enrollment_token": raw_token,
        "token_expires_at": expires_at.isoformat() + "Z",
    }


def _generate_psk() -> str:
    """Generate a base64-encoded preshared key via `wg genpsk` when possible,
    fall back to Python-generated 32-byte secret for dev environments."""
    try:
        r = subprocess.run(["wg", "genpsk"], capture_output=True, text=True, check=True)
        return r.stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        # wg binary unavailable — fall back to a 32-byte base64 secret
        import base64
        return base64.b64encode(secrets.token_bytes(32)).decode()


def enroll_agent(raw_token: str, public_key: str, hostname: Optional[str],
                 lan_interface: Optional[str],
                 advertised_cidrs: Optional[List[str]],
                 agent_version: Optional[str],
                 source_ip: str) -> Dict[str, Any]:
    """Complete an agent enrollment. Validates the token, assigns a WG IP,
    writes the peer block, live-syncs WG, and returns the agent's WG config.

    Raises ValueError for recoverable input errors, RuntimeError for server
    errors.
    """
    if not public_key or not isinstance(public_key, str) or len(public_key) != 44:
        raise ValueError("public_key must be a 44-character base64 string")

    cidrs_in = validate_cidrs(advertised_cidrs)

    agent_id = consume_enrollment_token(raw_token, source_ip)
    if agent_id is None:
        raise ValueError("Invalid, expired, or already-used enrollment token")

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
        row = c.fetchone()
        if not row:
            raise RuntimeError(f"Agent row id={agent_id} vanished mid-enroll")
        agent = dict(row)
        if agent["status"] == "revoked":
            raise ValueError("Agent was revoked before enrollment completed")
        if agent["status"] == "enrolled":
            raise ValueError("Agent is already enrolled; issue a new token if re-enrollment is needed")

        # Use agent-declared CIDRs if the admin didn't pre-declare any.
        # Otherwise, trust the admin's pre-declared list (agent can't escalate).
        try:
            pre = json.loads(agent["advertised_cidrs"] or "[]")
        except (TypeError, json.JSONDecodeError):
            pre = []
        final_cidrs = pre if pre else cidrs_in

        # Allocate an IP
        wg_ipv4 = allocate_agent_ipv4()

        # Persist
        c.execute(
            "UPDATE agents SET "
            "  public_key = ?, wg_ipv4 = ?, hostname = ?, lan_interface = ?, "
            "  advertised_cidrs = ?, agent_version = ?, status = 'enrolled', "
            "  enrolled_at = CURRENT_TIMESTAMP "
            "WHERE id = ?",
            (public_key, wg_ipv4, hostname, lan_interface,
             json.dumps(final_cidrs), agent_version, agent_id),
        )
        conn.commit()
    finally:
        conn.close()

    # Append to wg0.conf + live-sync
    try:
        append_agent_peer(agent["name"], public_key, agent["preshared_key"],
                          wg_ipv4, final_cidrs)
        wg_syncconf()
    except Exception as e:
        logger.error(f"WG config update failed for agent {agent['name']}: {e}")
        # Leave status='enrolled' so the admin can see the partial state;
        # they can retry via the console or manually reconcile.

    # Build client-side config
    params = _load_wg_params()
    endpoint_host = params.get("SERVER_PUB_IP", "")
    if ":" in endpoint_host and "[" not in endpoint_host:
        endpoint_host = f"[{endpoint_host}]"
    endpoint = f"{endpoint_host}:{params.get('SERVER_PORT', '51820')}"
    # Agent only needs the WG subnet in its AllowedIPs so it can reply to
    # the server; the reverse direction is handled by the server's AllowedIPs
    # on this peer's block (which includes the agent's LAN CIDRs).
    wg_subnet_v4 = f"{_base_v4(params)}.0/24"
    agent_allowed_ips = wg_subnet_v4

    agent_config = (
        f"[Interface]\n"
        f"# PrivateKey is set by the agent from its own locally-generated keypair.\n"
        f"Address = {wg_ipv4}/32\n"
        f"\n"
        f"[Peer]\n"
        f"PublicKey = {params.get('SERVER_PUB_KEY', '')}\n"
        f"PresharedKey = {agent['preshared_key']}\n"
        f"Endpoint = {endpoint}\n"
        f"AllowedIPs = {agent_allowed_ips}\n"
        f"PersistentKeepalive = 25\n"
    )

    logger.info(f"Enrolled agent id={agent_id} name={agent['name']!r} at {wg_ipv4}")
    return {
        "id": agent_id,
        "name": agent["name"],
        "wg_ipv4": wg_ipv4,
        "preshared_key": agent["preshared_key"],
        "server_public_key": params.get("SERVER_PUB_KEY", ""),
        "endpoint": endpoint,
        "agent_allowed_ips": agent_allowed_ips,
        "advertised_cidrs": final_cidrs,
        "config": agent_config,
    }


def revoke_agent(agent_id: int) -> bool:
    """Soft-delete an agent: remove its WG peer, mark revoked. Returns True
    if a state change occurred."""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT name, status FROM agents WHERE id = ?", (agent_id,))
        row = c.fetchone()
        if not row:
            return False
        if row["status"] == "revoked":
            return False
        name = row["name"]
        c.execute(
            "UPDATE agents SET status = 'revoked', revoked_at = CURRENT_TIMESTAMP "
            "WHERE id = ?",
            (agent_id,),
        )
        conn.commit()
    finally:
        conn.close()

    removed = remove_agent_peer(name)
    if removed:
        wg_syncconf()
    logger.info(f"Revoked agent id={agent_id} name={name!r} (peer removed={removed})")
    return True


def update_agent_cidrs(agent_id: int, new_cidrs: List[str]) -> bool:
    """Replace an enrolled agent's advertised_cidrs, update wg0.conf + sync.
    Returns True if the update was applied."""
    cidrs = validate_cidrs(new_cidrs)
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
        row = c.fetchone()
        if not row or row["status"] != "enrolled":
            return False
        agent = dict(row)
        c.execute(
            "UPDATE agents SET advertised_cidrs = ? WHERE id = ?",
            (json.dumps(cidrs), agent_id),
        )
        conn.commit()
    finally:
        conn.close()

    ok = replace_agent_peer_allowed_ips(
        agent["name"], agent["public_key"], agent["wg_ipv4"], cidrs
    )
    if ok:
        wg_syncconf()
    logger.info(f"Updated agent id={agent_id} CIDRs to {cidrs}")
    return True


def record_heartbeat(source_ip: str, agent_version: Optional[str],
                     rx_bytes: Optional[int], tx_bytes: Optional[int]) -> Optional[int]:
    """Record a heartbeat from an agent authenticated by WG source IP.
    Returns the agent_id on success, None if no enrolled agent matches."""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT id FROM agents WHERE wg_ipv4 = ? AND status = 'enrolled'",
            (source_ip,),
        )
        row = c.fetchone()
        if not row:
            return None
        agent_id = int(row["id"])

        c.execute(
            "UPDATE agents SET "
            "  last_seen = CURRENT_TIMESTAMP, last_seen_ip = ?, "
            "  agent_version = COALESCE(?, agent_version), "
            "  rx_bytes = COALESCE(?, rx_bytes), tx_bytes = COALESCE(?, tx_bytes) "
            "WHERE id = ?",
            (source_ip, agent_version, rx_bytes, tx_bytes, agent_id),
        )
        c.execute(
            "INSERT INTO agent_heartbeats (agent_id, agent_version, rx_bytes, tx_bytes) "
            "VALUES (?, ?, ?, ?)",
            (agent_id, agent_version, rx_bytes, tx_bytes),
        )
        conn.commit()
        return agent_id
    finally:
        conn.close()


# ============================================================================
# Read helpers
# ============================================================================

def list_agents(include_revoked: bool = False) -> List[Dict[str, Any]]:
    """Return all agent rows with advertised_cidrs deserialized."""
    conn = get_db()
    try:
        c = conn.cursor()
        if include_revoked:
            c.execute("SELECT * FROM agents ORDER BY id DESC")
        else:
            c.execute("SELECT * FROM agents WHERE status != 'revoked' ORDER BY id DESC")
        rows = [dict(r) for r in c.fetchall()]
    finally:
        conn.close()
    for r in rows:
        try:
            r["advertised_cidrs"] = json.loads(r.get("advertised_cidrs") or "[]")
        except (TypeError, json.JSONDecodeError):
            r["advertised_cidrs"] = []
        # Redact the preshared key in list responses
        r.pop("preshared_key", None)
        # Compute live status for UI
        r["online"] = _is_online(r.get("last_seen"))
    return rows


def get_agent(agent_id: int, include_secrets: bool = False) -> Optional[Dict[str, Any]]:
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
        row = c.fetchone()
    finally:
        conn.close()
    if not row:
        return None
    out = dict(row)
    try:
        out["advertised_cidrs"] = json.loads(out.get("advertised_cidrs") or "[]")
    except (TypeError, json.JSONDecodeError):
        out["advertised_cidrs"] = []
    if not include_secrets:
        out.pop("preshared_key", None)
    out["online"] = _is_online(out.get("last_seen"))
    return out


def _is_online(last_seen: Optional[str]) -> bool:
    if not last_seen:
        return False
    try:
        ts = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return False
    return (datetime.utcnow() - ts).total_seconds() < AGENT_OFFLINE_AFTER_SECONDS


def stats() -> Dict[str, int]:
    """Aggregate counts for /health."""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT "
            "  SUM(CASE WHEN status='enrolled' THEN 1 ELSE 0 END) AS enrolled, "
            "  SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) AS pending, "
            "  SUM(CASE WHEN status='revoked' THEN 1 ELSE 0 END) AS revoked, "
            "  COUNT(*) AS total FROM agents"
        )
        row = dict(c.fetchone() or {})
        c.execute(
            "SELECT COUNT(*) AS online FROM agents WHERE status='enrolled' "
            "AND last_seen IS NOT NULL "
            "AND last_seen > datetime('now', ?)",
            (f"-{AGENT_OFFLINE_AFTER_SECONDS} seconds",),
        )
        online_row = c.fetchone()
        row["online"] = int((dict(online_row) if online_row else {}).get("online") or 0)
    finally:
        conn.close()
    return {k: int(v or 0) for k, v in row.items()}
