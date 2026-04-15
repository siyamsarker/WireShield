"""
Network policy enforcement via iptables NAT POSTROUTING rules.

When a client authenticates, their per-client policies are applied as
MASQUERADE rules so local hosts on the server's network can route
responses back without needing VPN-aware routing themselves.

Rule format:
  iptables -t nat -A POSTROUTING -s <client_wg_ip> -d <target> \
      [-p tcp|udp [--dport <port>]] -j MASQUERADE
"""
import socket
import subprocess
import logging
from app.core.database import get_db

logger = logging.getLogger(__name__)


def _iptables(args: list) -> None:
    try:
        subprocess.run(args, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        logger.debug(f"iptables command failed: {args} — {e}")


def _rule_base(client_ip: str, target: str, port, protocol: str) -> list:
    """Return the iptables args that identify a NAT POSTROUTING policy rule."""
    args = ["-s", client_ip, "-d", target]
    if protocol in ("tcp", "udp"):
        args += ["-p", protocol]
        if port:
            args += ["--dport", str(port)]
    elif port:
        # port specified but protocol is 'any' — default to tcp
        args += ["-p", "tcp", "--dport", str(port)]
    return args


def _effective_target(policy: dict) -> str:
    """Return the IP/CIDR to use in the iptables rule for this policy."""
    if policy.get("target_type") == "domain":
        return policy.get("resolved_ip") or policy["target"]
    return policy["target"]


def _apply_rule(client_ip: str, policy: dict) -> None:
    target = _effective_target(policy)
    base = _rule_base(client_ip, target, policy.get("port"), policy.get("protocol", "any"))
    # Idempotent: only insert if rule doesn't already exist
    check = subprocess.run(
        ["iptables", "-t", "nat", "-C", "POSTROUTING"] + base + ["-j", "MASQUERADE"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    if check.returncode != 0:
        _iptables(["iptables", "-t", "nat", "-A", "POSTROUTING"] + base + ["-j", "MASQUERADE"])
        logger.info(f"Policy rule added: {client_ip} → {target} port={policy.get('port')} proto={policy.get('protocol')}")


def _remove_rule(client_ip: str, policy: dict) -> None:
    target = _effective_target(policy)
    base = _rule_base(client_ip, target, policy.get("port"), policy.get("protocol", "any"))
    _iptables(["iptables", "-t", "nat", "-D", "POSTROUTING"] + base + ["-j", "MASQUERADE"])
    logger.info(f"Policy rule removed: {client_ip} → {target} port={policy.get('port')} proto={policy.get('protocol')}")


def apply_client_policies(client_id: str, client_ip: str) -> None:
    """Apply all enabled policies for a client when their session becomes active."""
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT target_type, target, resolved_ip, port, protocol "
        "FROM network_policies WHERE client_id = ? AND enabled = 1",
        (client_id,)
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for policy in rows:
        try:
            _apply_rule(client_ip, policy)
        except Exception as e:
            logger.warning(f"Failed to apply policy for {client_id}: {e}")


def remove_client_policies(client_id: str, client_ip: str) -> None:
    """Remove all enabled policies for a client when their session is revoked."""
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT target_type, target, resolved_ip, port, protocol "
        "FROM network_policies WHERE client_id = ? AND enabled = 1",
        (client_id,)
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for policy in rows:
        try:
            _remove_rule(client_ip, policy)
        except Exception as e:
            logger.warning(f"Failed to remove policy for {client_id}: {e}")


def resolve_domain(domain: str):
    """Resolve a domain name to its IPv4 address. Returns None on failure."""
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        logger.debug(f"Domain resolution failed for '{domain}': {e}")
        return None


def get_client_active_ip(client_id: str):
    """Return the active WG IP for a client if they have a non-expired session, else None."""
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """
        SELECT u.wg_ipv4, u.wg_ipv6
        FROM users u
        JOIN sessions s ON u.client_id = s.client_id
        WHERE u.client_id = ? AND s.expires_at > datetime('now')
        LIMIT 1
        """,
        (client_id,)
    )
    row = c.fetchone()
    conn.close()
    if row:
        return row["wg_ipv4"] or row["wg_ipv6"]
    return None
