"""
Network policy enforcement via iptables FORWARD + NAT POSTROUTING rules.

When a client authenticates, their per-client policies are applied as:

1. FORWARD rule   – explicitly allows the traffic from the client's WG IP
                    to the policy target (local IP / CIDR).
2. MASQUERADE rule – NATs the client's WG source IP to the server's LAN
                     IP so the target host can route its response back.
3. ESTABLISHED,RELATED rule (one-time, global) – ensures return traffic
                     from local targets is accepted by the FORWARD chain.

On session revoke, rules #1 and #2 are removed per-policy.
Rule #3 is left in place (shared and harmless).
"""
import socket
import subprocess
import logging
from app.core.database import get_db

logger = logging.getLogger(__name__)

_conntrack_ensured = False


def _iptables(args: list) -> None:
    try:
        subprocess.run(args, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        logger.debug(f"iptables command failed: {args} — {e}")


def _rule_exists(args: list) -> bool:
    """Check whether an iptables rule already exists (-C check)."""
    try:
        r = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except Exception:
        return False


def _ensure_conntrack_forward() -> None:
    """Insert a global ESTABLISHED,RELATED FORWARD rule once per process."""
    global _conntrack_ensured
    if _conntrack_ensured:
        return
    ct_rule = ["iptables", "-C", "FORWARD", "-m", "conntrack",
               "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]
    if not _rule_exists(ct_rule):
        _iptables(["iptables", "-I", "FORWARD", "-m", "conntrack",
                    "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        logger.info("Global ESTABLISHED,RELATED FORWARD rule inserted")
    _conntrack_ensured = True


def _match_args(client_ip: str, target: str, port, protocol: str) -> list:
    """Build the match part of a FORWARD / POSTROUTING rule."""
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
    """Add FORWARD + MASQUERADE rules for a single policy."""
    _ensure_conntrack_forward()

    target = _effective_target(policy)
    base = _match_args(client_ip, target, policy.get("port"), policy.get("protocol", "any"))

    # 1) FORWARD: allow traffic from client to target
    fwd_check = ["iptables", "-C", "FORWARD"] + base + ["-j", "ACCEPT"]
    if not _rule_exists(fwd_check):
        _iptables(["iptables", "-I", "FORWARD"] + base + ["-j", "ACCEPT"])
        logger.info(f"FORWARD rule added: {client_ip} → {target}")

    # 2) NAT MASQUERADE: source-NAT so target can reply
    nat_check = ["iptables", "-t", "nat", "-C", "POSTROUTING"] + base + ["-j", "MASQUERADE"]
    if not _rule_exists(nat_check):
        _iptables(["iptables", "-t", "nat", "-A", "POSTROUTING"] + base + ["-j", "MASQUERADE"])
        logger.info(f"MASQUERADE rule added: {client_ip} → {target}")


def _remove_rule(client_ip: str, policy: dict) -> None:
    """Remove FORWARD + MASQUERADE rules for a single policy."""
    target = _effective_target(policy)
    base = _match_args(client_ip, target, policy.get("port"), policy.get("protocol", "any"))

    _iptables(["iptables", "-D", "FORWARD"] + base + ["-j", "ACCEPT"])
    _iptables(["iptables", "-t", "nat", "-D", "POSTROUTING"] + base + ["-j", "MASQUERADE"])
    logger.info(f"Policy rules removed: {client_ip} → {target}")


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
