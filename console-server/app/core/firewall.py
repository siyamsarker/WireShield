"""
Per-user firewall — reusable policies of allow/deny rules assigned to VPN
users, independent of the existing agent allowlist (agent_user_access /
is_restricted / WS_AGENT_ACL in tasks.py — that subsystem is untouched).

Concepts:
  - A firewall_policy is a named, reusable collection of firewall_rules
    plus a default_action ('allow' or 'deny') applied when no rule matches.
  - A firewall_rule belongs either to a policy (policy_id) or directly to
    one user as an override on top of their assigned policy
    (user_client_id) — never both (enforced by a DB CHECK constraint).
  - user_firewall assigns at most one policy to a user and carries an
    independent hard "blocked" kill-switch.

A user with no user_firewall row (or one with blocked=0 and policy_id
NULL) is not managed by this subsystem at all — they fall through to the
existing 2FA ipset gate unchanged. This is what makes the feature
backward compatible: nothing changes until an admin explicitly assigns a
policy or blocks a user.

all_firewall_rules() is the single source of truth consumed by the
WS_USER_FW iptables sync loop in tasks.py.
"""
import logging
from typing import Any, Dict, List, Optional, Tuple

from app.core.database import get_db
from app.core.agents import validate_cidrs

logger = logging.getLogger(__name__)

VALID_DIRECTIONS = {"inbound", "outbound"}
VALID_ACTIONS = {"allow", "deny"}
VALID_PROTOCOLS = {"tcp", "udp", "icmp", "all"}

MAX_POLICY_NAME_LEN = 64
MAX_RULES_PER_OWNER = 200  # per policy or per user's override set

# Sentinel for "argument not supplied" — lets update_rule/update_policy
# distinguish "leave this field alone" from "set it to None/empty".
_UNSET = object()


# ============================================================================
# Validation
# ============================================================================

def validate_policy_name(name: str) -> str:
    name = (name or "").strip()
    if not name:
        raise ValueError("Policy name is required")
    if len(name) > MAX_POLICY_NAME_LEN:
        raise ValueError(f"Policy name must be at most {MAX_POLICY_NAME_LEN} characters")
    return name


def validate_direction(direction: str) -> str:
    if direction not in VALID_DIRECTIONS:
        raise ValueError(f"direction must be one of {sorted(VALID_DIRECTIONS)}")
    return direction


def validate_action(action: str) -> str:
    if action not in VALID_ACTIONS:
        raise ValueError(f"action must be one of {sorted(VALID_ACTIONS)}")
    return action


def validate_protocol(protocol: Optional[str]) -> str:
    protocol = (protocol or "all").lower()
    if protocol not in VALID_PROTOCOLS:
        raise ValueError(f"protocol must be one of {sorted(VALID_PROTOCOLS)}")
    return protocol


def validate_port_range(
    port_start: Optional[int], port_end: Optional[int], protocol: str
) -> Tuple[Optional[int], Optional[int]]:
    """None/None means 'all ports'. A single port may be given as just
    port_start. icmp/all protocols never carry a port range."""
    if port_start is None and port_end is None:
        return None, None
    if protocol in ("icmp", "all"):
        raise ValueError(f"Ports are not applicable to protocol {protocol!r}")
    if port_start is None:
        port_start = port_end
    if port_end is None:
        port_end = port_start
    for p in (port_start, port_end):
        if not isinstance(p, int) or isinstance(p, bool) or not (1 <= p <= 65535):
            raise ValueError("Ports must be integers between 1 and 65535")
    if port_start > port_end:
        raise ValueError("port_start must be <= port_end")
    return port_start, port_end


def validate_remote_cidr(cidr: Optional[str]) -> Optional[str]:
    """None/empty means 'any' (0.0.0.0/0 equivalent). Reuses the same
    CIDR normalization/validation as the agent subsystem."""
    cidr = (cidr or "").strip()
    if not cidr:
        return None
    return validate_cidrs([cidr])[0]


# ============================================================================
# Policy CRUD
# ============================================================================

def create_policy(
    name: str, description: Optional[str] = None,
    default_action: str = "deny", enabled: bool = True,
) -> Dict[str, Any]:
    name = validate_policy_name(name)
    default_action = validate_action(default_action)
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            "INSERT INTO firewall_policies (name, description, default_action, enabled) "
            "VALUES (?, ?, ?, ?)",
            (name, description, default_action, 1 if enabled else 0),
        )
        policy_id = c.lastrowid
        conn.commit()
    finally:
        conn.close()
    return get_policy(policy_id)


def list_policies() -> List[Dict[str, Any]]:
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            """
            SELECT p.*,
                   (SELECT COUNT(*) FROM firewall_rules r WHERE r.policy_id = p.id) AS rule_count,
                   (SELECT COUNT(*) FROM user_firewall uf WHERE uf.policy_id = p.id) AS assigned_user_count
            FROM firewall_policies p
            ORDER BY p.name ASC
            """
        )
        rows = [dict(r) for r in c.fetchall()]
    finally:
        conn.close()
    for r in rows:
        r["enabled"] = bool(r.get("enabled"))
    return rows


def get_policy(policy_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            """
            SELECT p.*,
                   (SELECT COUNT(*) FROM user_firewall uf WHERE uf.policy_id = p.id) AS assigned_user_count
            FROM firewall_policies p WHERE p.id = ?
            """,
            (policy_id,),
        )
        row = c.fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    policy = dict(row)
    policy["enabled"] = bool(policy.get("enabled"))
    policy["rules"] = list_policy_rules(policy_id)
    return policy


def update_policy(
    policy_id: int, name=_UNSET, description=_UNSET,
    default_action=_UNSET, enabled=_UNSET,
) -> bool:
    fields: Dict[str, Any] = {}
    if name is not _UNSET:
        fields["name"] = validate_policy_name(name)
    if description is not _UNSET:
        fields["description"] = description
    if default_action is not _UNSET:
        fields["default_action"] = validate_action(default_action)
    if enabled is not _UNSET:
        fields["enabled"] = 1 if enabled else 0
    if not fields:
        return False

    fields["updated_at"] = "CURRENT_TIMESTAMP"
    set_clause = ", ".join(
        f"{k} = CURRENT_TIMESTAMP" if v == "CURRENT_TIMESTAMP" else f"{k} = ?"
        for k, v in fields.items()
    )
    values = [v for v in fields.values() if v != "CURRENT_TIMESTAMP"]
    values.append(policy_id)

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(f"UPDATE firewall_policies SET {set_clause} WHERE id = ?", values)
        changed = c.rowcount > 0
        conn.commit()
    finally:
        conn.close()
    return changed


def delete_policy(policy_id: int) -> bool:
    """Delete a policy. Users assigned to it fall back to unmanaged
    (policy_id cleared) rather than being blocked."""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("UPDATE user_firewall SET policy_id = NULL WHERE policy_id = ?", (policy_id,))
        c.execute("DELETE FROM firewall_rules WHERE policy_id = ?", (policy_id,))
        c.execute("DELETE FROM firewall_policies WHERE id = ?", (policy_id,))
        changed = c.rowcount > 0
        conn.commit()
    finally:
        conn.close()
    return changed


# ============================================================================
# Rule CRUD (shared table for policy rules and per-user override rules)
# ============================================================================

def _row_count_for(conn, *, policy_id: Optional[int], user_client_id: Optional[str]) -> int:
    c = conn.cursor()
    if policy_id is not None:
        c.execute("SELECT COUNT(*) FROM firewall_rules WHERE policy_id = ?", (policy_id,))
    else:
        c.execute("SELECT COUNT(*) FROM firewall_rules WHERE user_client_id = ?", (user_client_id,))
    return c.fetchone()[0]


def add_rule(
    *, policy_id: Optional[int] = None, user_client_id: Optional[str] = None,
    direction: str, action: str, protocol: str = "all",
    port_start: Optional[int] = None, port_end: Optional[int] = None,
    remote_cidr: Optional[str] = None, priority: int = 0,
) -> Dict[str, Any]:
    if (policy_id is None) == (user_client_id is None):
        raise ValueError("Exactly one of policy_id or user_client_id must be set")
    direction = validate_direction(direction)
    action = validate_action(action)
    protocol = validate_protocol(protocol)
    port_start, port_end = validate_port_range(port_start, port_end, protocol)
    remote_cidr = validate_remote_cidr(remote_cidr)

    conn = get_db()
    try:
        c = conn.cursor()
        if policy_id is not None:
            c.execute("SELECT 1 FROM firewall_policies WHERE id = ?", (policy_id,))
            if c.fetchone() is None:
                raise ValueError(f"unknown policy_id: {policy_id}")
        else:
            c.execute("SELECT 1 FROM users WHERE client_id = ?", (user_client_id,))
            if c.fetchone() is None:
                raise ValueError(f"unknown client_id: {user_client_id!r}")

        if _row_count_for(conn, policy_id=policy_id, user_client_id=user_client_id) >= MAX_RULES_PER_OWNER:
            raise ValueError(f"Too many rules (max {MAX_RULES_PER_OWNER})")

        c.execute(
            "INSERT INTO firewall_rules "
            "(policy_id, user_client_id, direction, action, protocol, port_start, port_end, remote_cidr, priority) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (policy_id, user_client_id, direction, action, protocol, port_start, port_end, remote_cidr, priority),
        )
        rule_id = c.lastrowid
        conn.commit()
        c.execute("SELECT * FROM firewall_rules WHERE id = ?", (rule_id,))
        row = dict(c.fetchone())
    finally:
        conn.close()
    return row


def update_rule(
    rule_id: int, *, direction=_UNSET, action=_UNSET, protocol=_UNSET,
    port_start=_UNSET, port_end=_UNSET, remote_cidr=_UNSET, priority=_UNSET,
) -> bool:
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM firewall_rules WHERE id = ?", (rule_id,))
        existing = c.fetchone()
        if existing is None:
            return False
        existing = dict(existing)

        new_protocol = validate_protocol(protocol) if protocol is not _UNSET else existing["protocol"]
        new_port_start = existing["port_start"] if port_start is _UNSET else port_start
        new_port_end = existing["port_end"] if port_end is _UNSET else port_end
        if port_start is not _UNSET or port_end is not _UNSET or protocol is not _UNSET:
            new_port_start, new_port_end = validate_port_range(new_port_start, new_port_end, new_protocol)

        fields: Dict[str, Any] = {"protocol": new_protocol, "port_start": new_port_start, "port_end": new_port_end}
        if direction is not _UNSET:
            fields["direction"] = validate_direction(direction)
        if action is not _UNSET:
            fields["action"] = validate_action(action)
        if remote_cidr is not _UNSET:
            fields["remote_cidr"] = validate_remote_cidr(remote_cidr)
        if priority is not _UNSET:
            fields["priority"] = priority

        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [rule_id]
        c.execute(f"UPDATE firewall_rules SET {set_clause} WHERE id = ?", values)
        conn.commit()
        return True
    finally:
        conn.close()


def delete_rule(rule_id: int) -> bool:
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM firewall_rules WHERE id = ?", (rule_id,))
        changed = c.rowcount > 0
        conn.commit()
    finally:
        conn.close()
    return changed


def list_policy_rules(policy_id: int) -> List[Dict[str, Any]]:
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT * FROM firewall_rules WHERE policy_id = ? ORDER BY priority ASC, id ASC",
            (policy_id,),
        )
        return [dict(r) for r in c.fetchall()]
    finally:
        conn.close()


def list_user_override_rules(client_id: str) -> List[Dict[str, Any]]:
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT * FROM firewall_rules WHERE user_client_id = ? ORDER BY priority ASC, id ASC",
            (client_id,),
        )
        return [dict(r) for r in c.fetchall()]
    finally:
        conn.close()


# ============================================================================
# Per-user assignment (policy + block kill-switch)
# ============================================================================

def get_user_firewall(client_id: str) -> Dict[str, Any]:
    """Return the user's firewall assignment. `managed=False` means there
    is no user_firewall row at all — the user is untouched by this
    subsystem and governed purely by the existing 2FA ipset gate."""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            """
            SELECT uf.client_id, uf.policy_id, uf.blocked, p.name AS policy_name
            FROM user_firewall uf
            LEFT JOIN firewall_policies p ON p.id = uf.policy_id
            WHERE uf.client_id = ?
            """,
            (client_id,),
        )
        row = c.fetchone()
    finally:
        conn.close()
    if row is None:
        return {"client_id": client_id, "policy_id": None, "policy_name": None, "blocked": False, "managed": False}
    result = dict(row)
    result["blocked"] = bool(result["blocked"])
    result["managed"] = True
    return result


def set_user_firewall(client_id: str, policy_id: Optional[int], blocked: bool) -> Dict[str, Any]:
    """Full-replace upsert (PUT semantics) of a user's firewall
    assignment. Validates the user and (if given) the policy exist."""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT 1 FROM users WHERE client_id = ?", (client_id,))
        if c.fetchone() is None:
            raise ValueError(f"unknown client_id: {client_id!r}")
        if policy_id is not None:
            c.execute("SELECT 1 FROM firewall_policies WHERE id = ?", (policy_id,))
            if c.fetchone() is None:
                raise ValueError(f"unknown policy_id: {policy_id}")

        c.execute(
            """
            INSERT INTO user_firewall (client_id, policy_id, blocked)
            VALUES (?, ?, ?)
            ON CONFLICT(client_id) DO UPDATE SET
                policy_id = excluded.policy_id,
                blocked = excluded.blocked,
                updated_at = CURRENT_TIMESTAMP
            """,
            (client_id, policy_id, 1 if blocked else 0),
        )
        conn.commit()
    finally:
        conn.close()
    return get_user_firewall(client_id)


# ============================================================================
# Rule resolution for the WS_USER_FW enforcement sync (tasks.py)
# ============================================================================

def resolve_client_ips(client_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (ipv4, ipv6) for a client. Prefers the users table;
    falls back to parsing wg0.conf (the ground-truth allocation) for
    whichever family isn't populated yet — mirrors the same fallback
    already relied on elsewhere for user->tunnel-IP mapping."""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT wg_ipv4, wg_ipv6 FROM users WHERE client_id = ?", (client_id,))
        row = c.fetchone()
    finally:
        conn.close()
    ipv4 = row["wg_ipv4"] if row else None
    ipv6 = row["wg_ipv6"] if row else None
    if ipv4 and ipv6:
        return ipv4, ipv6
    try:
        from app.core.wireguard import list_clients
        for entry in list_clients():
            if entry.get("name") == client_id:
                ipv4 = ipv4 or (entry.get("ipv4") or None)
                ipv6 = ipv6 or (entry.get("ipv6") or None)
                break
    except Exception as e:
        logger.warning(f"firewall: wg0.conf fallback lookup failed for {client_id!r}: {e}")
    return ipv4, ipv6


def all_firewall_rules() -> List[Dict[str, Any]]:
    """Resolve every managed user's effective firewall state in one pass.

    A user is "managed" here only if their user_firewall row has
    blocked=1 or a policy_id set. Anyone else is intentionally excluded
    from the result — they emit no WS_USER_FW rules and remain governed
    purely by the existing 2FA ipset gate (backward compatible default).

    Returned rule order per user is override rules first, then the
    assigned policy's rules, then the policy's default_action — this is
    the "first match wins" evaluation order the sync loop must preserve.
    """
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            """
            SELECT uf.client_id, uf.policy_id, uf.blocked,
                   p.default_action AS policy_default_action,
                   p.enabled AS policy_enabled
            FROM user_firewall uf
            LEFT JOIN firewall_policies p ON p.id = uf.policy_id
            WHERE uf.blocked = 1 OR uf.policy_id IS NOT NULL
            """
        )
        assignments = [dict(r) for r in c.fetchall()]
    finally:
        conn.close()

    results: List[Dict[str, Any]] = []
    for a in assignments:
        client_id = a["client_id"]
        ipv4, ipv6 = resolve_client_ips(client_id)
        blocked = bool(a["blocked"])
        policy_enabled = bool(a["policy_enabled"]) if a["policy_id"] is not None else False

        entry: Dict[str, Any] = {
            "client_id": client_id,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "blocked": blocked,
            "policy_id": a["policy_id"] if policy_enabled else None,
            "policy_default_action": a["policy_default_action"] if policy_enabled else None,
            "rules": [],
        }
        if not blocked:
            override_rules = list_user_override_rules(client_id)
            policy_rules = list_policy_rules(a["policy_id"]) if policy_enabled else []
            entry["rules"] = override_rules + policy_rules
        results.append(entry)
    return results
