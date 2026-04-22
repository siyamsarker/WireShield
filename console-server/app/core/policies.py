"""
Network policy enforcement — gateway-aware WireGuard routing + iptables.

Two enforcement modes:

1. **Gateway routing** (gateway_client_id set):
   Routes traffic through another WG peer that sits on the target LAN.
   - Adds the target CIDR to the gateway peer's AllowedIPs (live + conf)
   - Adds FORWARD -i wg0 -o wg0 rule for inter-client traffic
   - No MASQUERADE on the server — the gateway peer handles LAN NAT

2. **Direct routing** (no gateway, on-premises servers only):
   Original approach for when the VPN server is on the target LAN.
   - Adds FORWARD rule for client → target
   - Adds nat MASQUERADE so local hosts can route replies
"""
import os
import re
import socket
import subprocess
import logging
from typing import Optional
from app.core.database import get_db
from app.core.config import WG_INTERFACE

logger = logging.getLogger(__name__)

_conntrack_ensured = False


# ============================================================================
# Low-level iptables helpers
# ============================================================================

def _iptables(args: list) -> None:
    try:
        subprocess.run(args, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        logger.debug(f"iptables command failed: {args} — {e}")


def _rule_exists(args: list) -> bool:
    try:
        r = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except Exception:
        return False


def _ensure_conntrack_forward() -> None:
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
    args = ["-s", client_ip, "-d", target]
    if protocol in ("tcp", "udp"):
        args += ["-p", protocol]
        if port:
            args += ["--dport", str(port)]
    elif port:
        args += ["-p", "tcp", "--dport", str(port)]
    return args


def _effective_target(policy: dict) -> str:
    if policy.get("target_type") == "domain":
        return policy.get("resolved_ip") or policy["target"]
    return policy["target"]


# ============================================================================
# WireGuard config helpers (for gateway routing)
# ============================================================================

def _get_wg_interface() -> str:
    if WG_INTERFACE:
        return WG_INTERFACE
    try:
        with open("/etc/wireguard/params", "r") as f:
            for line in f:
                if line.strip().startswith("SERVER_WG_NIC="):
                    return line.strip().split("=", 1)[1].strip()
    except Exception:
        pass
    return "wg0"


def _get_peer_pubkey(client_id: str) -> Optional[str]:
    """Find the PublicKey for a client from wg0.conf."""
    iface = _get_wg_interface()
    conf_path = f"/etc/wireguard/{iface}.conf"
    try:
        with open(conf_path, "r") as f:
            lines = f.readlines()
    except Exception:
        return None

    in_block = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("### Client "):
            name = stripped[len("### Client "):].split(" | ")[0].strip()
            in_block = (name == client_id)
            continue
        if in_block and stripped.startswith("PublicKey"):
            return stripped.partition("=")[2].strip()
        if in_block and stripped == "":
            in_block = False
    return None


def _get_peer_allowed_ips(pubkey: str) -> list:
    """Read current AllowedIPs for a peer from live WireGuard state."""
    iface = _get_wg_interface()
    try:
        proc = subprocess.run(
            ["wg", "show", iface, "dump"],
            capture_output=True, text=True, check=False
        )
        if proc.returncode != 0:
            return []
        for line in proc.stdout.strip().splitlines()[1:]:
            parts = line.split('\t')
            if len(parts) >= 4 and parts[0] == pubkey:
                return [ip.strip() for ip in parts[3].split(',') if ip.strip() and ip.strip() != '(none)']
    except Exception as e:
        logger.warning(f"Failed to read peer AllowedIPs: {e}")
    return []


def _set_peer_allowed_ips(pubkey: str, allowed_ips: list) -> bool:
    """Apply AllowedIPs to a live WireGuard peer via 'wg set'."""
    iface = _get_wg_interface()
    ips_str = ",".join(allowed_ips)
    try:
        proc = subprocess.run(
            ["wg", "set", iface, "peer", pubkey, "allowed-ips", ips_str],
            capture_output=True, text=True, check=False
        )
        if proc.returncode != 0:
            logger.error(f"wg set failed: {proc.stderr.strip()}")
            return False
        return True
    except Exception as e:
        logger.error(f"wg set exception: {e}")
        return False


def _update_conf_allowed_ips(pubkey: str, new_allowed_ips: list) -> bool:
    """Persist AllowedIPs change to wg conf file (survives WG restart)."""
    iface = _get_wg_interface()
    conf_path = f"/etc/wireguard/{iface}.conf"
    try:
        with open(conf_path, "r") as f:
            lines = f.readlines()
    except Exception as e:
        logger.error(f"Cannot read {conf_path}: {e}")
        return False

    in_target_peer = False
    found_pubkey = False
    replaced = False
    new_lines = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[Peer]") or stripped.startswith("[Interface]") or stripped.startswith("### Client"):
            if in_target_peer and found_pubkey:
                in_target_peer = False
            in_target_peer = stripped == "[Peer]"
            if not in_target_peer:
                found_pubkey = False
            new_lines.append(line)
            continue

        if in_target_peer and not found_pubkey and stripped.startswith("PublicKey"):
            pk = stripped.partition("=")[2].strip()
            found_pubkey = (pk == pubkey)
            if not found_pubkey:
                in_target_peer = False
            new_lines.append(line)
            continue

        if in_target_peer and found_pubkey and stripped.startswith("AllowedIPs"):
            new_lines.append(f"AllowedIPs = {','.join(new_allowed_ips)}\n")
            replaced = True
            continue

        new_lines.append(line)

    if not replaced:
        return False

    try:
        tmp_path = conf_path + ".tmp"
        with open(tmp_path, "w") as f:
            f.writelines(new_lines)
        os.replace(tmp_path, conf_path)
        return True
    except Exception as e:
        logger.error(f"Failed to write {conf_path}: {e}")
        return False


def _normalize_target_cidr(target: str) -> str:
    if '/' not in target:
        return target + "/32"
    return target


# ============================================================================
# Apply / Remove — gateway-aware
# ============================================================================

def _apply_rule(client_ip: str, policy: dict) -> None:
    _ensure_conntrack_forward()
    target = _effective_target(policy)
    gateway_client_id = policy.get("gateway_client_id")
    base = _match_args(client_ip, target, policy.get("port"), policy.get("protocol", "any"))

    if gateway_client_id:
        _apply_gateway_rule(client_ip, target, gateway_client_id, policy)
    else:
        # Direct routing (on-premises server): FORWARD + MASQUERADE
        fwd_check = ["iptables", "-C", "FORWARD"] + base + ["-j", "ACCEPT"]
        if not _rule_exists(fwd_check):
            _iptables(["iptables", "-I", "FORWARD"] + base + ["-j", "ACCEPT"])
            logger.info(f"FORWARD rule added: {client_ip} → {target}")
        nat_check = ["iptables", "-t", "nat", "-C", "POSTROUTING"] + base + ["-j", "MASQUERADE"]
        if not _rule_exists(nat_check):
            _iptables(["iptables", "-t", "nat", "-A", "POSTROUTING"] + base + ["-j", "MASQUERADE"])
            logger.info(f"MASQUERADE rule added: {client_ip} → {target}")


def _remove_rule(client_ip: str, policy: dict) -> None:
    target = _effective_target(policy)
    gateway_client_id = policy.get("gateway_client_id")
    base = _match_args(client_ip, target, policy.get("port"), policy.get("protocol", "any"))

    if gateway_client_id:
        _remove_gateway_rule(client_ip, target, gateway_client_id, policy)
    else:
        _iptables(["iptables", "-D", "FORWARD"] + base + ["-j", "ACCEPT"])
        _iptables(["iptables", "-t", "nat", "-D", "POSTROUTING"] + base + ["-j", "MASQUERADE"])
        logger.info(f"Policy rules removed: {client_ip} → {target}")


# ── Gateway routing ─────────────────────────────────────────────────────────

def _apply_gateway_rule(client_ip: str, target: str, gateway_client_id: str, policy: dict) -> None:
    iface = _get_wg_interface()

    pubkey = _get_peer_pubkey(gateway_client_id)
    if not pubkey:
        logger.error(f"Gateway '{gateway_client_id}' not found in WG config")
        return

    # Add target to gateway peer's AllowedIPs
    current_ips = _get_peer_allowed_ips(pubkey)
    target_cidr = _normalize_target_cidr(target)

    if target_cidr not in current_ips:
        new_ips = current_ips + [target_cidr]
        if not _set_peer_allowed_ips(pubkey, new_ips):
            logger.error(f"Failed to update gateway AllowedIPs (live)")
            return
        _update_conf_allowed_ips(pubkey, new_ips)
        logger.info(f"Gateway AllowedIPs updated: {gateway_client_id} += {target_cidr}")

    # FORWARD rule: wg0 → wg0 (inter-client)
    fwd_args = ["-i", iface, "-o", iface, "-s", client_ip, "-d", target, "-j", "ACCEPT"]
    if not _rule_exists(["iptables", "-C", "FORWARD"] + fwd_args):
        _iptables(["iptables", "-I", "FORWARD"] + fwd_args)
        logger.info(f"Gateway FORWARD added: {client_ip} → {target} via {gateway_client_id}")


def _remove_gateway_rule(client_ip: str, target: str, gateway_client_id: str, policy: dict) -> None:
    iface = _get_wg_interface()

    # Remove FORWARD rule
    fwd_args = ["-i", iface, "-o", iface, "-s", client_ip, "-d", target, "-j", "ACCEPT"]
    _iptables(["iptables", "-D", "FORWARD"] + fwd_args)
    logger.info(f"Gateway FORWARD removed: {client_ip} → {target}")

    # Only remove AllowedIPs if no other enabled policy uses this gateway+target
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT COUNT(*) FROM network_policies "
        "WHERE gateway_client_id = ? AND target = ? AND enabled = 1",
        (gateway_client_id, target)
    )
    remaining = c.fetchone()[0]
    conn.close()

    if remaining > 0:
        logger.debug(f"Target {target} still used by {remaining} policies via {gateway_client_id}")
        return

    pubkey = _get_peer_pubkey(gateway_client_id)
    if not pubkey:
        return

    current_ips = _get_peer_allowed_ips(pubkey)
    target_cidr = _normalize_target_cidr(target)

    if target_cidr in current_ips:
        new_ips = [ip for ip in current_ips if ip != target_cidr]
        if not new_ips:
            logger.warning(f"Refusing to set empty AllowedIPs for {gateway_client_id}")
            return
        _set_peer_allowed_ips(pubkey, new_ips)
        _update_conf_allowed_ips(pubkey, new_ips)
        logger.info(f"Gateway AllowedIPs cleaned: {gateway_client_id} -= {target_cidr}")


# ============================================================================
# Bulk apply / remove (called by security.py on session changes)
# ============================================================================

def apply_client_policies(client_id: str, client_ip: str) -> None:
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT target_type, target, resolved_ip, port, protocol, gateway_client_id "
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
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT target_type, target, resolved_ip, port, protocol, gateway_client_id "
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


# ============================================================================
# Utilities
# ============================================================================

def resolve_domain(domain: str):
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        logger.debug(f"Domain resolution failed for '{domain}': {e}")
        return None


def get_client_active_ip(client_id: str):
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


# ============================================================================
# Split-Tunnel AllowedIPs Calculator
# ============================================================================

def calculate_split_allowed_ips(client_id: str) -> dict:
    """Calculate WireGuard AllowedIPs that exclude policy targets for split tunneling.

    Returns a dict with:
      - allowed_ips_v4: list of IPv4 CIDRs covering everything EXCEPT policy targets
      - allowed_ips_v6: list of IPv6 CIDRs (unchanged ::/0 for now)
      - excluded: list of human-readable excluded targets
      - allowed_ips_str: comma-separated string ready for WireGuard config
    """
    import ipaddress

    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT target_type, target, resolved_ip FROM network_policies "
        "WHERE client_id = ? AND enabled = 1",
        (client_id,)
    )
    policies = [dict(r) for r in c.fetchall()]
    conn.close()

    # Collect IPv4 networks to exclude
    exclude_nets = []
    excluded_labels = []
    for p in policies:
        raw = _effective_target(p)
        try:
            net = ipaddress.ip_network(raw, strict=False)
            if net.version == 4:
                exclude_nets.append(net)
                label = raw
                if p["target_type"] == "domain":
                    label = f"{p['target']} ({raw})"
                excluded_labels.append(label)
        except ValueError:
            continue

    if not exclude_nets:
        return {
            "allowed_ips_v4": ["0.0.0.0/0"],
            "allowed_ips_v6": ["::/0"],
            "excluded": [],
            "allowed_ips_str": "0.0.0.0/0,::/0",
        }

    # Start with 0.0.0.0/0 and subtract each exclusion
    remaining = [ipaddress.ip_network("0.0.0.0/0")]
    for exc in exclude_nets:
        new_remaining = []
        for net in remaining:
            if net.overlaps(exc):
                new_remaining.extend(net.address_exclude(exc))
            else:
                new_remaining.append(net)
        remaining = new_remaining

    # Sort and stringify
    v4_list = sorted(set(str(n) for n in remaining))
    v6_list = ["::/0"]
    all_ips = v4_list + v6_list

    return {
        "allowed_ips_v4": v4_list,
        "allowed_ips_v6": v6_list,
        "excluded": excluded_labels,
        "allowed_ips_str": ",".join(all_ips),
    }


def get_client_config_path(client_id: str) -> Optional[str]:
    """Locate the client's .conf file on the server.

    Checks the canonical location first (where both the CLI and the console's
    create_client write), then falls back to legacy per-user home directories
    for installs that pre-date the canonical path. An env-var override lets
    tests point at a sandbox location.
    """
    import glob
    canonical = os.environ.get("WS_CLIENT_CONFIG_DIR", "/etc/wireshield/clients")
    patterns = [
        f"{canonical}/{client_id}.conf",
        f"/root/{client_id}.conf",
        f"/home/*/{client_id}.conf",
    ]
    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
    return None


def generate_split_client_config(client_id: str) -> Optional[str]:
    """Return the client's existing config with an updated split-tunnel AllowedIPs
    plus PostUp/PreDown hooks that install explicit host routes via the LAN.

    Why the PostUp hooks are critical
    ---------------------------------
    AllowedIPs-based split tunneling is mathematically correct (32+ CIDRs that
    exclude the target), but certain WireGuard clients — notably the macOS
    native app — can still install a default route on the tunnel interface
    that shadows the exclusions. PostUp/PreDown commands on wg-quick-based
    clients (Linux + macOS CLI `wg-quick`) guarantee the target IPs are
    reached via the LAN by adding explicit host routes AFTER the tunnel
    comes up and removing them before it goes down.

    Clients that use the GUI app (Windows/macOS/iOS/Android) generally
    ignore these hooks — for those the AllowedIPs alone has to suffice, and
    the modal provides OS-specific manual fallback commands.

    The replacement is a targeted regex on the AllowedIPs line inside the
    [Peer] block; keys, endpoint, DNS, PersistentKeepalive, MTU are preserved.
    """
    import re

    config_path = get_client_config_path(client_id)
    if not config_path:
        return None

    try:
        with open(config_path, "r") as f:
            original = f.read()
    except Exception:
        return None

    split = calculate_split_allowed_ips(client_id)
    if not split["excluded"]:
        return original  # no rules, return as-is

    # 1) Replace the AllowedIPs line
    new_config = re.sub(
        r'AllowedIPs\s*=\s*.+',
        f'AllowedIPs = {split["allowed_ips_str"]}',
        original
    )

    # 2) Inject PostUp/PreDown hooks under the [Interface] block so
    #    wg-quick-based clients add host routes via the LAN interface.
    #    %i is wg-quick's interface placeholder — do not substitute here.
    hook_v4_cmds: list = []
    hook_v6_cmds: list = []
    predown_v4: list = []
    predown_v6: list = []

    # Only generate hooks for /32 IPv4 and /128 IPv6 host rules; CIDR rules
    # are harder to map to a single LAN interface reliably and the user's
    # OS routing should handle them naturally.
    import ipaddress as _ip
    for target in split["excluded"]:
        # split["excluded"] stores the original policy target strings
        raw = target
        # If it's "domain (ip)" format from calculate_split_allowed_ips, extract the ip
        if "(" in raw and raw.endswith(")"):
            raw = raw.rsplit("(", 1)[1].rstrip(")")
        raw = raw.strip()
        try:
            net = _ip.ip_network(raw if "/" in raw else raw + "/32", strict=False)
        except ValueError:
            continue
        if net.version == 4 and net.prefixlen == 32:
            host = str(net.network_address)
            # Use `ip route` when available, fall back to `route` (BSD/macOS).
            # `|| true` keeps wg-quick from failing if the command errors.
            hook_v4_cmds.append(host)
            predown_v4.append(host)
        elif net.version == 6 and net.prefixlen == 128:
            host = str(net.network_address)
            hook_v6_cmds.append(host)
            predown_v6.append(host)

    if hook_v4_cmds or hook_v6_cmds:
        # Build the PostUp/PreDown lines.
        # We use a helper shell snippet that detects the default LAN interface
        # so the hooks work without the user hand-editing anything.
        postup_lines = []
        predown_lines = []
        for host in hook_v4_cmds:
            postup_lines.append(
                f"PostUp = LAN_IF=$(ip route show default 2>/dev/null | awk '/default/ {{print $5; exit}}' || route -n get default 2>/dev/null | awk '/interface:/ {{print $2; exit}}'); "
                f"ip route add {host}/32 dev \"$LAN_IF\" 2>/dev/null || route -n add -host {host} -interface \"$LAN_IF\" 2>/dev/null || true"
            )
            predown_lines.append(
                f"PreDown = ip route del {host}/32 2>/dev/null || route -n delete -host {host} 2>/dev/null || true"
            )
        for host in hook_v6_cmds:
            postup_lines.append(
                f"PostUp = LAN_IF=$(ip -6 route show default 2>/dev/null | awk '/default/ {{print $5; exit}}' || route -n get -inet6 default 2>/dev/null | awk '/interface:/ {{print $2; exit}}'); "
                f"ip -6 route add {host}/128 dev \"$LAN_IF\" 2>/dev/null || route -n add -inet6 -host {host} -interface \"$LAN_IF\" 2>/dev/null || true"
            )
            predown_lines.append(
                f"PreDown = ip -6 route del {host}/128 2>/dev/null || route -n delete -inet6 -host {host} 2>/dev/null || true"
            )
        hook_block = "\n".join(postup_lines + predown_lines) + "\n"

        # Insert the hooks at the end of the [Interface] section (just before
        # the next section header, or append if no next section).
        def _inject_hooks(config_text: str, hook_text: str) -> str:
            lines = config_text.splitlines(keepends=True)
            out = []
            in_iface = False
            inserted = False
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped == "[Interface]":
                    in_iface = True
                    out.append(line)
                    continue
                if in_iface and not inserted and stripped.startswith("["):
                    # About to enter next section; insert hooks first
                    out.append(hook_text)
                    out.append("\n")
                    inserted = True
                    in_iface = False
                    out.append(line)
                    continue
                out.append(line)
            if in_iface and not inserted:
                # No next section found; append at end of file
                if not out[-1].endswith("\n"):
                    out.append("\n")
                out.append(hook_text)
            return "".join(out)

        new_config = _inject_hooks(new_config, hook_block)

    # 3) Prepend an ASCII-safe comment header documenting what's excluded
    #    and flagging macOS users to the fallback instructions.
    header_lines = [
        "# " + "=" * 70,
        f"# Split-tunnel config for client: {client_id}",
        "#",
        "# The following destinations bypass the VPN tunnel and go directly",
        "# via the client device's own network:",
    ]
    for target in split["excluded"]:
        header_lines.append(f"#   - {target}")
    header_lines.append("#")
    header_lines.append("# All other traffic continues through the VPN.")
    header_lines.append("#")
    header_lines.append("# Apply steps:")
    header_lines.append("#   1. In your VPN client, deactivate and DELETE the old tunnel.")
    header_lines.append("#   2. Import THIS file as a new tunnel.")
    header_lines.append("#   3. Activate the new tunnel.")
    header_lines.append("#")
    header_lines.append("# macOS / Windows GUI apps IGNORE the PostUp/PreDown hooks below.")
    header_lines.append("# If a target stays routed through the tunnel after activation,")
    header_lines.append("# see the \"Verify routing\" section in the console for a one-line")
    header_lines.append("# manual `route add` workaround specific to your OS.")
    header_lines.append("# " + "=" * 70)
    header = "\n".join(header_lines) + "\n\n"

    return header + new_config
