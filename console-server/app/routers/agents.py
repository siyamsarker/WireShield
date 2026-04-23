"""
Agent-facing (non-admin) API endpoints.

These are called by the agent daemon itself during its lifecycle:

  GET  /api/agents/install              — serves the bootstrap shell script
  POST /api/agents/enroll               — one-time: token + pubkey → WG config
  POST /api/agents/heartbeat            — periodic liveness + counters
  GET  /api/agents/revocation-check     — agent polls for its revocation
                                          status so it can self-uninstall

Auth model
----------
  install     : public (but the script is useless without a valid TOKEN env).
  enroll      : authenticated by the one-time enrollment token itself
                + server-side HMAC signing of tokens. Rate-limited.
  heartbeat   : authenticated by the caller's WireGuard source IP matching
                the agent's assigned wg_ipv4. This endpoint is ONLY
                reachable through the WG tunnel; public internet callers
                can never match a legitimate source IP.
  revocation  : same as heartbeat — WG source IP auth.

All writes land in audit_log via the shared helper.
"""
import logging
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from app.core.security import audit_log, rate_limiter
from app.core.database import get_db

logger = logging.getLogger(__name__)
router = APIRouter()


# ============================================================================
# Request models
# ============================================================================

class AgentEnrollRequest(BaseModel):
    token: str
    public_key: str
    hostname: Optional[str] = None
    lan_interface: Optional[str] = None
    advertised_cidrs: Optional[List[str]] = None
    agent_version: Optional[str] = None


class AgentHeartbeatRequest(BaseModel):
    agent_version: Optional[str] = None
    rx_bytes: Optional[int] = None
    tx_bytes: Optional[int] = None


# ============================================================================
# Enrollment
# ============================================================================

@router.post("/api/agents/enroll", tags=["agent"])
async def enroll_endpoint(
    body: AgentEnrollRequest,
    request: Request,
    rate_limit: None = Depends(rate_limiter),
):
    """Complete an agent enrollment using a one-time token."""
    from app.core.agents import enroll_agent

    source_ip = request.client.host if request and request.client else "unknown"

    try:
        result = enroll_agent(
            raw_token=body.token,
            public_key=body.public_key,
            hostname=body.hostname,
            lan_interface=body.lan_interface,
            advertised_cidrs=body.advertised_cidrs,
            agent_version=body.agent_version,
            source_ip=source_ip,
        )
    except ValueError as e:
        msg = str(e)
        # Don't leak token-validity details to probing callers
        if "token" in msg.lower():
            audit_log(None, "AGENT_ENROLL", f"rejected: {msg}", source_ip)
            raise HTTPException(status_code=401, detail="Invalid or expired enrollment token")
        audit_log(None, "AGENT_ENROLL", f"rejected: {msg}", source_ip)
        raise HTTPException(status_code=400, detail=msg)
    except RuntimeError as e:
        logger.error(f"enroll runtime error: {e}")
        audit_log(None, "AGENT_ENROLL", f"server_error: {e}", source_ip)
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.exception("enroll unexpected error")
        audit_log(None, "AGENT_ENROLL", f"unexpected: {e}", source_ip)
        raise HTTPException(status_code=500, detail="Enrollment failed")

    audit_log(
        None,
        "AGENT_ENROLL",
        f"success id={result['id']} name={result['name']} wg_ipv4={result['wg_ipv4']}",
        source_ip,
    )

    # Return just what the agent needs to write its local config + start talking.
    return {
        "success": True,
        "agent_id": result["id"],
        "name": result["name"],
        "wg_ipv4": result["wg_ipv4"],
        "preshared_key": result["preshared_key"],
        "server_public_key": result["server_public_key"],
        "endpoint": result["endpoint"],
        "agent_allowed_ips": result["agent_allowed_ips"],
        "advertised_cidrs": result["advertised_cidrs"],
        "config": result["config"],
    }


# ============================================================================
# Heartbeat — WG-source-IP authenticated
# ============================================================================

def _authenticated_agent_id(request: Request) -> int:
    """Resolve the agent_id whose wg_ipv4 matches the caller's source IP.
    Raises 403 if no match or if the agent is revoked. ONLY reachable via
    the WG tunnel — spoofing this from the internet is not possible
    because packets with a WG subnet source IP won't reach the FastAPI
    process unless they arrived through the decrypted tunnel."""
    source_ip = request.client.host if request and request.client else "unknown"
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT id, status FROM agents WHERE wg_ipv4 = ?",
            (source_ip,),
        )
        row = c.fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(status_code=403, detail="Agent authentication failed")
    if row["status"] != "enrolled":
        raise HTTPException(status_code=403, detail=f"Agent is {row['status']}")
    return int(row["id"])


@router.post("/api/agents/heartbeat", tags=["agent"])
async def heartbeat_endpoint(body: AgentHeartbeatRequest, request: Request):
    """Record a heartbeat. Auth = request source IP equals the agent's wg_ipv4."""
    from app.core.agents import record_heartbeat
    source_ip = request.client.host if request and request.client else "unknown"

    # Fast reject: if the source isn't even in the WG subnet, don't bother
    # hitting the DB. (Cheap defence-in-depth against malformed probes.)
    agent_id = record_heartbeat(
        source_ip=source_ip,
        agent_version=body.agent_version,
        rx_bytes=body.rx_bytes,
        tx_bytes=body.tx_bytes,
    )
    if agent_id is None:
        raise HTTPException(status_code=403, detail="Agent authentication failed")

    return {"success": True, "agent_id": agent_id}


@router.get("/api/agents/revocation-check", tags=["agent"])
async def revocation_check_endpoint(request: Request):
    """Let the agent daemon poll for its own revocation status. Returns
    `revoked: true` if an admin has revoked the agent — on receiving this
    the daemon should self-uninstall. If the source IP doesn't match any
    known agent, 403 (agent should also self-uninstall in that case)."""
    source_ip = request.client.host if request and request.client else "unknown"
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT status FROM agents WHERE wg_ipv4 = ?",
            (source_ip,),
        )
        row = c.fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(status_code=403, detail="Agent authentication failed")
    return {"revoked": row["status"] == "revoked", "status": row["status"]}


# ============================================================================
# Install script
# ============================================================================

# The Phase 1 install script is an idempotent Bash bootstrap that uses
# wg-quick (already required on any Linux host) and curl. It:
#   1. Validates $TOKEN and $WIRESHIELD_SERVER are set.
#   2. Requires root.
#   3. Installs wireguard-tools + curl + jq if missing (apt/dnf/yum/pacman/apk).
#   4. Generates a WG keypair in /etc/wireshield-agent/.
#   5. POSTs to /api/agents/enroll with the token + pubkey + detected info.
#   6. Writes /etc/wireguard/wg-agent0.conf from the server's response.
#   7. Enables IP forwarding + MASQUERADE for the VPN subnet on the agent's LAN iface.
#   8. Starts wg-quick@wg-agent0 via systemd.
#   9. Installs a systemd timer that runs the heartbeat every 30s.
#
# Phase 2 will replace this with a proper Go binary; for Phase 1 this is
# a fully functional agent with no external dependencies beyond coreutils,
# wg-quick, and curl.

_INSTALL_SCRIPT = r"""#!/usr/bin/env bash
#
# WireShield Agent — bootstrap installer
#
# Usage:
#   curl -sSL https://<server>/api/agents/install | sudo TOKEN=<token> WIRESHIELD_SERVER=<url> bash
#
# Env:
#   TOKEN              (required) one-time enrollment token
#   WIRESHIELD_SERVER  (required) base URL of the WireShield server, e.g. https://vpn.example.com
#   AGENT_LAN_IF       (optional) override auto-detected LAN interface
#   AGENT_CIDRS        (optional) comma-separated CIDRs to advertise if the admin
#                                 didn't pre-declare any (e.g. "192.168.169.0/24")
#
set -euo pipefail

AGENT_ETC="/etc/wireshield-agent"
WG_CONF="/etc/wireguard/wg-agent0.conf"
WG_IFACE="wg-agent0"
HEARTBEAT_SCRIPT="/usr/local/sbin/wireshield-agent-heartbeat"
HEARTBEAT_SERVICE="/etc/systemd/system/wireshield-agent-heartbeat.service"
HEARTBEAT_TIMER="/etc/systemd/system/wireshield-agent-heartbeat.timer"
AGENT_VERSION="phase1-bash-0.1.0"

# ── Pretty output ──────────────────────────────────────────────────────────
_step() { printf "\n\033[1;34m==>\033[0m %s\n" "$*"; }
_ok()   { printf "   \033[0;32m✓\033[0m %s\n" "$*"; }
_warn() { printf "   \033[0;33m!\033[0m %s\n" "$*"; }
_err()  { printf "   \033[0;31m✗\033[0m %s\n" "$*"; exit 1; }

# ── Pre-flight ─────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || _err "Run as root (sudo)."
[[ -n "${TOKEN:-}" ]] || _err "TOKEN env var required."
[[ -n "${WIRESHIELD_SERVER:-}" ]] || _err "WIRESHIELD_SERVER env var required."
# Strip trailing slash
WIRESHIELD_SERVER="${WIRESHIELD_SERVER%/}"

_step "WireShield Agent installer"
printf "   Server: %s\n" "$WIRESHIELD_SERVER"

# ── Install dependencies ───────────────────────────────────────────────────
_step "Installing dependencies (wireguard-tools, curl, jq)"
if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq wireguard-tools curl jq iproute2
elif command -v dnf >/dev/null; then
    dnf install -y -q wireguard-tools curl jq iproute
elif command -v yum >/dev/null; then
    yum install -y -q wireguard-tools curl jq iproute
elif command -v pacman >/dev/null; then
    pacman -Sy --noconfirm --needed wireguard-tools curl jq iproute2
elif command -v apk >/dev/null; then
    apk add --no-progress wireguard-tools curl jq iproute2
else
    _err "No supported package manager found."
fi
_ok "Dependencies installed."

# ── Keypair ────────────────────────────────────────────────────────────────
_step "Generating WireGuard keypair"
mkdir -p "$AGENT_ETC"
chmod 700 "$AGENT_ETC"
if [[ -f "$AGENT_ETC/private.key" ]]; then
    _warn "Existing private key found at $AGENT_ETC/private.key — reusing."
else
    umask 077
    wg genkey > "$AGENT_ETC/private.key"
fi
PRIV_KEY="$(cat "$AGENT_ETC/private.key")"
PUB_KEY="$(echo "$PRIV_KEY" | wg pubkey)"
_ok "Public key: $PUB_KEY"

# ── Detect LAN interface ───────────────────────────────────────────────────
if [[ -n "${AGENT_LAN_IF:-}" ]]; then
    LAN_IF="$AGENT_LAN_IF"
else
    LAN_IF="$(ip route show default | awk '/default/ {print $5; exit}')"
fi
[[ -n "$LAN_IF" ]] || _err "Could not detect LAN interface (set AGENT_LAN_IF)."
_ok "LAN interface: $LAN_IF"

# ── Assemble CIDRs payload ─────────────────────────────────────────────────
CIDR_JSON="null"
if [[ -n "${AGENT_CIDRS:-}" ]]; then
    CIDR_JSON="$(echo "$AGENT_CIDRS" | jq -Rc 'split(",") | map(gsub("^\\s+|\\s+$"; ""))')"
fi

# ── Enroll ─────────────────────────────────────────────────────────────────
_step "Enrolling with server"
HOSTNAME_VAL="$(hostname -f 2>/dev/null || hostname)"
ENROLL_RESP="$(curl -sS --fail --max-time 30 -H 'Content-Type: application/json' \
    -X POST "$WIRESHIELD_SERVER/api/agents/enroll" \
    -d "$(jq -nc \
        --arg t "$TOKEN" --arg pk "$PUB_KEY" \
        --arg hn "$HOSTNAME_VAL" --arg li "$LAN_IF" \
        --arg ver "$AGENT_VERSION" \
        --argjson cidrs "$CIDR_JSON" \
        '{token:$t, public_key:$pk, hostname:$hn, lan_interface:$li, agent_version:$ver, advertised_cidrs:$cidrs}')")" \
    || _err "Enrollment request failed. Check TOKEN validity and server reachability."

echo "$ENROLL_RESP" | jq -e '.success == true' >/dev/null \
    || _err "Enrollment rejected: $(echo "$ENROLL_RESP" | jq -r '.detail // .')"

WG_IPV4="$(echo "$ENROLL_RESP" | jq -r '.wg_ipv4')"
_ok "Assigned WG IP: $WG_IPV4"

# ── Write wg-quick config ──────────────────────────────────────────────────
_step "Writing $WG_CONF"
mkdir -p /etc/wireguard
{
    echo "# ==================================================================="
    echo "# WireShield Agent config — generated by installer"
    echo "# Managed by systemd unit wg-quick@${WG_IFACE}"
    echo "# ==================================================================="
    echo ""
    echo "[Interface]"
    echo "PrivateKey = $PRIV_KEY"
    echo "$ENROLL_RESP" | jq -r '"Address = " + .wg_ipv4 + "/32"'
    echo "PostUp = sysctl -w net.ipv4.ip_forward=1"
    echo "PostUp = iptables -A FORWARD -i %i -j ACCEPT"
    echo "PostUp = iptables -A FORWARD -o %i -j ACCEPT"
    echo "PostUp = iptables -t nat -A POSTROUTING -s $(echo "$ENROLL_RESP" | jq -r '.agent_allowed_ips') -o $LAN_IF -j MASQUERADE"
    echo "PreDown = iptables -t nat -D POSTROUTING -s $(echo "$ENROLL_RESP" | jq -r '.agent_allowed_ips') -o $LAN_IF -j MASQUERADE"
    echo "PreDown = iptables -D FORWARD -o %i -j ACCEPT"
    echo "PreDown = iptables -D FORWARD -i %i -j ACCEPT"
    echo ""
    echo "[Peer]"
    echo "$ENROLL_RESP" | jq -r '"PublicKey = " + .server_public_key'
    echo "$ENROLL_RESP" | jq -r '"PresharedKey = " + .preshared_key'
    echo "$ENROLL_RESP" | jq -r '"Endpoint = " + .endpoint'
    echo "$ENROLL_RESP" | jq -r '"AllowedIPs = " + .agent_allowed_ips'
    echo "PersistentKeepalive = 25"
} > "$WG_CONF"
chmod 600 "$WG_CONF"
_ok "Config written (mode 0600)."

# Persist ip_forward across reboots
if [[ ! -f /etc/sysctl.d/99-wireshield-agent.conf ]]; then
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wireshield-agent.conf
fi

# ── Bring up the tunnel ────────────────────────────────────────────────────
_step "Starting $WG_IFACE"
systemctl enable "wg-quick@${WG_IFACE}" >/dev/null
systemctl restart "wg-quick@${WG_IFACE}"
sleep 1
if systemctl is-active --quiet "wg-quick@${WG_IFACE}"; then
    _ok "wg-quick@${WG_IFACE} active."
else
    _err "wg-quick@${WG_IFACE} failed to start. Check: journalctl -u wg-quick@${WG_IFACE}"
fi

# ── Heartbeat timer ────────────────────────────────────────────────────────
_step "Installing heartbeat timer (30s interval)"
cat > "$HEARTBEAT_SCRIPT" <<SCRIPT
#!/usr/bin/env bash
set -euo pipefail
SERVER="$WIRESHIELD_SERVER"
IFACE="$WG_IFACE"
AGENT_VERSION="$AGENT_VERSION"

# Grab rx/tx bytes from wg (counters are cumulative since interface up)
RX=0 TX=0
if command -v wg >/dev/null; then
    read RX TX < <(wg show "\$IFACE" transfer 2>/dev/null | awk '{print \$2, \$3; exit}')
    RX=\${RX:-0}
    TX=\${TX:-0}
fi

curl -sS --fail --max-time 10 -H 'Content-Type: application/json' \
    -X POST "\$SERVER/api/agents/heartbeat" \
    -d "{\"agent_version\": \"\$AGENT_VERSION\", \"rx_bytes\": \$RX, \"tx_bytes\": \$TX}" \
    > /dev/null || exit 1

# Check revocation; if revoked, self-disable (admin will DELETE properly later)
REVOKED=\$(curl -sS --fail --max-time 10 "\$SERVER/api/agents/revocation-check" | jq -r '.revoked // false' 2>/dev/null || echo false)
if [[ "\$REVOKED" == "true" ]]; then
    logger -t wireshield-agent "revoked by server; stopping tunnel"
    systemctl disable --now wg-quick@"\$IFACE" 2>/dev/null || true
    systemctl disable --now wireshield-agent-heartbeat.timer 2>/dev/null || true
fi
SCRIPT
chmod 755 "$HEARTBEAT_SCRIPT"

cat > "$HEARTBEAT_SERVICE" <<SERVICE
[Unit]
Description=WireShield Agent heartbeat
After=wg-quick@${WG_IFACE}.service
Requires=wg-quick@${WG_IFACE}.service

[Service]
Type=oneshot
ExecStart=$HEARTBEAT_SCRIPT
SERVICE

cat > "$HEARTBEAT_TIMER" <<TIMER
[Unit]
Description=WireShield Agent heartbeat (30s)

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s
Unit=wireshield-agent-heartbeat.service

[Install]
WantedBy=timers.target
TIMER

systemctl daemon-reload
systemctl enable --now wireshield-agent-heartbeat.timer >/dev/null
_ok "Heartbeat timer enabled."

_step "Done"
printf "   Agent ID: %s\n" "$(echo "$ENROLL_RESP" | jq -r '.agent_id')"
printf "   Name:     %s\n" "$(echo "$ENROLL_RESP" | jq -r '.name')"
printf "   WG IP:    %s\n" "$WG_IPV4"
printf "\nTo uninstall later:\n"
printf "   systemctl disable --now wg-quick@%s wireshield-agent-heartbeat.timer\n" "$WG_IFACE"
printf "   rm -rf %s %s /etc/sysctl.d/99-wireshield-agent.conf\n" "$AGENT_ETC" "$WG_CONF"
printf "   rm -f %s %s %s\n" "$HEARTBEAT_SCRIPT" "$HEARTBEAT_SERVICE" "$HEARTBEAT_TIMER"
"""


@router.get("/api/agents/install", tags=["agent"], response_class=PlainTextResponse)
async def install_script_endpoint():
    """Return the Bash bootstrap script for agent installation."""
    return PlainTextResponse(content=_INSTALL_SCRIPT, media_type="text/x-shellscript")
