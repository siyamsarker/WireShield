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
  heartbeat   : authenticated by Authorization: Bearer <heartbeat_secret>
                issued at enrollment and stored as a SHA-256 hash in the DB.
                Works regardless of routing path — no WG tunnel required.
  revocation  : same as heartbeat — bearer token auth.

All writes land in audit_log via the shared helper.
"""
import hashlib
import logging
import os
from pathlib import Path
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import PlainTextResponse, FileResponse
from pydantic import BaseModel

from app.core.security import audit_log, rate_limiter
from app.core.database import get_db
from app.core.config import AGENT_BINARY_DIR

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
        "heartbeat_secret": result["heartbeat_secret"],
    }


# ============================================================================
# Heartbeat — WG-source-IP authenticated
# ============================================================================

def _authenticated_agent_id(request: Request) -> int:
    """Resolve agent_id by bearer token from the Authorization header.
    The token is a high-entropy secret issued at enrollment; we store only
    its SHA-256 hash so a DB leak does not expose the secret."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=403, detail="Agent authentication failed")
    raw_token = auth[len("Bearer "):]
    if not raw_token:
        raise HTTPException(status_code=403, detail="Agent authentication failed")
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT id, status FROM agents WHERE heartbeat_secret_hash = ?",
            (token_hash,),
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
    """Record a heartbeat. Auth = Authorization: Bearer <heartbeat_secret>."""
    from app.core.agents import record_heartbeat
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=403, detail="Agent authentication failed")
    raw_token = auth[len("Bearer "):]
    source_ip = request.client.host if request and request.client else "unknown"
    result = record_heartbeat(
        auth_token=raw_token,
        source_ip=source_ip,
        agent_version=body.agent_version,
        rx_bytes=body.rx_bytes,
        tx_bytes=body.tx_bytes,
    )
    if result is None:
        raise HTTPException(status_code=403, detail="Agent authentication failed")

    return {
        "success": True,
        "agent_id": result["agent_id"],
        "advertised_cidrs": result["advertised_cidrs"],
        "lan_interface": result["lan_interface"],
    }


@router.get("/api/agents/revocation-check", tags=["agent"])
async def revocation_check_endpoint(request: Request):
    """Let the agent daemon poll for its own revocation status. Returns
    `revoked: true` if an admin has revoked the agent — on receiving this
    the daemon should self-uninstall. Auth = Authorization: Bearer <heartbeat_secret>."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=403, detail="Agent authentication failed")
    raw_token = auth[len("Bearer "):]
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT status FROM agents WHERE heartbeat_secret_hash = ?",
            (token_hash,),
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

# The legacy install script is an idempotent Bash bootstrap that uses
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
# Newer deployments use the Go agent (see /api/agents/install-go); this
# Bash flow stays as a fully functional fallback with no dependencies
# beyond coreutils, wg-quick, and curl.

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
AGENT_VERSION="bash-0.1.0"

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
    """Return the legacy Bash bootstrap script for agent installation.

    Preserved for backward compatibility — operators with existing cURL
    one-liners continue to work. New installs should use /api/agents/install-go
    (Go daemon)."""
    return PlainTextResponse(content=_INSTALL_SCRIPT, media_type="text/x-shellscript")


# ============================================================================
# Go agent distribution
# ----------------------------------------------------------------------------
# The admin populates AGENT_BINARY_DIR via `make -C agent dist` (tarball
# lands on the VPN server, unpacks into a per-arch tree). These endpoints
# only *serve* what is already on disk — they never shell out to `go build`.
# Arch names are restricted to an allow-list so path traversal is impossible.
# ============================================================================

_ALLOWED_ARCHES = {"linux-amd64", "linux-arm64"}
_BINARY_FILENAME = "wireshield-agent"
_UNIT_FILENAME = "wireshield-agent.service"
_INSTALLER_GO_FILENAME = "install.sh"


def _binary_filename(arch: str) -> str:
    """Return the on-disk filename for arch using the standard <name>_<os>_<arch>
    convention, e.g. 'wireshield-agent_linux_amd64'."""
    return f"{_BINARY_FILENAME}_{arch.replace('-', '_')}"


def _binary_path(arch: str) -> Path:
    """Return the on-disk binary path for a whitelisted arch, or raise 404.
    Only names in _ALLOWED_ARCHES are accepted; this blocks path traversal
    regardless of FastAPI's route parsing."""
    if arch not in _ALLOWED_ARCHES:
        raise HTTPException(status_code=404, detail=f"unsupported arch: {arch}")
    return Path(AGENT_BINARY_DIR) / _binary_filename(arch)


def _agent_dist_file(relative: str) -> Path:
    """Resolve a file bundled under agent/dist/ for defaults (unit, install.sh)."""
    # This router lives at console-server/app/routers/agents.py. The repo
    # root is 3 parents up; agent/dist/ is the sibling of console-server/.
    repo_root = Path(__file__).resolve().parents[3]
    return repo_root / "agent" / "dist" / relative


@router.get("/api/agents/binary/{arch}.sha256", tags=["agent"])
async def agent_binary_sha_endpoint(arch: str):
    """Serve the sidecar .sha256 checksum generated by `make dist`.

    Optional — install.sh treats a 404 here as "no checksum published"
    and continues without verification.

    Declared *before* the generic binary route so FastAPI matches the
    more-specific `.sha256` suffix first."""
    if arch not in _ALLOWED_ARCHES:
        raise HTTPException(status_code=404, detail=f"unsupported arch: {arch}")
    path = Path(AGENT_BINARY_DIR) / f"{_binary_filename(arch)}.sha256"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="no checksum published")
    return FileResponse(str(path), media_type="text/plain")


@router.get("/api/agents/binary/{arch}", tags=["agent"])
async def agent_binary_endpoint(arch: str):
    """Stream the pre-built wireshield-agent binary for <arch>.

    Intentionally unauthenticated: the binary is not a secret, and the
    caller still needs a valid enrollment TOKEN to actually join the
    VPN. Restricting the download would only break the bootstrap
    install.sh flow without adding real security.
    """
    path = _binary_path(arch)
    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"binary for {arch} not published; run `make -C agent dist` on the VPN server",
        )
    return FileResponse(
        str(path),
        media_type="application/octet-stream",
        filename=_BINARY_FILENAME,
    )


@router.get("/api/agents/unit", tags=["agent"], response_class=PlainTextResponse)
async def agent_systemd_unit_endpoint():
    """Serve the systemd unit file.

    Prefers a version-matched file under AGENT_BINARY_DIR (shipped by
    `make dist` alongside the binary); falls back to the repo-bundled
    agent/dist/wireshield-agent.service so this endpoint always works
    in a fresh dev install."""
    published = Path(AGENT_BINARY_DIR) / _UNIT_FILENAME
    fallback = _agent_dist_file(_UNIT_FILENAME)
    for candidate in (published, fallback):
        if candidate.is_file():
            return PlainTextResponse(
                content=candidate.read_text(),
                media_type="text/plain; charset=utf-8",
            )
    raise HTTPException(status_code=404, detail="systemd unit not found on server")


@router.get("/api/agents/install-go", tags=["agent"], response_class=PlainTextResponse)
async def install_script_go_endpoint():
    """Serve the Bash bootstrap that fetches the Go binary + enrolls.

    Mirrors the legacy /api/agents/install flow but for the Go daemon.
    Same precedence rule as /api/agents/unit: published copy first,
    repo-bundled fallback second."""
    published = Path(AGENT_BINARY_DIR) / _INSTALLER_GO_FILENAME
    fallback = _agent_dist_file(_INSTALLER_GO_FILENAME)
    for candidate in (published, fallback):
        if candidate.is_file():
            return PlainTextResponse(
                content=candidate.read_text(),
                media_type="text/x-shellscript",
            )
    raise HTTPException(status_code=404, detail="install script not found on server")


# ----------------------------------------------------------------------------
# Auto-update version manifest
#
# /api/agents/version is the cheap polling endpoint the daemon hits every
# few hours to decide whether it needs to pull a new binary. Format:
#
#   {
#     "current_version": "1.1.0",
#     "released_at":     "2026-04-26T10:00:00Z",   (optional)
#     "min_version":     "1.0.0",                  (optional, force-upgrade gate)
#     "arches": {
#       "linux-amd64": {
#         "url":    "/api/agents/binary/linux-amd64",
#         "sha256": "abc...64chars"
#       },
#       "linux-arm64": { ... }
#     }
#   }
#
# Source of truth: $AGENT_BINARY_DIR/version.json, written by the operator's
# release flow (typically `make dist` followed by manual edit). If the file
# is missing we fall back to a synthetic manifest computed from whatever
# binaries are on disk — keeps the endpoint useful in dev installs without
# requiring a manual JSON file.
# ----------------------------------------------------------------------------

import json as _json  # local import alias to avoid shadowing earlier `json` if added

_VERSION_MANIFEST_FILENAME = "version.json"


def _read_published_sha256(arch: str) -> Optional[str]:
    """Read the sidecar SHA-256 produced by `make dist` for one arch.
    Returns the 64-char lowercase hex digest, or None if missing/malformed."""
    path = Path(AGENT_BINARY_DIR) / f"{_binary_filename(arch)}.sha256"
    try:
        line = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    # `sha256sum` and `shasum -a 256` both emit "<hex>  <filename>"
    digest = line.split()[0] if line else ""
    if len(digest) == 64 and all(c in "0123456789abcdefABCDEF" for c in digest):
        return digest.lower()
    return None


def _synthesize_manifest() -> Dict[str, Any]:
    """Best-effort manifest when version.json is absent. Reports
    current_version='unknown' so well-behaved agents do nothing."""
    arches: Dict[str, Any] = {}
    for arch in sorted(_ALLOWED_ARCHES):
        binary = Path(AGENT_BINARY_DIR) / _binary_filename(arch)
        if binary.is_file():
            entry: Dict[str, Any] = {"url": f"/api/agents/binary/{arch}"}
            sha = _read_published_sha256(arch)
            if sha:
                entry["sha256"] = sha
            arches[arch] = entry
    return {
        "current_version": "unknown",
        "arches": arches,
        "synthesized": True,
    }


@router.get("/api/agents/version", tags=["agent"])
async def agent_version_endpoint():
    """Return the published agent version manifest.

    Intentionally unauthenticated: same rationale as /api/agents/binary —
    the manifest is not a secret and the agent needs to call this before
    it has any kind of session. Cache-Control: no-store so a stale CDN
    layer (if any) doesn't pin agents to an old version after a release.
    """
    manifest_path = Path(AGENT_BINARY_DIR) / _VERSION_MANIFEST_FILENAME
    if manifest_path.is_file():
        try:
            data = _json.loads(manifest_path.read_text(encoding="utf-8"))
        except _json.JSONDecodeError as exc:
            logger.warning("version.json malformed: %s", exc)
            raise HTTPException(status_code=500, detail="version manifest malformed")

        # Validate the arch allow-list — never let an operator typo a
        # manifest into pointing agents at a download for an unknown arch.
        arches = data.get("arches") or {}
        sanitized: Dict[str, Any] = {}
        for arch, entry in arches.items():
            if arch not in _ALLOWED_ARCHES or not isinstance(entry, dict):
                continue
            url = entry.get("url") or f"/api/agents/binary/{arch}"
            sanitized_entry = {"url": url}
            if isinstance(entry.get("sha256"), str) and len(entry["sha256"]) == 64:
                sanitized_entry["sha256"] = entry["sha256"].lower()
            sanitized[arch] = sanitized_entry

        # Backfill missing sha256 from the on-disk sidecar if available.
        for arch in _ALLOWED_ARCHES:
            entry = sanitized.get(arch)
            if entry and "sha256" not in entry:
                sha = _read_published_sha256(arch)
                if sha:
                    entry["sha256"] = sha

        return {
            "current_version": str(data.get("current_version") or "unknown"),
            "released_at": data.get("released_at"),
            "min_version": data.get("min_version"),
            "arches": sanitized,
        }

    return _synthesize_manifest()
