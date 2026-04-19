import os
import subprocess
from datetime import datetime
from fastapi import APIRouter
from app.core.database import get_db

router = APIRouter()


def _check_db() -> dict:
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users")
        user_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now')")
        active_sessions = c.fetchone()[0]
        conn.close()
        return {"status": "ok", "users": user_count, "active_sessions": active_sessions}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _check_interface(iface: str) -> dict:
    try:
        path = f"/sys/class/net/{iface}/operstate"
        if not os.path.exists(path):
            return {"status": "missing", "interface": iface}
        with open(path, "r") as f:
            state = f.read().strip()
        return {
            "status": "up" if state in ("up", "unknown") else "down",
            "interface": iface,
            "operstate": state,
        }
    except Exception as e:
        return {"status": "error", "interface": iface, "error": str(e)}


def _check_iptables_portal() -> dict:
    """Verify the portal's INPUT ACCEPT rules for ports 80/443 exist."""
    rules = {}
    for port in (80, 443):
        try:
            r = subprocess.run(
                ["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            rules[str(port)] = "present" if r.returncode == 0 else "missing"
        except FileNotFoundError:
            rules[str(port)] = "iptables_unavailable"
        except Exception as e:
            rules[str(port)] = f"error: {e}"
    return rules


@router.get("/health", tags=["system"])
async def health_check():
    """Comprehensive health check: DB, WireGuard interface, iptables, watchdog."""
    status = {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    # Database
    status["database"] = _check_db()
    if status["database"].get("status") != "ok":
        status["status"] = "degraded"

    # WireGuard interface state
    from app.core.tasks import _ensure_wg_interface, get_watchdog_state
    iface = _ensure_wg_interface() or "wg0"
    status["wireguard"] = _check_interface(iface)
    if status["wireguard"].get("status") not in ("up",):
        status["status"] = "degraded"

    # iptables portal rules
    status["iptables_portal"] = _check_iptables_portal()
    if any(v != "present" for v in status["iptables_portal"].values()):
        status["status"] = "degraded"

    # Watchdog snapshot (interface transitions + rule-fix counter)
    status["watchdog"] = get_watchdog_state()

    return status
