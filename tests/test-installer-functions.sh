#!/usr/bin/env bash
#
# Scenario tests for the installer's WireGuard module-provisioning logic:
#   _ws_kernel_flavor
#   _ws_apt_install_if_available
#   _ws_ensure_wireguard_module
#
# Regression coverage for the Ubuntu 26.04 (cloud kernel) install failure where
# wireguard.ko lives in a linux-modules-extra package the image doesn't ship,
# the old installer attempted a hardcoded package name (apt error), modprobe
# failed silently, and wg-quick died with a misleading "reboot" hint.
#
# Pure bash, no root, no network: every external command the functions call
# (uname, modprobe, apt-cache, apt-get) is replaced with a PATH stub that logs
# its invocation and behaves according to per-scenario state files.
#
# Run: bash tests/test-installer-functions.sh

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
STUB="${WORK}/bin"
STATE="${WORK}/state"
mkdir -p "${STUB}" "${STATE}"
trap 'rm -rf "${WORK}"' EXIT

# ── PATH stubs ───────────────────────────────────────────────────────────────

cat > "${STUB}/uname" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "-r" ]]; then
    cat "${WS_STATE}/uname_r"
else
    /usr/bin/uname "$@"
fi
EOF

cat > "${STUB}/modprobe" <<'EOF'
#!/usr/bin/env bash
echo "modprobe $*" >> "${WS_STATE}/calls"
[[ -f "${WS_STATE}/module_ok" ]] && exit 0
exit 1
EOF

cat > "${STUB}/apt-cache" <<'EOF'
#!/usr/bin/env bash
echo "apt-cache $*" >> "${WS_STATE}/calls"
if [[ "${1:-}" == "show" ]]; then
    grep -qxF "${2:-}" "${WS_STATE}/available_pkgs" 2>/dev/null && exit 0
fi
exit 100
EOF

cat > "${STUB}/apt-get" <<'EOF'
#!/usr/bin/env bash
echo "apt-get $*" >> "${WS_STATE}/calls"
if [[ "${1:-}" == "install" ]]; then
    pkg=""
    for a in "$@"; do pkg="$a"; done
    if grep -qxF "${pkg}" "${WS_STATE}/available_pkgs" 2>/dev/null; then
        case "${pkg}" in
            linux-modules-extra-*)
                # Installing a modules package makes modprobe succeed.
                touch "${WS_STATE}/module_ok"
                ;;
            wireguard-go)
                printf '#!/usr/bin/env bash\nexit 0\n' > "${WS_BIN}/wireguard-go"
                chmod +x "${WS_BIN}/wireguard-go"
                ;;
        esac
        exit 0
    fi
    echo "E: Unable to locate package ${pkg}" >&2
    exit 100
fi
exit 0
EOF

cat > "${STUB}/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "${WS_STATE}/calls"
exit 0
EOF

chmod +x "${STUB}"/*

export WS_STATE="${STATE}"
export WS_BIN="${STUB}"
export PATH="${STUB}:${PATH}"
# Point the builtin-module check at a path that never exists so only the
# stubbed modprobe decides kernel availability.
export WS_TEST_SYS_MODULE_DIR="${WORK}/no-such-sys-module"

# Source the installer (function definitions only — the interactive main is
# guarded by a BASH_SOURCE check and does not run when sourced).
# shellcheck disable=SC1091
source "${ROOT}/wireshield.sh"
# Drop the installer's inherited ERR trap: these tests intentionally exercise
# non-zero return paths and the trap would spam stderr for each of them.
trap - ERR
set +E

# ── tiny assertion helpers ───────────────────────────────────────────────────

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); echo "  ✓ $1"; }
bad()  { FAIL=$((FAIL + 1)); echo "  ✗ $1"; }
check() {
    local desc="$1"; shift
    if "$@"; then ok "${desc}"; else bad "${desc}"; fi
}
not_in_calls() { ! grep -q "$1" "${STATE}/calls" 2>/dev/null; }
in_calls()     { grep -q "$1" "${STATE}/calls" 2>/dev/null; }

reset_state() {
    rm -f "${STATE}/module_ok" "${STATE}/calls" "${STUB}/wireguard-go"
    : > "${STATE}/available_pkgs"
    : > "${STATE}/calls"
    echo "${1:-7.0.0-1004-aws}" > "${STATE}/uname_r"
    _WS_WG_BACKEND="kernel"
}

# ── flavor parsing ───────────────────────────────────────────────────────────

echo "Kernel flavor parsing"
echo "7.0.0-1004-aws" > "${STATE}/uname_r"
check "cloud kernel '7.0.0-1004-aws' → aws" test "$(_ws_kernel_flavor)" = "aws"
echo "6.8.0-31-generic" > "${STATE}/uname_r"
check "stock kernel '6.8.0-31-generic' → generic" test "$(_ws_kernel_flavor)" = "generic"
echo "5.10.0" > "${STATE}/uname_r"
check "unflavored '5.10.0' → empty" test -z "$(_ws_kernel_flavor)"

# ── guarded apt install ──────────────────────────────────────────────────────

echo "Guarded apt install"
reset_state
if ! _ws_apt_install_if_available no-such-pkg && not_in_calls "apt-get install"; then
    ok "unknown package is never passed to apt-get install"
else
    bad "unknown package is never passed to apt-get install"
fi
reset_state
echo "some-pkg" >> "${STATE}/available_pkgs"
if _ws_apt_install_if_available some-pkg && in_calls "apt-get install -y some-pkg"; then
    ok "known package installs and returns success"
else
    bad "known package installs and returns success"
fi

# ── scenario 1: module already loadable ──────────────────────────────────────

echo "Scenario 1: kernel module loads on the first try"
reset_state
touch "${STATE}/module_ok"
_ws_ensure_wireguard_module; rc=$?
check "returns success" test "${rc}" -eq 0
check "backend is kernel" test "${_WS_WG_BACKEND}" = "kernel"
check "no package installs attempted" not_in_calls "apt-get install"

# ── scenario 2: versioned extras package provides the module ─────────────────

echo "Scenario 2: linux-modules-extra-<release> provides the module"
reset_state
echo "linux-modules-extra-7.0.0-1004-aws" >> "${STATE}/available_pkgs"
_ws_ensure_wireguard_module; rc=$?
check "returns success" test "${rc}" -eq 0
check "backend is kernel" test "${_WS_WG_BACKEND}" = "kernel"
check "installed the exact versioned package" in_calls "apt-get install -y linux-modules-extra-7.0.0-1004-aws"
check "did not need the flavor meta-package" not_in_calls "apt-get install -y linux-modules-extra-aws$"

# ── scenario 3: only the flavor meta-package exists ──────────────────────────

echo "Scenario 3: only the flavor meta-package (linux-modules-extra-aws) exists"
reset_state
echo "linux-modules-extra-aws" >> "${STATE}/available_pkgs"
_ws_ensure_wireguard_module; rc=$?
check "returns success" test "${rc}" -eq 0
check "backend is kernel" test "${_WS_WG_BACKEND}" = "kernel"
check "installed the flavor meta-package" in_calls "apt-get install -y linux-modules-extra-aws"

# ── scenario 4: no module packages → wireguard-go fallback ───────────────────

echo "Scenario 4: no modules packages anywhere → userspace wireguard-go fallback"
reset_state
echo "wireguard-go" >> "${STATE}/available_pkgs"
_ws_ensure_wireguard_module; rc=$?
check "returns success" test "${rc}" -eq 0
check "backend is userspace" test "${_WS_WG_BACKEND}" = "userspace"
check "installed wireguard-go" in_calls "apt-get install -y wireguard-go"

# ── scenario 5: nothing available at all ─────────────────────────────────────

echo "Scenario 5: nothing available → reported unavailable, no blind installs"
reset_state
_ws_ensure_wireguard_module; rc=$?
check "returns failure" test "${rc}" -eq 1
check "backend is unavailable" test "${_WS_WG_BACKEND}" = "unavailable"
check "never invoked apt-get install for a missing package" not_in_calls "apt-get install"

# ── scenario 6: ipset boot unit (hardened-host fix) ──────────────────────────
# Regression for Ubuntu 26.04 where exec of /usr/sbin/ipset from wg-quick is
# denied (status 126) by AppArmor confinement even as root: the sets must be
# pre-created by a oneshot unit ordered before wg-quick.

echo "Scenario 6: wireshield-ipsets oneshot unit + wg-quick drop-in"
reset_state
export WS_TEST_SYSTEMD_DIR="${WORK}/systemd"
_ws_install_ipset_boot_unit "wg0"
UNIT="${WS_TEST_SYSTEMD_DIR}/wireshield-ipsets.service"
DROPIN="${WS_TEST_SYSTEMD_DIR}/wg-quick@wg0.service.d/wireshield-ipsets.conf"
check "unit file written" test -f "${UNIT}"
check "unit ordered before wg-quick@wg0" grep -q "^Before=wg-quick@wg0.service$" "${UNIT}"
check "unit is a oneshot that stays 'active'" grep -q "^RemainAfterExit=yes$" "${UNIT}"
check "creates the v4 set idempotently" grep -q "ipset create ws_2fa_allowed_v4 hash:ip family inet -exist" "${UNIT}"
check "creates the v6 set idempotently" grep -q "ipset create ws_2fa_allowed_v6 hash:ip family inet6 -exist" "${UNIT}"
check "drop-in written for wg-quick@wg0" test -f "${DROPIN}"
check "drop-in wants the ipset unit" grep -q "^Wants=wireshield-ipsets.service$" "${DROPIN}"
check "drop-in orders after the ipset unit" grep -q "^After=wireshield-ipsets.service$" "${DROPIN}"
check "systemd reloaded" in_calls "systemctl daemon-reload"
check "unit enabled and started immediately" in_calls "systemctl enable --now wireshield-ipsets.service"
unset WS_TEST_SYSTEMD_DIR

# ── static regression guards on the generated wg0.conf PostUp lines ──────────

echo "Static guards: PostUp ipset creation must never be fatal"
check "v4 PostUp create is exec-denial tolerant" \
    grep -q 'PostUp = ipset create ws_2fa_allowed_v4 hash:ip family inet -exist 2>/dev/null || true' "${ROOT}/wireshield.sh"
check "v6 PostUp create is exec-denial tolerant" \
    grep -q 'PostUp = ipset create ws_2fa_allowed_v6 hash:ip family inet6 -exist 2>/dev/null || true' "${ROOT}/wireshield.sh"

# ── summary ──────────────────────────────────────────────────────────────────

echo
echo "PASS=${PASS} FAIL=${FAIL}"
test "${FAIL}" -eq 0
