package wg

import (
	"os/exec"
)

// ReconcileForwarding idempotently ensures the three iptables rules that
// let VPN traffic flow through this agent to its LAN are in place:
//
//  1. FORWARD -i <wgIface> -j ACCEPT   (inbound from tunnel)
//  2. FORWARD -o <wgIface> -j ACCEPT   (outbound to tunnel)
//  3. nat POSTROUTING -s <wgSubnet> -o <lanIface> -j MASQUERADE
//
// Called by the daemon whenever the server reports a CIDR change so the
// agent heals itself without requiring manual re-enrollment or reboots.
// Each rule is checked with `iptables -C` before insertion; no-op if already
// present. Errors are silently swallowed because the caller runs as a
// background goroutine — the wg-agent0.conf PostUp block is the authoritative
// source on next wg-quick restart.
func ReconcileForwarding(wgIface, wgSubnet, lanIface string) {
	if wgIface == "" || lanIface == "" {
		return
	}
	ensureForward("-i", wgIface)
	ensureForward("-o", wgIface)
	if wgSubnet != "" {
		ensureMasquerade(wgSubnet, lanIface)
	}
}

func ensureForward(dir, iface string) {
	check := exec.Command("iptables", "-C", "FORWARD", dir, iface, "-j", "ACCEPT")
	if check.Run() == nil {
		return
	}
	exec.Command("iptables", "-A", "FORWARD", dir, iface, "-j", "ACCEPT").Run() //nolint:errcheck
}

func ensureMasquerade(subnet, lanIface string) {
	check := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING",
		"-s", subnet, "-o", lanIface, "-j", "MASQUERADE")
	if check.Run() == nil {
		return
	}
	exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", //nolint:errcheck
		"-s", subnet, "-o", lanIface, "-j", "MASQUERADE").Run()
}
