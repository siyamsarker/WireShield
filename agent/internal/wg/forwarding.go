package wg

import (
	"os"
	"os/exec"
	"strings"
)

// ReconcileForwarding idempotently ensures the kernel state needed to forward
// VPN traffic through this agent to its LAN is in place:
//
//  1. net.ipv4.ip_forward=1            (kernel routing enabled)
//  2. FORWARD -i <wgIface> -j ACCEPT   (inbound from tunnel)
//  3. FORWARD -o <wgIface> -j ACCEPT   (outbound to tunnel)
//  4. nat POSTROUTING -s <wgSubnet> -o <lanIface> -j MASQUERADE
//
// Called by the daemon whenever the server reports a CIDR change so the
// agent heals itself without requiring manual re-enrollment or reboots.
// Each step is checked before mutation; no-op if already present. Errors
// are silently swallowed because the caller runs as a background goroutine —
// the wg-agent0.conf PostUp block is the authoritative source on next
// wg-quick restart.
//
// The ip_forward step is critical for the post-enrollment CIDR-add path:
// when an agent enrolls with empty advertised_cidrs, BuildAgentConfig omits
// the `sysctl -w net.ipv4.ip_forward=1` PostUp line, so the knob remains
// off in the kernel even after the admin later patches CIDRs and the
// iptables rules get added at runtime.
func ReconcileForwarding(wgIface, wgSubnet, lanIface string) {
	if wgIface == "" || lanIface == "" {
		return
	}
	ensureIPForward()
	ensureForward("-i", wgIface)
	ensureForward("-o", wgIface)
	if wgSubnet != "" {
		ensureMasquerade(wgSubnet, lanIface)
	}
}

func ensureIPForward() {
	// Cheap read of /proc/sys before any subprocess; the knob is on for the
	// vast majority of post-startup invocations because wg-quick's PostUp
	// already set it. Only shells out when actually needed.
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			return
		}
	}
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run() //nolint:errcheck
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
