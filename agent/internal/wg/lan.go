package wg

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
)

// DetectDefaultLAN returns the outbound interface name by running
// `ip route show default` and parsing the first non-WG link. If no route
// is found, it returns "" — callers fall back to AGENT_LAN_IF env var or
// skip emitting the NAT rule entirely.
func DetectDefaultLAN() string {
	out, err := exec.Command("ip", "-o", "-4", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		for i, f := range fields {
			if f == "dev" && i+1 < len(fields) {
				ifname := fields[i+1]
				// Guard: don't MASQUERADE out of another WG tunnel.
				if strings.HasPrefix(ifname, "wg") {
					continue
				}
				return ifname
			}
		}
	}
	return ""
}

// InterfaceExists reports whether a network interface by that name is
// currently present. Used to validate AGENT_LAN_IF overrides before we
// commit it to a config file that wg-quick would reject.
func InterfaceExists(name string) bool {
	if name == "" {
		return false
	}
	_, err := os.Stat("/sys/class/net/" + name)
	return err == nil
}
