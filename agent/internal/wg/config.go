package wg

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BuildAgentConfig constructs the `/etc/wireguard/wg-agent0.conf` body from
// the fields returned by /api/agents/enroll plus the locally-held private
// key and advertised LAN CIDRs (for the PostUp MASQUERADE rule).
//
// Shape (order matters for readability, not correctness):
//
//   [Interface]
//   PrivateKey = <base64>
//   Address = <wgIPv4>/32
//   PostUp = sysctl -w net.ipv4.ip_forward=1
//   PostUp = iptables -t nat -A POSTROUTING -s <wgSubnet> -o <lanIface> -j MASQUERADE
//   PreDown = iptables -t nat -D POSTROUTING -s <wgSubnet> -o <lanIface> -j MASQUERADE
//
//   [Peer]
//   PublicKey = <serverPub>
//   PresharedKey = <psk>
//   Endpoint = <host:port>
//   AllowedIPs = <wgSubnet>          (just the VPN subnet — NOT 0.0.0.0/0)
//   PersistentKeepalive = 25
//
// lanInterface and advertisedCIDRs may be empty; we only emit NAT rules when
// both are present. We NAT only traffic sourced from the VPN subnet so the
// agent does not become an open relay for its host's own traffic.
type AgentConfigInput struct {
	PrivateKey       string
	WGIPv4           string
	ServerPublicKey  string
	PresharedKey     string
	ServerEndpoint   string
	AgentAllowedIPs  string // subnet the agent routes back through the server (from EnrollResponse)
	LANInterface     string // e.g. eth0 — NAT egress interface on the agent host
	AdvertisedCIDRs  []string
}

func (in *AgentConfigInput) validate() error {
	if in == nil {
		return errors.New("nil AgentConfigInput")
	}
	missing := []string{}
	if strings.TrimSpace(in.PrivateKey) == "" {
		missing = append(missing, "PrivateKey")
	}
	if strings.TrimSpace(in.WGIPv4) == "" {
		missing = append(missing, "WGIPv4")
	}
	if strings.TrimSpace(in.ServerPublicKey) == "" {
		missing = append(missing, "ServerPublicKey")
	}
	if strings.TrimSpace(in.ServerEndpoint) == "" {
		missing = append(missing, "ServerEndpoint")
	}
	if strings.TrimSpace(in.AgentAllowedIPs) == "" {
		missing = append(missing, "AgentAllowedIPs")
	}
	if len(missing) > 0 {
		return fmt.Errorf("AgentConfigInput missing fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// BuildAgentConfig returns the config body as a string. It does NOT write
// to disk — the caller decides where and with what mode.
func BuildAgentConfig(in *AgentConfigInput) (string, error) {
	if err := in.validate(); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", in.PrivateKey)
	fmt.Fprintf(&b, "Address = %s/32\n", in.WGIPv4)

	if in.LANInterface != "" && len(in.AdvertisedCIDRs) > 0 {
		b.WriteString("PostUp = sysctl -w net.ipv4.ip_forward=1\n")
		fmt.Fprintf(&b,
			"PostUp = iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE\n",
			in.AgentAllowedIPs, in.LANInterface,
		)
		fmt.Fprintf(&b,
			"PreDown = iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE\n",
			in.AgentAllowedIPs, in.LANInterface,
		)
	}

	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", in.ServerPublicKey)
	if in.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", in.PresharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", in.ServerEndpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", in.AgentAllowedIPs)
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String(), nil
}

// WriteConfigAtomic writes the WG config at mode 0600 via tmp+rename. The
// parent directory is created at 0755 if missing (matches wg-quick's
// expectation that /etc/wireguard exists).
func WriteConfigAtomic(path, body string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".wg-agent-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	return os.Rename(tmpPath, path)
}
