package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/siyamsarker/wireshield/agent/internal/client"
	"github.com/siyamsarker/wireshield/agent/internal/config"
	"github.com/siyamsarker/wireshield/agent/internal/logx"
	"github.com/siyamsarker/wireshield/agent/internal/wg"
)

// runEnroll exchanges the single-use token for a WG peer config, persists
// local state (config.json + private.key + /etc/wireguard/wg-agent0.conf),
// and — unless --no-start is given — enables the wg-quick@ unit so the
// tunnel comes up immediately and on subsequent boots.
//
// Re-running enroll on an already-enrolled host is refused. Operators who
// need to re-enroll (token rotation after a server migration, etc.) must
// `wireshield-agent revoke` first or pass --force.
func runEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	var (
		token        = fs.String("token", os.Getenv("TOKEN"), "enrollment token (single-use). Env: TOKEN")
		server       = fs.String("server", os.Getenv("WIRESHIELD_SERVER"), "VPN server base URL. Env: WIRESHIELD_SERVER")
		hostname     = fs.String("hostname", defaultHostname(), "hostname advertised to server")
		lanIface     = fs.String("lan-if", os.Getenv("AGENT_LAN_IF"), "LAN interface to MASQUERADE onto (default: auto-detect)")
		cidrs        = fs.String("advertised-cidrs", os.Getenv("AGENT_CIDRS"), "comma-separated LAN CIDRs to advertise (agent-declared; server may override)")
		tlsInsecure  = fs.Bool("tls-insecure", false, "skip TLS verification (lab use only)")
		noStart      = fs.Bool("no-start", false, "write config but do NOT enable wg-quick@ unit")
		force        = fs.Bool("force", false, "overwrite existing enrollment (implies revoke)")
	)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(),
			"usage: wireshield-agent enroll --token <t> --server <url> [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*token) == "" {
		return errors.New("enroll: --token is required (or set TOKEN env var)")
	}
	if strings.TrimSpace(*server) == "" {
		return errors.New("enroll: --server is required (or set WIRESHIELD_SERVER env var)")
	}

	p := paths()
	if config.Exists(p) {
		if !*force {
			return fmt.Errorf("enroll: already enrolled (config at %s); re-run with --force to overwrite", p.Dir)
		}
		logx.Info("--force: tearing down existing enrollment before re-enrolling…")
		if err := runRevoke([]string{}); err != nil {
			logx.Warn("pre-force revoke: %v (continuing anyway)", err)
		}
	}

	// Keypair is generated locally; the private key never leaves this host.
	kp, err := wg.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("keypair: %w", err)
	}

	// LAN interface resolution: explicit flag > env var > auto-detect > skip.
	lan := strings.TrimSpace(*lanIface)
	if lan == "" {
		lan = wg.DetectDefaultLAN()
	}
	if lan != "" && !wg.InterfaceExists(lan) {
		logx.Warn("LAN interface %q not found on host; MASQUERADE rule will be skipped", lan)
		lan = ""
	}

	advertised := splitCSV(*cidrs)

	httpc, err := client.New(*server, Version, "", *tlsInsecure)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logx.Info("enrolling with %s as %q (lan=%q, advertised=%v)", httpc.ServerURL(), *hostname, lan, advertised)
	resp, err := httpc.Enroll(ctx, &client.EnrollRequest{
		Token:           *token,
		PublicKey:       kp.PublicKey,
		Hostname:        *hostname,
		LANInterface:    lan,
		AdvertisedCIDRs: advertised,
		AgentVersion:    Version,
	})
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}

	// Build the WG config *from the server-side response plus our local key*
	// rather than using resp.Config verbatim. The server's string has a
	// placeholder comment where PrivateKey should go; we own the private
	// key so it's cleaner to assemble the file here.
	cfgBody, err := wg.BuildAgentConfig(&wg.AgentConfigInput{
		PrivateKey:      kp.PrivateKey,
		WGIPv4:          resp.WGIPv4,
		ServerPublicKey: resp.ServerPublicKey,
		PresharedKey:    resp.PresharedKey,
		ServerEndpoint:  resp.ServerEndpoint,
		AgentAllowedIPs: resp.AgentAllowedIPs,
		LANInterface:    lan,
		AdvertisedCIDRs: resp.AdvertisedCIDRs,
	})
	if err != nil {
		return fmt.Errorf("build wg config: %w", err)
	}

	// Persist private key first (0600), then wg-agent0.conf (0600), then
	// config.json. If any write fails mid-way we leave the rest in place
	// but return an error — `revoke` cleans up on next operator action.
	if err := config.SavePrivateKey(p, kp.PrivateKey); err != nil {
		return fmt.Errorf("save private key: %w", err)
	}

	wgConfPath := config.DefaultWGConfPath
	if err := wg.WriteConfigAtomic(wgConfPath, cfgBody); err != nil {
		return fmt.Errorf("write %s: %w", wgConfPath, err)
	}

	cfg := &config.Config{
		ServerURL:       httpc.ServerURL(),
		AgentID:         resp.AgentID,
		AgentName:       resp.AgentName,
		PublicKey:       kp.PublicKey,
		WGIPv4:          resp.WGIPv4,
		AdvertisedCIDRs: resp.AdvertisedCIDRs,
		WGInterface:     config.DefaultWGIface,
		WGConfPath:      wgConfPath,
		TLSInsecure:     *tlsInsecure,
	}
	if err := config.Save(p, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	if err := config.SaveHeartbeatSecret(p, resp.HeartbeatSecret); err != nil {
		return fmt.Errorf("save heartbeat secret: %w", err)
	}

	logx.Info("enrolled: agent_id=%d name=%s wg_ipv4=%s", resp.AgentID, resp.AgentName, resp.WGIPv4)
	logx.Info("wrote: %s, %s, %s", p.PrivateKey, wgConfPath, p.Config)

	if *noStart {
		logx.Info("--no-start given; skipping systemctl enable --now")
		return nil
	}
	if err := wg.EnableAndStart(config.DefaultWGIface); err != nil {
		return fmt.Errorf("bring up WG: %w", err)
	}
	logx.Info("wg-quick@%s enabled and started", config.DefaultWGIface)
	return nil
}

func defaultHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
