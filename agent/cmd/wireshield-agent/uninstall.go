package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/siyamsarker/wireshield/agent/internal/config"
	"github.com/siyamsarker/wireshield/agent/internal/logx"
	"github.com/siyamsarker/wireshield/agent/internal/wg"
)

const (
	agentBin         = "/usr/local/bin/wireshield-agent"
	agentServiceFile = "/etc/systemd/system/wireshield-agent.service"
	agentServiceName = "wireshield-agent.service"
)

// runUninstall performs a complete agent teardown on the local host:
//
//  1. Stop + disable wireshield-agent.service (the heartbeat daemon)
//  2. Stop + disable wg-quick@wg-agent0 and remove the WG config
//  3. Delete /etc/wireshield-agent/ (config.json + private.key)
//  4. Remove /etc/systemd/system/wireshield-agent.service
//  5. Remove /usr/local/bin/wireshield-agent  (unless --keep-binary)
//  6. Run systemctl daemon-reload
//
// Every step is idempotent: already-gone files and already-stopped units
// are not errors. Server-side revocation (removing the WireGuard peer and
// marking the DB row revoked) is done separately via the admin console.
func runUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	keepBinary := fs.Bool("keep-binary", false, "do NOT remove /usr/local/bin/wireshield-agent")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: wireshield-agent uninstall [--keep-binary]\n\n")
		fmt.Fprintf(fs.Output(), "Completely removes the agent from this host.\n")
		fmt.Fprintf(fs.Output(), "Server-side revocation must be done separately via the admin console.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// ── Step 1: stop + disable the heartbeat daemon ───────────────────────
	logx.Info("stopping wireshield-agent.service…")
	if err := wg.StopAndDisableUnit(agentServiceName); err != nil {
		logx.Warn("wireshield-agent.service teardown: %v", err)
	} else {
		logx.Info("wireshield-agent.service stopped and disabled")
	}

	// ── Step 2: tear down WireGuard tunnel + delete enrollment config ─────
	// runRevoke handles wg-quick@wg-agent0 + /etc/wireguard/wg-agent0.conf
	// + /etc/wireshield-agent/{config.json,private.key}. It is fully
	// idempotent so calling it on an already-revoked host is harmless.
	logx.Info("tearing down WireGuard tunnel…")
	if err := runRevoke([]string{}); err != nil {
		logx.Warn("revoke: %v", err)
	}

	// ── Step 3: remove /etc/wireshield-agent/ if still present ───────────
	// runRevoke removes the individual files but leaves the directory if any
	// extra files were placed there by the operator.
	cfgDir := config.DefaultDir
	if err := os.RemoveAll(cfgDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		logx.Warn("remove %s: %v", cfgDir, err)
	} else {
		logx.Info("removed %s", cfgDir)
	}

	// ── Step 4: remove the systemd service file ───────────────────────────
	switch err := os.Remove(agentServiceFile); {
	case err == nil:
		logx.Info("removed %s", agentServiceFile)
	case errors.Is(err, os.ErrNotExist):
		// already gone
	default:
		logx.Warn("remove %s: %v", agentServiceFile, err)
	}

	// ── Step 5: reload systemd so it forgets the removed unit ────────────
	if err := wg.DaemonReload(); err != nil {
		logx.Warn("daemon-reload: %v", err)
	} else {
		logx.Info("systemctl daemon-reload done")
	}

	// ── Step 6: remove the binary (last, so earlier steps can still log) ──
	if !*keepBinary {
		switch err := os.Remove(agentBin); {
		case err == nil:
			logx.Info("removed %s", agentBin)
		case errors.Is(err, os.ErrNotExist):
			// already gone
		default:
			logx.Warn("remove %s: %v", agentBin, err)
		}
	} else {
		logx.Info("--keep-binary set; %s left in place", agentBin)
	}

	logx.Info("✓ agent uninstalled from this host")
	logx.Info("  to complete removal, revoke the agent in the admin console:")
	logx.Info("  https://<server>/console  →  Agents  →  Delete")
	return nil
}
