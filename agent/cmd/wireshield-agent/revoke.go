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

// runRevoke performs LOCAL agent teardown: disable the systemd wg-quick
// unit, remove /etc/wireguard/wg-agent0.conf, and delete config.json +
// private.key. The *server* side is revoked via the admin console; this
// command is what the operator runs on the agent host to clean up after
// a server-side revocation has already happened (or as part of
// decommissioning).
//
// Idempotent: runs without error even if nothing is enrolled.
func runRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	keepConfig := fs.Bool("keep-wg-conf", false, "do NOT delete /etc/wireguard/wg-agent0.conf")
	if err := fs.Parse(args); err != nil {
		return err
	}

	p := paths()
	cfg, cfgErr := config.Load(p)

	// 1. Bring down wg-quick@<iface>. Failures here are logged but not
	//    fatal — we still want to clean up disk state so a subsequent
	//    enroll works.
	iface := config.DefaultWGIface
	if cfg != nil {
		iface = cfg.WGInterface
	}
	if err := wg.DisableAndStop(iface); err != nil {
		logx.Warn("wg-quick@%s teardown: %v", iface, err)
	} else {
		logx.Info("wg-quick@%s stopped and disabled", iface)
	}

	// 2. Remove /etc/wireguard/wg-agent0.conf unless the operator asked
	//    to keep it (useful for debugging).
	wgConf := config.DefaultWGConfPath
	if cfg != nil && cfg.WGConfPath != "" {
		wgConf = cfg.WGConfPath
	}
	if !*keepConfig {
		switch err := os.Remove(wgConf); {
		case err == nil:
			logx.Info("removed %s", wgConf)
		case errors.Is(err, os.ErrNotExist):
			// Already gone; nothing to say.
		default:
			logx.Warn("remove %s: %v", wgConf, err)
		}
	}

	// 3. Delete persisted agent identity.
	if err := config.Remove(p); err != nil {
		return fmt.Errorf("remove agent state: %w", err)
	}
	logx.Info("removed agent state under %s", p.Dir)

	if cfgErr != nil && !errors.Is(cfgErr, os.ErrNotExist) {
		// Non-ENOENT load errors are interesting to surface post-hoc.
		logx.Warn("initial config load returned: %v", cfgErr)
	}
	return nil
}
