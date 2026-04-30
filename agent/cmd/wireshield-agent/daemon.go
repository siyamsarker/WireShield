package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/siyamsarker/wireshield/agent/internal/client"
	"github.com/siyamsarker/wireshield/agent/internal/config"
	"github.com/siyamsarker/wireshield/agent/internal/logx"
	"github.com/siyamsarker/wireshield/agent/internal/runner"
	"github.com/siyamsarker/wireshield/agent/internal/updater"
	"github.com/siyamsarker/wireshield/agent/internal/wg"
)

// runDaemon is the long-running heartbeat + revocation loop, invoked by
// the bundled systemd unit. Exit semantics:
//
//   0   — received SIGTERM/SIGINT; clean shutdown (systemd restart policy
//         does not re-fire because exit was expected)
//   1   — fatal config/startup error
//   2   — server confirmed the agent has been revoked (runner.ErrRevoked);
//         systemd unit is configured with RestartPreventExitStatus=2 so
//         the daemon stays down after revocation
//   75  — auto-update replaced the on-disk binary (sysexits EX_TEMPFAIL);
//         systemd's Restart=on-failure rule reloads onto the new image
func runDaemon(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var (
		heartbeatSec   = fs.Int("heartbeat", 30, "heartbeat interval seconds")
		revocationSec  = fs.Int("revocation", 60, "revocation-check interval seconds")
		autoUpdate     = fs.Bool("auto-update", false, "enable periodic self-upgrade against the server's published manifest")
		updateHours    = fs.Int("update-interval", 6, "auto-update check interval (hours, only used with --auto-update)")
	)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: wireshield-agent run [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	p := paths()
	cfg, err := config.Load(p)
	if err != nil {
		return fmt.Errorf("load config (is the agent enrolled?): %w", err)
	}
	heartbeatSecret, err := config.LoadHeartbeatSecret(p)
	if err != nil {
		return fmt.Errorf("load heartbeat secret (re-enrollment may be needed): %w", err)
	}

	httpc, err := client.New(cfg.ServerURL, Version, heartbeatSecret, cfg.TLSInsecure)
	if err != nil {
		return err
	}

	reader := &wgReader{iface: cfg.WGInterface}
	opts := runner.DefaultOptions(Version)
	opts.HeartbeatInterval = time.Duration(*heartbeatSec) * time.Second
	opts.RevocationInterval = time.Duration(*revocationSec) * time.Second

	if *autoUpdate {
		if *updateHours < 1 {
			*updateHours = 1
		}
		opts.AutoUpdateInterval = time.Duration(*updateHours) * time.Hour
		opts.UpdateCheck = func(uctx context.Context) (bool, error) {
			res, err := updater.Run(uctx, httpc, updater.Options{CurrentVersion: Version})
			if err != nil {
				return false, err
			}
			return res.UpgradeApplied, nil
		}
	}

	ctx, cancel := signalContext()
	defer cancel()

	logx.Info("daemon starting: agent_id=%d iface=%s hb=%s rev=%s auto_update=%v",
		cfg.AgentID, cfg.WGInterface, opts.HeartbeatInterval, opts.RevocationInterval, *autoUpdate)

	err = runner.Run(ctx, httpc, reader, opts)
	switch {
	case errors.Is(err, runner.ErrRevoked):
		// Exit code 2 signals revocation to the systemd unit (which sets
		// RestartPreventExitStatus=2).
		logx.Error("exiting: %v", err)
		os.Exit(2)
	case errors.Is(err, runner.ErrUpgraded):
		// Exit code 75 (sysexits EX_TEMPFAIL) — systemd's Restart=on-failure
		// reloads us onto the new on-disk binary.
		logx.Info("exiting %d for systemd reload onto new binary", ExitCodeUpdated)
		os.Exit(ExitCodeUpdated)
	case errors.Is(err, context.Canceled):
		logx.Info("daemon exited cleanly")
		return nil
	default:
		return err
	}
	return nil
}

// signalContext returns a context that is cancelled on SIGTERM or SIGINT.
func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		cancel()
	}()
	return ctx, cancel
}

// wgReader adapts wg.ReadTransfer to runner.TransferReader. Kept in the
// cmd layer so the runner package stays free of the wg dependency.
type wgReader struct{ iface string }

func (w *wgReader) Read() (int64, int64, error) {
	stats, err := wg.ReadTransfer(w.iface)
	if err != nil {
		return 0, 0, err
	}
	return stats.RXBytes, stats.TXBytes, nil
}
