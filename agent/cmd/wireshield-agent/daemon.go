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
	"github.com/siyamsarker/wireshield/agent/internal/wg"
)

// runDaemon is the long-running heartbeat + revocation loop, invoked by
// the systemd unit shipped in C4. Exit semantics:
//
//   0   — received SIGTERM/SIGINT; clean shutdown (systemd restart policy
//         does not re-fire because exit was expected)
//   1   — fatal config/startup error
//   2   — server confirmed the agent has been revoked (runner.ErrRevoked);
//         systemd unit is configured with Restart=no on this code so the
//         daemon stays down after revocation
func runDaemon(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var (
		heartbeatSec  = fs.Int("heartbeat", 30, "heartbeat interval seconds")
		revocationSec = fs.Int("revocation", 60, "revocation-check interval seconds")
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

	httpc, err := client.New(cfg.ServerURL, Version, cfg.TLSInsecure)
	if err != nil {
		return err
	}

	reader := &wgReader{iface: cfg.WGInterface}
	opts := runner.DefaultOptions(Version)
	opts.HeartbeatInterval = time.Duration(*heartbeatSec) * time.Second
	opts.RevocationInterval = time.Duration(*revocationSec) * time.Second

	ctx, cancel := signalContext()
	defer cancel()

	logx.Info("daemon starting: agent_id=%d iface=%s hb=%s rev=%s",
		cfg.AgentID, cfg.WGInterface, opts.HeartbeatInterval, opts.RevocationInterval)

	err = runner.Run(ctx, httpc, reader, opts)
	switch {
	case errors.Is(err, runner.ErrRevoked):
		// Exit code 2 signals revocation to the systemd unit (which sets
		// RestartPreventExitStatus=2).
		logx.Error("exiting: %v", err)
		os.Exit(2)
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
