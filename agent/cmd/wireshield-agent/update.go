package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/siyamsarker/wireshield/agent/internal/client"
	"github.com/siyamsarker/wireshield/agent/internal/config"
	"github.com/siyamsarker/wireshield/agent/internal/logx"
	"github.com/siyamsarker/wireshield/agent/internal/updater"
)

// ExitCodeUpdated — daemon used this to tell systemd "binary on disk is
// new, please bounce me so the new image runs". Matches sysexits(3)
// EX_TEMPFAIL (75): "system temporarily unable to perform requested
// service" — restart-friendly without flagging it as an actual failure.
// The systemd unit (C4 of Phase 2) has Restart=on-failure which fires
// for any non-zero exit, so 75 cleanly triggers the bounce. Code 2
// remains reserved for runner.ErrRevoked (RestartPreventExitStatus=2).
const ExitCodeUpdated = 75

// runUpdate executes a single check-and-replace cycle and exits.
// Used by operators for manual upgrades and by `run` daemon's
// auto-update loop when --auto-update is set.
func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "check only — never replace the on-disk binary")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: wireshield-agent update [flags]\n\n")
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

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if *dryRun {
		manifest, err := httpc.Version(ctx)
		if err != nil {
			return fmt.Errorf("fetch version manifest: %w", err)
		}
		logx.Info("update --dry-run: server reports current=%q min=%q (running %q)",
			manifest.CurrentVersion, manifest.MinVersion, Version)
		fmt.Println("server_version =", manifest.CurrentVersion)
		fmt.Println("min_version    =", manifest.MinVersion)
		fmt.Println("running        =", Version)
		return nil
	}

	res, err := updater.Run(ctx, httpc, updater.Options{
		CurrentVersion: Version,
		// BinaryPath defaults to os.Executable() inside updater.Run.
	})
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	if !res.UpgradeApplied {
		logx.Info("update: no action — %s", res.Skipped)
		return nil
	}
	logx.Info("update: replaced %s — exiting %d so systemd reloads with the new binary",
		res.BinaryReplaced, ExitCodeUpdated)
	os.Exit(ExitCodeUpdated)
	return errors.New("unreachable")
}
