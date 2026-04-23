// Package runner is the agent's main heartbeat + revocation loop. It is
// split out of cmd/wireshield-agent so the state machine can be unit-tested
// with fake clients and stats readers without involving systemd or wg.
package runner

import (
	"context"
	"errors"
	"math/rand"
	"time"

	"github.com/siyamsarker/wireshield/agent/internal/client"
	"github.com/siyamsarker/wireshield/agent/internal/logx"
)

// Options configures Run.
//
// Heartbeat cadence (HeartbeatInterval) and revocation-check cadence
// (RevocationInterval) are independent so a larger HeartbeatInterval can be
// paired with a more responsive RevocationInterval if needed. In practice we
// piggy-back revocation checks on the heartbeat tick.
type Options struct {
	HeartbeatInterval  time.Duration
	RevocationInterval time.Duration
	MaxBackoff         time.Duration // clamp for network-error retry backoff
	AgentVersion       string
}

// DefaultOptions returns the production cadence: 30s heartbeat, 60s
// revocation poll, 5-minute backoff cap.
func DefaultOptions(version string) Options {
	return Options{
		HeartbeatInterval:  30 * time.Second,
		RevocationInterval: 60 * time.Second,
		MaxBackoff:         5 * time.Minute,
		AgentVersion:       version,
	}
}

// TransferReader abstracts away `wg show <iface> transfer` so tests can
// inject deterministic values.
type TransferReader interface {
	Read() (rxBytes, txBytes int64, err error)
}

// HeartbeatClient is the subset of *client.Client that runner needs. Keeps
// the interface small so tests can stub it.
type HeartbeatClient interface {
	Heartbeat(ctx context.Context, req *client.HeartbeatRequest) error
	RevocationCheck(ctx context.Context) (*client.RevocationResponse, error)
}

// ErrRevoked is returned by Run when the server confirms this agent has
// been revoked. The binary should exit non-zero on this condition so
// systemd records the failure and the operator is prompted to run
// `wireshield-agent revoke`.
var ErrRevoked = errors.New("agent revoked by server")

// Run drives the heartbeat loop until ctx is cancelled or ErrRevoked
// fires. The function is blocking; the caller (cmd/main) handles signal
// plumbing.
func Run(ctx context.Context, c HeartbeatClient, r TransferReader, opts Options) error {
	if opts.HeartbeatInterval <= 0 {
		opts.HeartbeatInterval = 30 * time.Second
	}
	if opts.RevocationInterval <= 0 {
		opts.RevocationInterval = 60 * time.Second
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = 5 * time.Minute
	}

	hbTimer := time.NewTimer(0) // fire immediately on startup
	defer hbTimer.Stop()
	revTimer := time.NewTimer(opts.RevocationInterval)
	defer revTimer.Stop()

	var consecutiveHBFailures int

	for {
		select {
		case <-ctx.Done():
			logx.Info("runner: context cancelled, exiting")
			return ctx.Err()

		case <-hbTimer.C:
			if err := sendHeartbeat(ctx, c, r, opts.AgentVersion); err != nil {
				consecutiveHBFailures++
				delay := backoff(consecutiveHBFailures, opts.HeartbeatInterval, opts.MaxBackoff)
				if client.Retryable(err) {
					logx.Warn("heartbeat failed (attempt %d, retry in %s): %v",
						consecutiveHBFailures, delay, err)
				} else {
					// 4xx is not retryable — but we keep the loop running
					// since an operator may be mid-revoke. Back off to the
					// normal cadence so we don't spam.
					logx.Error("heartbeat rejected (not retryable): %v", err)
					delay = opts.HeartbeatInterval
				}
				hbTimer.Reset(delay)
			} else {
				consecutiveHBFailures = 0
				hbTimer.Reset(opts.HeartbeatInterval)
			}

		case <-revTimer.C:
			revoked, err := checkRevocation(ctx, c)
			if err != nil {
				// Revocation-check failures are non-fatal — the heartbeat
				// loop above carries the liveness signal.
				logx.Warn("revocation-check failed: %v", err)
			} else if revoked {
				logx.Error("server reports agent revoked; exiting")
				return ErrRevoked
			}
			revTimer.Reset(opts.RevocationInterval)
		}
	}
}

func sendHeartbeat(ctx context.Context, c HeartbeatClient, r TransferReader, version string) error {
	req := &client.HeartbeatRequest{AgentVersion: version}
	if r != nil {
		rx, tx, err := r.Read()
		if err != nil {
			logx.Warn("stats read failed (will send heartbeat without counters): %v", err)
		} else {
			req.RXBytes = rx
			req.TXBytes = tx
		}
	}
	hbCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.Heartbeat(hbCtx, req)
}

func checkRevocation(ctx context.Context, c HeartbeatClient) (bool, error) {
	rcCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := c.RevocationCheck(rcCtx)
	if err != nil {
		return false, err
	}
	return resp.Revoked, nil
}

// backoff returns a jittered delay: base * 2^(attempt-1), clamped to max,
// plus a random 0–10% jitter to prevent a cohort of agents from
// self-synchronising on recovery.
func backoff(attempt int, base, max time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 16 { // 2^16 * base is well beyond max for any reasonable base
		shift = 16
	}
	d := base << shift
	if d <= 0 || d > max {
		d = max
	}
	// Jitter: up to +10%.
	jitter := time.Duration(rand.Int63n(int64(d) / 10))
	return d + jitter
}
