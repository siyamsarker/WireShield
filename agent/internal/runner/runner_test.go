package runner

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/siyamsarker/wireshield/agent/internal/client"
)

// fakeClient tracks every heartbeat + revocation call so tests can assert
// ordering and arguments.
type fakeClient struct {
	mu              sync.Mutex
	heartbeats      []client.HeartbeatRequest
	heartbeatErr    error
	revokeAfter     int32 // once this many rev checks fire, return revoked
	revocationCalls int32
	revocationErr   error
}

func (f *fakeClient) Heartbeat(ctx context.Context, req *client.HeartbeatRequest) (*client.HeartbeatResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heartbeats = append(f.heartbeats, *req)
	if f.heartbeatErr != nil {
		return nil, f.heartbeatErr
	}
	return &client.HeartbeatResponse{Success: true}, nil
}

func (f *fakeClient) RevocationCheck(ctx context.Context) (*client.RevocationResponse, error) {
	n := atomic.AddInt32(&f.revocationCalls, 1)
	if f.revocationErr != nil {
		return nil, f.revocationErr
	}
	if f.revokeAfter > 0 && n >= f.revokeAfter {
		return &client.RevocationResponse{Revoked: true, Status: "revoked"}, nil
	}
	return &client.RevocationResponse{Revoked: false, Status: "enrolled"}, nil
}

type fakeReader struct{ rx, tx int64 }

func (f *fakeReader) Read() (int64, int64, error) { return f.rx, f.tx, nil }

func TestRunSendsHeartbeatWithStats(t *testing.T) {
	c := &fakeClient{}
	r := &fakeReader{rx: 100, tx: 200}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	opts := Options{
		HeartbeatInterval:  40 * time.Millisecond,
		RevocationInterval: 300 * time.Millisecond, // skip during test window
		MaxBackoff:         time.Second,
		AgentVersion:       "test-1.0",
	}
	err := Run(ctx, c, r, opts)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.heartbeats) < 2 {
		t.Fatalf("expected at least 2 heartbeats, got %d", len(c.heartbeats))
	}
	if c.heartbeats[0].AgentVersion != "test-1.0" {
		t.Errorf("version not forwarded: %q", c.heartbeats[0].AgentVersion)
	}
	if c.heartbeats[0].RXBytes != 100 || c.heartbeats[0].TXBytes != 200 {
		t.Errorf("stats not forwarded: %+v", c.heartbeats[0])
	}
}

func TestRunReturnsErrRevokedWhenRevoked(t *testing.T) {
	c := &fakeClient{revokeAfter: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	opts := Options{
		HeartbeatInterval:  300 * time.Millisecond,
		RevocationInterval: 20 * time.Millisecond,
		MaxBackoff:         time.Second,
	}
	err := Run(ctx, c, nil, opts)
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("expected ErrRevoked, got %v", err)
	}
}

func TestRunContinuesOnHeartbeatNetworkError(t *testing.T) {
	// Simulate a network blip. Runner should back off but keep going.
	c := &fakeClient{heartbeatErr: errors.New("dial tcp: connection refused")}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	opts := Options{
		HeartbeatInterval:  20 * time.Millisecond,
		RevocationInterval: time.Hour,
		MaxBackoff:         50 * time.Millisecond,
	}
	err := Run(ctx, c, nil, opts)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.heartbeats) < 2 {
		t.Fatalf("expected runner to keep retrying, got %d heartbeats", len(c.heartbeats))
	}
}

func TestRunToleratesNonRetryableHeartbeatError(t *testing.T) {
	// 4xx from the server should not kill the loop — operator might be
	// mid-revoke; runner stays up so the revocation-check path can confirm.
	httpErr := &client.HTTPError{StatusCode: http.StatusForbidden, Body: "nope", Endpoint: "POST /api/agents/heartbeat"}
	c := &fakeClient{heartbeatErr: httpErr}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	opts := Options{
		HeartbeatInterval:  30 * time.Millisecond,
		RevocationInterval: time.Hour,
		MaxBackoff:         time.Second,
	}
	err := Run(ctx, c, nil, opts)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected loop to run to deadline, got %v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.heartbeats) < 2 {
		t.Fatalf("expected multiple heartbeat attempts despite 403, got %d", len(c.heartbeats))
	}
}

func TestRunReturnsErrUpgradedWhenUpdateApplies(t *testing.T) {
	c := &fakeClient{}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	calls := 0
	opts := Options{
		HeartbeatInterval:  300 * time.Millisecond,
		RevocationInterval: 300 * time.Millisecond,
		AutoUpdateInterval: 30 * time.Millisecond,
		UpdateCheck: func(ctx context.Context) (bool, error) {
			calls++
			return calls >= 1, nil // upgrade on first check
		},
	}
	err := Run(ctx, c, nil, opts)
	if !errors.Is(err, ErrUpgraded) {
		t.Fatalf("expected ErrUpgraded, got %v", err)
	}
	if calls < 1 {
		t.Fatal("expected at least one update check call")
	}
}

func TestRunIgnoresUpdateCheckErrors(t *testing.T) {
	// Network error in the update path must NOT take the daemon down.
	c := &fakeClient{}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	calls := 0
	opts := Options{
		HeartbeatInterval:  time.Hour,
		RevocationInterval: time.Hour,
		AutoUpdateInterval: 25 * time.Millisecond,
		UpdateCheck: func(ctx context.Context) (bool, error) {
			calls++
			return false, errors.New("boom")
		},
	}
	err := Run(ctx, c, nil, opts)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	if calls < 2 {
		t.Fatalf("expected ≥ 2 update attempts despite errors, got %d", calls)
	}
}

func TestBackoffJitteredAndClamped(t *testing.T) {
	base := 10 * time.Millisecond
	max := 100 * time.Millisecond
	for _, a := range []int{1, 2, 10, 100} {
		d := backoff(a, base, max)
		if d < base || d > max+max/10 {
			t.Errorf("backoff(%d)=%s out of [%s, %s+10%%]", a, d, base, max)
		}
	}
}
