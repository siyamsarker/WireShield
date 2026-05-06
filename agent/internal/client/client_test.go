package client

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewRejectsInvalidURL(t *testing.T) {
	for _, u := range []string{"", "vpn.example.com", "ftp://vpn"} {
		if _, err := New(u, "test", "", false); err == nil {
			t.Fatalf("New(%q) returned nil error", u)
		}
	}
}

func TestEnrollHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agents/enroll" || r.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "wireshield-agent/") {
			t.Errorf("missing UA header: %q", r.Header.Get("User-Agent"))
		}
		var req EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if req.Token != "abc" || req.PublicKey != "pk" {
			t.Errorf("unexpected body: %+v", req)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(EnrollResponse{
			Success: true, AgentID: 7, AgentName: "n", WGIPv4: "10.8.0.200",
			ServerPublicKey: "srv", ServerEndpoint: "vpn:51820",
			PresharedKey: "psk", AgentAllowedIPs: "10.8.0.0/24",
			AdvertisedCIDRs: []string{"10.0.0.0/24"},
			Config:          "[Interface]\n...",
		})
	}))
	defer srv.Close()

	c, err := New(srv.URL, "1.0.0", "", false)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Enroll(context.Background(), &EnrollRequest{Token: "abc", PublicKey: "pk"})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if resp.AgentID != 7 || resp.WGIPv4 != "10.8.0.200" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestEnroll401IsNonRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"Invalid or expired enrollment token"}`))
	}))
	defer srv.Close()

	c, _ := New(srv.URL, "t", "", false)
	_, err := c.Enroll(context.Background(), &EnrollRequest{Token: "x", PublicKey: "y"})
	if err == nil {
		t.Fatal("expected error on 401")
	}
	var he *HTTPError
	if !errors.As(err, &he) || he.StatusCode != 401 {
		t.Fatalf("expected HTTPError 401, got %v", err)
	}
	if Retryable(err) {
		t.Fatal("401 should not be retryable")
	}
}

func TestHeartbeat5xxIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c, _ := New(srv.URL, "t", "", false)
	_, err := c.Heartbeat(context.Background(), &HeartbeatRequest{})
	if err == nil {
		t.Fatal("expected error on 502")
	}
	if !Retryable(err) {
		t.Fatal("502 should be retryable")
	}
}

func TestHeartbeatSendsSignatureHeaders(t *testing.T) {
	const secret = "agent-secret-token"
	var capturedTs, capturedNonce, capturedSig string
	var capturedAuth string
	var capturedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		capturedTs = r.Header.Get("X-Agent-Ts")
		capturedNonce = r.Header.Get("X-Agent-Nonce")
		capturedSig = r.Header.Get("X-Agent-Sig")
		body, _ := io.ReadAll(r.Body)
		capturedBody = body
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"agent_id":1}`))
	}))
	defer srv.Close()

	c, _ := New(srv.URL, "t", secret, false)
	_, err := c.Heartbeat(context.Background(), &HeartbeatRequest{AgentVersion: "x"})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	if capturedAuth != "Bearer "+secret {
		t.Errorf("bearer header missing or wrong: %q", capturedAuth)
	}
	if capturedTs == "" || capturedNonce == "" || capturedSig == "" {
		t.Fatalf("missing signature headers: ts=%q nonce=%q sig=%q",
			capturedTs, capturedNonce, capturedSig)
	}
	if got := len(capturedNonce); got != 32 {
		t.Errorf("nonce should be 32-char hex; got %d (%q)", got, capturedNonce)
	}

	// Recompute the expected HMAC and verify byte-for-byte. This is the
	// canonical-form check the server runs, mirrored client-side as a
	// regression guard.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("POST"))
	mac.Write([]byte("\n"))
	mac.Write([]byte("/api/agents/heartbeat"))
	mac.Write([]byte("\n"))
	mac.Write([]byte(capturedTs))
	mac.Write([]byte("\n"))
	mac.Write([]byte(capturedNonce))
	mac.Write([]byte("\n"))
	mac.Write(capturedBody)
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(capturedSig)) {
		t.Errorf("signature mismatch:\n want %s\n got  %s", want, capturedSig)
	}
}

func TestRevocationCheckSendsSignatureHeaders(t *testing.T) {
	const secret = "agent-secret-token"
	var capturedSig string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSig = r.Header.Get("X-Agent-Sig")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revoked":false,"status":"enrolled"}`))
	}))
	defer srv.Close()

	c, _ := New(srv.URL, "t", secret, false)
	if _, err := c.RevocationCheck(context.Background()); err != nil {
		t.Fatalf("revoke check: %v", err)
	}
	if capturedSig == "" {
		t.Error("revocation check did not send X-Agent-Sig")
	}
}

func TestRevocationCheckDecodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revoked":true,"status":"revoked"}`))
	}))
	defer srv.Close()

	c, _ := New(srv.URL, "t", "", false)
	resp, err := c.RevocationCheck(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Revoked || resp.Status != "revoked" {
		t.Fatalf("unexpected: %+v", resp)
	}
}
