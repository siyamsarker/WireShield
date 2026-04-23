package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewRejectsInvalidURL(t *testing.T) {
	for _, u := range []string{"", "vpn.example.com", "ftp://vpn"} {
		if _, err := New(u, "test", false); err == nil {
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

	c, err := New(srv.URL, "1.0.0", false)
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

	c, _ := New(srv.URL, "t", false)
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

	c, _ := New(srv.URL, "t", false)
	err := c.Heartbeat(context.Background(), &HeartbeatRequest{})
	if err == nil {
		t.Fatal("expected error on 502")
	}
	if !Retryable(err) {
		t.Fatal("502 should be retryable")
	}
}

func TestRevocationCheckDecodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revoked":true,"status":"revoked"}`))
	}))
	defer srv.Close()

	c, _ := New(srv.URL, "t", false)
	resp, err := c.RevocationCheck(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Revoked || resp.Status != "revoked" {
		t.Fatalf("unexpected: %+v", resp)
	}
}
