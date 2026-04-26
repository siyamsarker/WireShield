// Package client is the HTTP client that talks to the WireShield VPN server's
// /api/agents/* endpoints. It handles TLS, JSON encoding, timeouts, and
// distinguishing retryable (network/5xx) from fatal (4xx) errors so the
// daemon's backoff logic in package runner stays simple.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	userAgentPrefix = "wireshield-agent/"
	defaultTimeout  = 15 * time.Second
)

// Client is safe for concurrent use; all state is in the embedded *http.Client.
type Client struct {
	serverURL string
	version   string
	http      *http.Client
}

// New builds a client against baseURL. If tlsInsecure is true the client
// skips TLS verification — this is only for lab/bootstrap use and is opt-in
// via the agent config.
func New(baseURL, version string, tlsInsecure bool) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid server URL: %q", baseURL)
	}
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: tlsInsecure},
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   5,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: defaultTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &Client{
		serverURL: u.String(),
		version:   version,
		http: &http.Client{
			Transport: tr,
			Timeout:   defaultTimeout,
		},
	}, nil
}

// HTTPError is returned for non-2xx responses; callers can inspect StatusCode
// to decide whether to retry (5xx/network) or give up (4xx).
type HTTPError struct {
	StatusCode int
	Body       string
	Endpoint   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s: HTTP %d: %s", e.Endpoint, e.StatusCode, e.Body)
}

// Retryable reports whether the error is worth backing off and retrying.
// Network errors, context deadline, and 5xx are retryable; 4xx is not.
func Retryable(err error) bool {
	if err == nil {
		return false
	}
	var he *HTTPError
	if errors.As(err, &he) {
		return he.StatusCode >= 500
	}
	// Network/timeout errors surface as generic net errors; treat all
	// non-HTTPError failures as retryable.
	return true
}

// EnrollRequest mirrors the server's AgentEnrollRequest Pydantic model.
type EnrollRequest struct {
	Token           string   `json:"token"`
	PublicKey       string   `json:"public_key"`
	Hostname        string   `json:"hostname,omitempty"`
	LANInterface    string   `json:"lan_interface,omitempty"`
	AdvertisedCIDRs []string `json:"advertised_cidrs,omitempty"`
	AgentVersion    string   `json:"agent_version,omitempty"`
}

// EnrollResponse is the server's reply: WG peer config the agent should
// apply locally to bring up its tunnel. Field tags mirror the JSON keys
// returned by console-server routers/agents.py /api/agents/enroll.
type EnrollResponse struct {
	Success         bool     `json:"success"`
	AgentID         int64    `json:"agent_id"`
	AgentName       string   `json:"name"`
	WGIPv4          string   `json:"wg_ipv4"`
	PresharedKey    string   `json:"preshared_key"`
	ServerPublicKey string   `json:"server_public_key"`
	ServerEndpoint  string   `json:"endpoint"`
	AgentAllowedIPs string   `json:"agent_allowed_ips"`
	AdvertisedCIDRs []string `json:"advertised_cidrs"`
	Config          string   `json:"config"`
}

// HeartbeatRequest mirrors AgentHeartbeatRequest on the server.
type HeartbeatRequest struct {
	AgentVersion string `json:"agent_version,omitempty"`
	RXBytes      int64  `json:"rx_bytes,omitempty"`
	TXBytes      int64  `json:"tx_bytes,omitempty"`
}

// RevocationResponse matches /api/agents/revocation-check.
type RevocationResponse struct {
	Revoked bool   `json:"revoked"`
	Status  string `json:"status"`
}

// VersionArchEntry is one element of VersionResponse.Arches; it tells the
// agent where to download the binary for a given arch and the expected
// SHA-256 of the bytes that come back.
type VersionArchEntry struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256,omitempty"`
}

// VersionResponse mirrors /api/agents/version. CurrentVersion may be the
// literal "unknown" string when the server is in synthesized-fallback
// mode; the updater package treats that as "do nothing".
type VersionResponse struct {
	CurrentVersion string                      `json:"current_version"`
	ReleasedAt     string                      `json:"released_at,omitempty"`
	MinVersion     string                      `json:"min_version,omitempty"`
	Arches         map[string]VersionArchEntry `json:"arches"`
}

// Enroll posts the single-use token + agent public key and returns the WG
// peer config. Called once per agent lifetime.
func (c *Client) Enroll(ctx context.Context, req *EnrollRequest) (*EnrollResponse, error) {
	var resp EnrollResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/agents/enroll", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Heartbeat is called on a ticker by the daemon. Authentication is implicit
// via the WG tunnel source IP; there is no bearer token.
func (c *Client) Heartbeat(ctx context.Context, req *HeartbeatRequest) error {
	return c.doJSON(ctx, http.MethodPost, "/api/agents/heartbeat", req, nil)
}

// RevocationCheck polls whether the agent has been revoked. On a true
// response the daemon should stop its WG tunnel and exit.
func (c *Client) RevocationCheck(ctx context.Context) (*RevocationResponse, error) {
	var resp RevocationResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/agents/revocation-check", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Version returns the published agent version manifest. Used by the
// updater package to decide whether a self-upgrade is warranted.
func (c *Client) Version(ctx context.Context) (*VersionResponse, error) {
	var resp VersionResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/agents/version", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DownloadBinary streams a path on the same baseURL into a temp file and
// returns the path. Cleanup is the caller's responsibility. Used by the
// updater to fetch the new binary; we keep this on Client so it shares
// the same transport/timeout/TLS config as the JSON endpoints.
func (c *Client) DownloadBinary(ctx context.Context, path string) (tmpPath string, err error) {
	full := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		full = c.serverURL + path
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("User-Agent", userAgentPrefix+c.version)
	httpReq.Header.Set("Accept", "application/octet-stream")

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 4*1024))
		return "", &HTTPError{
			StatusCode: httpResp.StatusCode,
			Body:       strings.TrimSpace(string(body)),
			Endpoint:   "GET " + path,
		}
	}

	tmp, err := os.CreateTemp("", "wireshield-agent-update-*")
	if err != nil {
		return "", err
	}
	tmpPath = tmp.Name()
	if _, err := io.Copy(tmp, httpResp.Body); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	return tmpPath, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("marshal %s body: %w", path, err)
		}
		body = bytes.NewReader(b)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, c.serverURL+path, body)
	if err != nil {
		return err
	}
	httpReq.Header.Set("User-Agent", userAgentPrefix+c.version)
	httpReq.Header.Set("Accept", "application/json")
	if in != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()

	rawBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 64*1024))
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return &HTTPError{
			StatusCode: httpResp.StatusCode,
			Body:       strings.TrimSpace(string(rawBody)),
			Endpoint:   method + " " + path,
		}
	}
	if out != nil && len(rawBody) > 0 {
		if err := json.Unmarshal(rawBody, out); err != nil {
			return fmt.Errorf("decode %s response: %w", path, err)
		}
	}
	return nil
}

// ServerURL returns the normalized base URL (used by callers that need to
// construct related URLs, e.g. binary download paths).
func (c *Client) ServerURL() string { return c.serverURL }
