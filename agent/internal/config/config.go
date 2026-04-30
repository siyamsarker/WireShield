// Package config owns the on-disk agent state: server URL, WG identity,
// enrollment output. Everything reads/writes through here so atomicity and
// file-mode invariants (0600) live in one place.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultDir          = "/etc/wireshield-agent"
	configFile          = "config.json"
	privateKeyFile      = "private.key"
	heartbeatSecretFile = "heartbeat.secret"
	configMode          = 0o600
	privateKeyMode      = 0o600
	directoryMode       = 0o700
	DefaultWGIface      = "wg-agent0"
	DefaultWGConfPath   = "/etc/wireguard/wg-agent0.conf"
)

// Config is the persisted agent identity after enrollment. It does NOT contain
// the WG private key or the heartbeat bearer token — both live in separate
// 0600 files for defence in depth. A misconfigured backup of config.json
// alone leaks neither the tunnel key nor the auth credential.
type Config struct {
	ServerURL       string   `json:"server_url"`
	AgentID         int64    `json:"agent_id"`
	AgentName       string   `json:"agent_name"`
	PublicKey       string   `json:"public_key"`
	WGIPv4          string   `json:"wg_ipv4"`
	AdvertisedCIDRs []string `json:"advertised_cidrs"`
	WGInterface     string   `json:"wg_interface"`
	WGConfPath      string   `json:"wg_conf_path"`
	TLSInsecure     bool     `json:"tls_insecure,omitempty"`
}

// Paths returns absolute paths for the files under Dir.
type Paths struct {
	Dir             string
	Config          string
	PrivateKey      string
	HeartbeatSecret string
}

func DefaultPaths() Paths {
	return PathsFor(DefaultDir)
}

func PathsFor(dir string) Paths {
	return Paths{
		Dir:             dir,
		Config:          filepath.Join(dir, configFile),
		PrivateKey:      filepath.Join(dir, privateKeyFile),
		HeartbeatSecret: filepath.Join(dir, heartbeatSecretFile),
	}
}

// Load reads the persisted agent config. Returns an error wrapping os.ErrNotExist
// if the file is missing so callers can distinguish "not enrolled yet" from
// "config corrupt".
func Load(p Paths) (*Config, error) {
	data, err := os.ReadFile(p.Config)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p.Config, err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Save writes the config atomically (tmp + rename) so a crash can never
// leave a truncated file that a subsequent Load would misparse.
func Save(p Paths, c *Config) error {
	if err := c.validate(); err != nil {
		return err
	}
	if err := ensureDir(p.Dir); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(p.Config, data, configMode)
}

// LoadPrivateKey returns the base64-encoded WG private key string.
func LoadPrivateKey(p Paths) (string, error) {
	data, err := os.ReadFile(p.PrivateKey)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// SavePrivateKey writes the key atomically at mode 0600.
func SavePrivateKey(p Paths, key string) error {
	if err := ensureDir(p.Dir); err != nil {
		return err
	}
	return writeFileAtomic(p.PrivateKey, []byte(strings.TrimSpace(key)+"\n"), privateKeyMode)
}

// LoadHeartbeatSecret returns the bearer token issued at enrollment.
// This lives in its own 0600 file separate from config.json so that an
// accidental backup of config.json alone cannot leak the auth credential.
func LoadHeartbeatSecret(p Paths) (string, error) {
	data, err := os.ReadFile(p.HeartbeatSecret)
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", errors.New("heartbeat.secret is empty")
	}
	return secret, nil
}

// SaveHeartbeatSecret writes the bearer token atomically at mode 0600.
func SaveHeartbeatSecret(p Paths, secret string) error {
	if err := ensureDir(p.Dir); err != nil {
		return err
	}
	return writeFileAtomic(p.HeartbeatSecret, []byte(strings.TrimSpace(secret)+"\n"), privateKeyMode)
}

// Exists reports whether the config, private key, and heartbeat secret are
// all present. Used by `status` and to guard against double-enrollment.
func Exists(p Paths) bool {
	for _, f := range []string{p.Config, p.PrivateKey, p.HeartbeatSecret} {
		if _, err := os.Stat(f); err != nil {
			return false
		}
	}
	return true
}

// Remove deletes the config, private key, and heartbeat secret. Used by
// `revoke`. Missing files are not an error — this is idempotent.
func Remove(p Paths) error {
	var firstErr error
	for _, f := range []string{p.Config, p.PrivateKey, p.HeartbeatSecret} {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *Config) validate() error {
	if c == nil {
		return errors.New("nil config")
	}
	if strings.TrimSpace(c.ServerURL) == "" {
		return errors.New("server_url is required")
	}
	u, err := url.Parse(c.ServerURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("server_url must be an http(s) URL: %q", c.ServerURL)
	}
	if c.AgentID <= 0 {
		return errors.New("agent_id must be > 0")
	}
	if strings.TrimSpace(c.PublicKey) == "" {
		return errors.New("public_key is required")
	}
	if strings.TrimSpace(c.WGIPv4) == "" {
		return errors.New("wg_ipv4 is required")
	}
	if strings.TrimSpace(c.WGInterface) == "" {
		c.WGInterface = DefaultWGIface
	}
	if strings.TrimSpace(c.WGConfPath) == "" {
		c.WGConfPath = DefaultWGConfPath
	}
	return nil
}

func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, directoryMode); err != nil {
		return err
	}
	// MkdirAll won't tighten mode on an existing permissive directory.
	return os.Chmod(dir, directoryMode)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	return os.Rename(tmpPath, path)
}
