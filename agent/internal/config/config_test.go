package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := PathsFor(dir)

	in := &Config{
		ServerURL:       "https://vpn.example.com",
		AgentID:         42,
		AgentName:       "branch-01",
		PublicKey:       "abc123=",
		WGIPv4:          "10.8.0.200",
		AdvertisedCIDRs: []string{"10.50.0.0/24"},
		WGInterface:     DefaultWGIface,
		WGConfPath:      DefaultWGConfPath,
	}
	if err := Save(p, in); err != nil {
		t.Fatalf("save: %v", err)
	}

	info, err := os.Stat(p.Config)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("config mode = %o, want 0600", mode)
	}

	out, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if out.AgentID != in.AgentID || out.ServerURL != in.ServerURL || out.WGIPv4 != in.WGIPv4 {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", out, in)
	}
}

func TestSavePrivateKeyAtomicAndMode(t *testing.T) {
	dir := t.TempDir()
	p := PathsFor(dir)
	if err := SavePrivateKey(p, "THIS_IS_A_KEY"); err != nil {
		t.Fatalf("save private key: %v", err)
	}
	info, err := os.Stat(p.PrivateKey)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("private key mode = %o, want 0600", mode)
	}
	got, err := LoadPrivateKey(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got != "THIS_IS_A_KEY" {
		t.Fatalf("key mismatch: got %q", got)
	}
}

func TestValidateRejectsBadURL(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"empty", ""},
		{"no scheme", "vpn.example.com"},
		{"bad scheme", "ftp://vpn.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{
				ServerURL: tc.url,
				AgentID:   1,
				PublicKey: "pk",
				WGIPv4:    "10.8.0.200",
			}
			if err := c.validate(); err == nil {
				t.Fatalf("expected validate() to reject %q", tc.url)
			}
		})
	}
}

func TestExistsReturnsTrueOnlyWhenBothPresent(t *testing.T) {
	dir := t.TempDir()
	p := PathsFor(dir)
	if Exists(p) {
		t.Fatal("Exists() true on empty dir")
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if Exists(p) {
		t.Fatal("Exists() true when private key is missing")
	}
	if err := os.WriteFile(filepath.Join(dir, "private.key"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !Exists(p) {
		t.Fatal("Exists() false when both files present")
	}
}

func TestRemoveIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	p := PathsFor(dir)
	// First remove on empty dir is a no-op.
	if err := Remove(p); err != nil {
		t.Fatalf("remove on empty: %v", err)
	}
	// After saving, remove + remove again.
	_ = SavePrivateKey(p, "k")
	if err := Save(p, &Config{
		ServerURL: "https://x", AgentID: 1, PublicKey: "p", WGIPv4: "10.8.0.200",
	}); err != nil {
		t.Fatal(err)
	}
	if err := Remove(p); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := Remove(p); err != nil {
		t.Fatalf("remove (2nd): %v", err)
	}
}
