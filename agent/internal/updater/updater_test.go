package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/siyamsarker/wireshield/agent/internal/client"
)

// fakeFetcher implements ManifestFetcher with deterministic outputs.
type fakeFetcher struct {
	manifest    *client.VersionResponse
	manifestErr error

	// downloaded payload returned for any request
	payload    []byte
	downloadErr error

	// lastDownloadURL is set after a download call so tests can assert
	// what URL the updater chose from the manifest.
	lastDownloadURL string
}

func (f *fakeFetcher) Version(ctx context.Context) (*client.VersionResponse, error) {
	if f.manifestErr != nil {
		return nil, f.manifestErr
	}
	return f.manifest, nil
}

func (f *fakeFetcher) DownloadBinary(ctx context.Context, path string) (string, error) {
	if f.downloadErr != nil {
		return "", f.downloadErr
	}
	f.lastDownloadURL = path
	tmp, err := os.CreateTemp("", "fake-dl-*")
	if err != nil {
		return "", err
	}
	if _, err := tmp.Write(f.payload); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	tmp.Close()
	return tmp.Name(), nil
}

func sha256Of(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// stagedBinary writes a fake "current" binary to a temp file and returns
// its path. Tests use this as Options.BinaryPath so the updater has a
// real file to atomically replace.
func stagedBinary(t *testing.T, content []byte) string {
	t.Helper()
	tmp, err := os.CreateTemp("", "wsagent-running-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write(content); err != nil {
		t.Fatal(err)
	}
	tmp.Chmod(0o755)
	tmp.Close()
	t.Cleanup(func() { os.Remove(tmp.Name()) })
	return tmp.Name()
}

func TestRunUpgrades(t *testing.T) {
	newBin := []byte("NEW-BINARY-BYTES")
	dest := stagedBinary(t, []byte("OLD-BINARY"))

	f := &fakeFetcher{
		manifest: &client.VersionResponse{
			CurrentVersion: "1.1.0",
			Arches: map[string]client.VersionArchEntry{
				"linux-amd64": {URL: "/api/agents/binary/linux-amd64", SHA256: sha256Of(newBin)},
			},
		},
		payload: newBin,
	}
	res, err := Run(context.Background(), f, Options{
		CurrentVersion: "1.0.0",
		BinaryPath:     dest,
		Arch:           "linux-amd64",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.UpgradeApplied {
		t.Fatal("expected UpgradeApplied=true")
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newBin) {
		t.Fatalf("binary not replaced; got %q", got)
	}
	if f.lastDownloadURL != "/api/agents/binary/linux-amd64" {
		t.Fatalf("unexpected download URL: %q", f.lastDownloadURL)
	}
}

func TestRunSkipsWhenAlreadyCurrent(t *testing.T) {
	dest := stagedBinary(t, []byte("OLD"))
	f := &fakeFetcher{
		manifest: &client.VersionResponse{
			CurrentVersion: "1.0.0",
			Arches: map[string]client.VersionArchEntry{
				"linux-amd64": {URL: "/api/agents/binary/linux-amd64"},
			},
		},
		payload: []byte("SHOULD-NOT-BE-USED"),
	}
	res, err := Run(context.Background(), f, Options{
		CurrentVersion: "1.0.0",
		BinaryPath:     dest,
		Arch:           "linux-amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.UpgradeApplied {
		t.Fatal("expected no upgrade when already current")
	}
	if res.Skipped == "" {
		t.Fatal("expected Skipped reason to be populated")
	}
	if got, _ := os.ReadFile(dest); string(got) != "OLD" {
		t.Fatalf("binary changed: %q", got)
	}
}

func TestRunSkipsWhenManifestUnknown(t *testing.T) {
	dest := stagedBinary(t, []byte("OLD"))
	f := &fakeFetcher{
		manifest: &client.VersionResponse{
			CurrentVersion: "unknown",
			Arches:         map[string]client.VersionArchEntry{},
		},
	}
	res, err := Run(context.Background(), f, Options{
		CurrentVersion: "1.0.0",
		BinaryPath:     dest,
		Arch:           "linux-amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.UpgradeApplied {
		t.Fatal("expected skip on unknown manifest")
	}
}

func TestRunRejectsChecksumMismatch(t *testing.T) {
	dest := stagedBinary(t, []byte("OLD"))
	f := &fakeFetcher{
		manifest: &client.VersionResponse{
			CurrentVersion: "1.1.0",
			Arches: map[string]client.VersionArchEntry{
				"linux-amd64": {URL: "/api/agents/binary/linux-amd64", SHA256: "deadbeef" + strings.Repeat("0", 56)},
			},
		},
		payload: []byte("HONEST-NEW-BYTES"),
	}
	_, err := Run(context.Background(), f, Options{
		CurrentVersion: "1.0.0",
		BinaryPath:     dest,
		Arch:           "linux-amd64",
	})
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("expected ErrChecksumMismatch, got %v", err)
	}
	// Critically: the on-disk binary must NOT have been replaced.
	if got, _ := os.ReadFile(dest); string(got) != "OLD" {
		t.Fatalf("binary was replaced despite checksum mismatch: %q", got)
	}
}

func TestRunRejectsMissingArch(t *testing.T) {
	dest := stagedBinary(t, []byte("OLD"))
	f := &fakeFetcher{
		manifest: &client.VersionResponse{
			CurrentVersion: "1.1.0",
			Arches:         map[string]client.VersionArchEntry{}, // empty
		},
	}
	_, err := Run(context.Background(), f, Options{
		CurrentVersion: "1.0.0",
		BinaryPath:     dest,
		Arch:           "linux-arm64",
	})
	if !errors.Is(err, ErrNoMatchingArch) {
		t.Fatalf("expected ErrNoMatchingArch, got %v", err)
	}
}

func TestRunForcesMinVersionUpgrade(t *testing.T) {
	// Server says current=2.0.0, min=1.5.0; we are on 1.0.0 → must upgrade
	// even though we'd normally consider 2.0.0 as "newer" (which we'd
	// upgrade to anyway). The key check: a min_version below current is
	// honoured even when the user might otherwise be cautious — the test
	// uses agent version exactly equal to current to check the gate.
	newBin := []byte("FORCE-UPGRADE-BYTES")
	dest := stagedBinary(t, []byte("OLD"))
	f := &fakeFetcher{
		manifest: &client.VersionResponse{
			CurrentVersion: "1.5.0",
			MinVersion:     "1.5.0",
			Arches: map[string]client.VersionArchEntry{
				"linux-amd64": {URL: "/api/agents/binary/linux-amd64", SHA256: sha256Of(newBin)},
			},
		},
		payload: newBin,
	}
	res, err := Run(context.Background(), f, Options{
		CurrentVersion: "1.0.0", // < min_version
		BinaryPath:     dest,
		Arch:           "linux-amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.UpgradeApplied {
		t.Fatal("expected forced upgrade")
	}
}

func TestParseSemver(t *testing.T) {
	cases := []struct {
		in   string
		want [3]int
		ok   bool
	}{
		{"1.2.3", [3]int{1, 2, 3}, true},
		{"v1.2.3", [3]int{1, 2, 3}, true},
		{"1.2", [3]int{1, 2, 0}, true},
		{"1", [3]int{1, 0, 0}, true},
		{"1.2.3-rc1", [3]int{1, 2, 3}, true},
		{"1.2.3+build5", [3]int{1, 2, 3}, true},
		{"dev", [3]int{}, false},
		{"unknown", [3]int{}, false},
		{"", [3]int{}, false},
		{"abc", [3]int{}, false},
	}
	for _, tc := range cases {
		got, ok := parseSemver(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("parseSemver(%q) = %v %v, want %v %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.0.0", "1.0.0", 0, true},
		{"1.0.0", "1.0.1", -1, true},
		{"1.1.0", "1.0.9", 1, true},
		{"2.0.0", "1.99.99", 1, true},
		{"dev", "1.0.0", 0, false},
		{"", "1.0.0", 0, false},
	}
	for _, tc := range cases {
		got, ok := compareSemver(tc.a, tc.b)
		if got != tc.want || ok != tc.ok {
			t.Errorf("compareSemver(%q,%q) = %d %v, want %d %v", tc.a, tc.b, got, ok, tc.want, tc.ok)
		}
	}
}

func TestAtomicReplacePreservesMode(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "new")
	dst := filepath.Join(dir, "running")
	if err := os.WriteFile(src, []byte("NEW"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := atomicReplace(src, dst); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "NEW" {
		t.Fatalf("not replaced: %q", got)
	}
	info, _ := os.Stat(dst)
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}
