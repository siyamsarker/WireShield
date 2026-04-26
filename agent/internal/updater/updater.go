// Package updater implements the agent's self-upgrade flow:
//   1. Pull the version manifest from /api/agents/version.
//   2. Decide whether the published version is newer than ours
//      (with a force-upgrade gate via min_version).
//   3. Download the per-arch binary, verify its sha256 against the
//      manifest, and atomically replace the running binary on disk.
//
// The package is deliberately HTTP-client-agnostic: tests inject fakes
// for the manifest fetch and the binary download. Filesystem operations
// are real — they're easier to verify than to mock and the cost is
// negligible (everything happens in t.TempDir()).
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/siyamsarker/wireshield/agent/internal/client"
	"github.com/siyamsarker/wireshield/agent/internal/logx"
)

// ManifestFetcher is the only thing updater needs from the HTTP layer
// beyond download — keeping it small lets tests stub it without
// reimplementing the full client surface.
type ManifestFetcher interface {
	Version(ctx context.Context) (*client.VersionResponse, error)
	DownloadBinary(ctx context.Context, path string) (string, error)
}

// Options drive a single update attempt.
type Options struct {
	CurrentVersion string // version string the running binary was built with
	BinaryPath     string // absolute path to /usr/local/bin/wireshield-agent
	Arch           string // "linux-amd64" or "linux-arm64"; auto-detected if empty
}

// Result describes what the updater decided to do this run.
type Result struct {
	Checked         bool   // true if we successfully fetched a manifest
	PublishedVer    string // current_version reported by the manifest
	UpgradeApplied  bool   // true when a new binary was written to disk
	BinaryReplaced  string // absolute path of the binary we replaced (when UpgradeApplied)
	Skipped         string // reason if we did nothing — e.g. "already current" or "manifest unknown"
}

// Errors that callers might want to distinguish.
var (
	// ErrNoMatchingArch — the manifest doesn't list our architecture.
	// Could be a server-side typo or a brand-new arch not yet uploaded.
	ErrNoMatchingArch = errors.New("manifest does not list our architecture")
	// ErrChecksumMismatch — downloaded bytes did not match manifest sha256.
	// We never replace the binary in this case.
	ErrChecksumMismatch = errors.New("downloaded binary failed sha256 verification")
)

// DetectArch returns the GOOS-GOARCH string we use as the manifest key.
// Matches the layout written by `make -C agent dist`.
func DetectArch() string {
	return runtime.GOOS + "-" + runtime.GOARCH
}

// Run performs the check-download-verify-replace sequence end-to-end.
// Errors at any step are returned without touching the on-disk binary.
func Run(ctx context.Context, c ManifestFetcher, opts Options) (Result, error) {
	if opts.Arch == "" {
		opts.Arch = DetectArch()
	}
	if opts.BinaryPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return Result{}, fmt.Errorf("resolve binary path: %w", err)
		}
		opts.BinaryPath = exe
	}

	manifest, err := c.Version(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("fetch version manifest: %w", err)
	}
	res := Result{Checked: true, PublishedVer: manifest.CurrentVersion}

	if manifest.CurrentVersion == "" || manifest.CurrentVersion == "unknown" || manifest.CurrentVersion == "dev" {
		// Server didn't publish a real version; nothing to compare against.
		res.Skipped = "manifest reports unknown version"
		logx.Debug("updater: %s", res.Skipped)
		return res, nil
	}

	// Force-upgrade gate: if the manifest declares a min_version newer
	// than ours, we MUST upgrade (unless we're already at min). This is
	// the operator's escape hatch for shipping security fixes.
	mustUpgrade := false
	if manifest.MinVersion != "" && opts.CurrentVersion != "" {
		if cmp, ok := compareSemver(opts.CurrentVersion, manifest.MinVersion); ok && cmp < 0 {
			mustUpgrade = true
			logx.Info("updater: forcing upgrade (current=%s < min=%s)", opts.CurrentVersion, manifest.MinVersion)
		}
	}

	if !mustUpgrade && opts.CurrentVersion != "" {
		if cmp, ok := compareSemver(opts.CurrentVersion, manifest.CurrentVersion); ok && cmp >= 0 {
			res.Skipped = fmt.Sprintf("already at %s (manifest=%s)", opts.CurrentVersion, manifest.CurrentVersion)
			logx.Debug("updater: %s", res.Skipped)
			return res, nil
		}
	}

	entry, ok := manifest.Arches[opts.Arch]
	if !ok {
		return res, fmt.Errorf("%w: %s", ErrNoMatchingArch, opts.Arch)
	}
	if strings.TrimSpace(entry.URL) == "" {
		return res, fmt.Errorf("manifest entry for %s has empty URL", opts.Arch)
	}

	logx.Info("updater: pulling new binary for %s from %s", opts.Arch, entry.URL)
	tmpPath, err := c.DownloadBinary(ctx, entry.URL)
	if err != nil {
		return res, fmt.Errorf("download: %w", err)
	}
	defer os.Remove(tmpPath)

	if entry.SHA256 != "" {
		got, err := sha256OfFile(tmpPath)
		if err != nil {
			return res, fmt.Errorf("hash downloaded binary: %w", err)
		}
		if !strings.EqualFold(got, entry.SHA256) {
			return res, fmt.Errorf("%w: got %s, expected %s", ErrChecksumMismatch, got, entry.SHA256)
		}
		logx.Debug("updater: checksum verified (%s)", got[:12]+"…")
	} else {
		logx.Warn("updater: manifest has no sha256 — proceeding without integrity check")
	}

	if err := atomicReplace(tmpPath, opts.BinaryPath); err != nil {
		return res, fmt.Errorf("replace %s: %w", opts.BinaryPath, err)
	}

	res.UpgradeApplied = true
	res.BinaryReplaced = opts.BinaryPath
	logx.Info("updater: upgraded %s → %s", opts.CurrentVersion, manifest.CurrentVersion)
	return res, nil
}

// compareSemver returns -1/0/+1 if a is older/equal/newer than b. The
// second return value is false when either side fails to parse — callers
// fall back to "no upgrade" in that case so a malformed version string
// never triggers a surprise replacement.
func compareSemver(a, b string) (int, bool) {
	pa, ok := parseSemver(a)
	if !ok {
		return 0, false
	}
	pb, ok := parseSemver(b)
	if !ok {
		return 0, false
	}
	for i := 0; i < 3; i++ {
		if pa[i] < pb[i] {
			return -1, true
		}
		if pa[i] > pb[i] {
			return 1, true
		}
	}
	return 0, true
}

// parseSemver accepts "1.2.3", "1.2", or "1" — anything beyond those
// three numeric segments (pre-release tags, build metadata, etc.) is
// stripped at the first non-numeric character. Conservative on purpose:
// the agent never needs to compare prerelease ordering.
func parseSemver(v string) ([3]int, bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if v == "" || v == "dev" || v == "unknown" {
		return [3]int{}, false
	}
	// Strip any "-suffix" or "+build" tail.
	for _, sep := range []string{"-", "+"} {
		if i := strings.Index(v, sep); i >= 0 {
			v = v[:i]
		}
	}
	parts := strings.Split(v, ".")
	var out [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

func sha256OfFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// atomicReplace renames tmp into dest after copying mode + ownership.
// On Linux you cannot rename across filesystems, so we fall back to a
// copy if rename fails with EXDEV. The destination is replaced via
// rename so an in-flight read on the running binary is unaffected
// (Linux unlinks-on-close).
func atomicReplace(srcTmp, dest string) error {
	srcInfo, err := os.Stat(srcTmp)
	if err != nil {
		return err
	}
	destDir := filepath.Dir(dest)
	stage, err := os.CreateTemp(destDir, ".wireshield-agent-stage-*")
	if err != nil {
		// Cross-FS or no permission — rare, but in that case we have to
		// skip the same-FS staging dance and rename directly.
		stage = nil
	}
	if stage != nil {
		stagePath := stage.Name()
		stage.Close()
		// Copy bytes into the staged file so rename(2) is on the same FS.
		if err := copyFile(srcTmp, stagePath); err != nil {
			os.Remove(stagePath)
			return err
		}
		if err := os.Chmod(stagePath, srcInfo.Mode().Perm()); err != nil {
			os.Remove(stagePath)
			return err
		}
		if err := os.Rename(stagePath, dest); err != nil {
			os.Remove(stagePath)
			return err
		}
		return nil
	}
	// Fallback: try a direct rename. May fail across filesystems; in that
	// case the caller has to retry after copying — but we're already in
	// /tmp so this branch is mostly theoretical.
	if err := os.Rename(srcTmp, dest); err != nil {
		return err
	}
	return os.Chmod(dest, srcInfo.Mode().Perm())
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
