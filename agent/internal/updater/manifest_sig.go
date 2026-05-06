// Manifest signing — Ed25519 over a canonical form of the version manifest.
//
// Threat: a compromised /api/agents/version endpoint (or anyone who can
// MITM that response — combined with the agent's lab-mode tls_insecure,
// or simply if the server runs on plaintext HTTP) can supply attacker
// binary URL + attacker SHA-256, and the agent will faithfully replace
// /usr/local/bin/wireshield-agent. SHA-256 alone does not gate this:
// the same response provides both URL and hash.
//
// Defense: the operator generates an Ed25519 release keypair offline,
// embeds the public key into the agent at build time via -ldflags, and
// signs each released manifest with the private half. Only manifests
// signed by the embedded key are accepted.
//
// Backwards compatibility: agents built without an embedded key skip
// signature verification entirely — old binaries in the field continue
// to work. This is intentionally permissive so a single-binary rollout
// path works (rebuild + republish + redeploy in any order).
package updater

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/siyamsarker/wireshield/agent/internal/client"
)

// CanonicalManifestPayload returns the byte sequence that the operator's
// signing tool MUST sign and the agent MUST verify. It is deliberately
// human-readable (debuggable) and order-independent for the arches map.
//
// Format (LF-separated, trailing LF):
//
//	wireshield-manifest/v1
//	current_version=<v>
//	min_version=<v|empty>
//	released_at=<v|empty>
//	arch=<name>;sha256=<hex>;url=<url>
//	... (arches sorted by name)
//
// The arch URL is included so an attacker cannot retarget the download
// host while keeping the rest of the manifest signed. The trailing LF
// ensures the payload always ends in a known byte (defends against some
// truncation bugs in tooling).
func CanonicalManifestPayload(m *client.VersionResponse) []byte {
	var b strings.Builder
	b.WriteString("wireshield-manifest/v1\n")
	b.WriteString("current_version=")
	b.WriteString(m.CurrentVersion)
	b.WriteByte('\n')
	b.WriteString("min_version=")
	b.WriteString(m.MinVersion)
	b.WriteByte('\n')
	b.WriteString("released_at=")
	b.WriteString(m.ReleasedAt)
	b.WriteByte('\n')

	keys := make([]string, 0, len(m.Arches))
	for k := range m.Arches {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		entry := m.Arches[k]
		b.WriteString("arch=")
		b.WriteString(k)
		b.WriteString(";sha256=")
		b.WriteString(entry.SHA256)
		b.WriteString(";url=")
		b.WriteString(entry.URL)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// ErrManifestUnsigned — the agent has an embedded release public key but
// the manifest carries no signature. Refuse to upgrade.
var ErrManifestUnsigned = errors.New("manifest is unsigned but agent requires a signature")

// ErrManifestSignatureInvalid — the signature did not verify against the
// embedded public key. Refuse to upgrade.
var ErrManifestSignatureInvalid = errors.New("manifest signature failed Ed25519 verification")

// ErrPublicKeyMalformed — the operator built the agent with a malformed
// public key (wrong length, non-hex). Treated as "no key configured" so
// the build doesn't silently brick all upgrades — but logged loudly.
var ErrPublicKeyMalformed = errors.New("embedded release public key is malformed")

// VerifyManifest enforces the signature policy.
//
// Inputs:
//
//	pubKeyHex — the hex-encoded Ed25519 public key embedded in this binary
//	            via -ldflags (or an empty string for older builds). 64 hex
//	            chars (32 bytes); anything else is malformed.
//	require   — even if pubKeyHex is empty, refuse unsigned manifests.
//	            Matches WIRESHIELD_REQUIRE_SIGNED_UPDATES=1.
//	manifest  — the parsed VersionResponse.
//
// Returns nil when the manifest may proceed to download. Specific errors
// for each rejection reason so the caller can log clearly.
func VerifyManifest(pubKeyHex string, require bool, manifest *client.VersionResponse) error {
	if pubKeyHex == "" {
		if require {
			return fmt.Errorf("%w: WIRESHIELD_REQUIRE_SIGNED_UPDATES=1 but agent was built without an embedded release pubkey", ErrManifestUnsigned)
		}
		return nil
	}

	pub, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		// Malformed pubkey is operator error at build time — but we should
		// not silently auto-upgrade in that case; that would defeat the
		// security goal. Returning an error fails the upgrade attempt.
		return fmt.Errorf("%w (got %d bytes, want %d)", ErrPublicKeyMalformed, len(pub), ed25519.PublicKeySize)
	}

	if manifest.Signature == "" {
		return ErrManifestUnsigned
	}
	sig, err := hex.DecodeString(strings.TrimSpace(manifest.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w (signature decode error or wrong size)", ErrManifestSignatureInvalid)
	}

	payload := CanonicalManifestPayload(manifest)
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return ErrManifestSignatureInvalid
	}
	return nil
}

// requireSignedFromEnv reads WIRESHIELD_REQUIRE_SIGNED_UPDATES — extracted
// for testability. Truthy values: 1, true, yes, on (case-insensitive).
func requireSignedFromEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("WIRESHIELD_REQUIRE_SIGNED_UPDATES"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
