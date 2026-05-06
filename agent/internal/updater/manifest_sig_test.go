package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/siyamsarker/wireshield/agent/internal/client"
)

func mustGenKeypair(t *testing.T) (pubHex string, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pub), priv
}

func sampleManifest() *client.VersionResponse {
	return &client.VersionResponse{
		CurrentVersion: "1.2.3",
		MinVersion:     "1.0.0",
		ReleasedAt:     "2026-05-06T12:00:00Z",
		Arches: map[string]client.VersionArchEntry{
			"linux-amd64": {URL: "https://srv/bin/amd64", SHA256: "deadbeef"},
			"linux-arm64": {URL: "https://srv/bin/arm64", SHA256: "cafef00d"},
		},
	}
}

func TestCanonicalPayloadDeterministic(t *testing.T) {
	a := CanonicalManifestPayload(sampleManifest())
	b := CanonicalManifestPayload(sampleManifest())
	if string(a) != string(b) {
		t.Fatalf("canonical payload not deterministic:\n%s\nvs\n%s", a, b)
	}
	// Arches must be sorted by key — verify amd64 appears before arm64.
	if i, j := strings.Index(string(a), "linux-amd64"), strings.Index(string(a), "linux-arm64"); i < 0 || j < 0 || i >= j {
		t.Fatalf("arches not sorted alphabetically:\n%s", a)
	}
}

func TestVerifyManifestNoKeyConfigured(t *testing.T) {
	m := sampleManifest()
	// No embedded key, signature missing → allow (legacy mode).
	if err := VerifyManifest("", false, m); err != nil {
		t.Fatalf("expected legacy bypass to allow, got %v", err)
	}
	// No embedded key but require=true → reject loudly.
	if err := VerifyManifest("", true, m); !errors.Is(err, ErrManifestUnsigned) {
		t.Fatalf("expected ErrManifestUnsigned, got %v", err)
	}
}

func TestVerifyManifestHappyPath(t *testing.T) {
	pubHex, priv := mustGenKeypair(t)
	m := sampleManifest()
	m.Signature = hex.EncodeToString(ed25519.Sign(priv, CanonicalManifestPayload(m)))
	if err := VerifyManifest(pubHex, true, m); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifyManifestRejectsTampering(t *testing.T) {
	pubHex, priv := mustGenKeypair(t)
	m := sampleManifest()
	m.Signature = hex.EncodeToString(ed25519.Sign(priv, CanonicalManifestPayload(m)))

	// 1. Tamper with arch URL
	tampered := *m
	tampered.Arches = map[string]client.VersionArchEntry{
		"linux-amd64": {URL: "https://attacker/bin/amd64", SHA256: "deadbeef"},
		"linux-arm64": {URL: "https://srv/bin/arm64", SHA256: "cafef00d"},
	}
	if err := VerifyManifest(pubHex, true, &tampered); !errors.Is(err, ErrManifestSignatureInvalid) {
		t.Errorf("URL tamper not caught: got %v", err)
	}

	// 2. Tamper with sha256
	tampered2 := *m
	tampered2.Arches = map[string]client.VersionArchEntry{
		"linux-amd64": {URL: "https://srv/bin/amd64", SHA256: "1111"},
		"linux-arm64": {URL: "https://srv/bin/arm64", SHA256: "cafef00d"},
	}
	if err := VerifyManifest(pubHex, true, &tampered2); !errors.Is(err, ErrManifestSignatureInvalid) {
		t.Errorf("sha256 tamper not caught: got %v", err)
	}

	// 3. Tamper with version
	tampered3 := *m
	tampered3.CurrentVersion = "9.9.9"
	if err := VerifyManifest(pubHex, true, &tampered3); !errors.Is(err, ErrManifestSignatureInvalid) {
		t.Errorf("version tamper not caught: got %v", err)
	}
}

func TestVerifyManifestUnsigned(t *testing.T) {
	pubHex, _ := mustGenKeypair(t)
	m := sampleManifest()
	// No signature, but agent has a key configured → reject.
	if err := VerifyManifest(pubHex, false, m); !errors.Is(err, ErrManifestUnsigned) {
		t.Fatalf("unsigned manifest accepted: got %v", err)
	}
}

func TestVerifyManifestMalformedKey(t *testing.T) {
	m := sampleManifest()
	m.Signature = "00" + strings.Repeat("01", 63)
	for _, bad := range []string{"not-hex", "deadbeef", strings.Repeat("ff", 31)} {
		if err := VerifyManifest(bad, false, m); !errors.Is(err, ErrPublicKeyMalformed) {
			t.Errorf("malformed key %q not caught: got %v", bad, err)
		}
	}
}

func TestVerifyManifestRejectsCrossKeySignature(t *testing.T) {
	pubA, _ := mustGenKeypair(t)
	_, privB := mustGenKeypair(t)
	m := sampleManifest()
	// Sign with B but verify against A.
	m.Signature = hex.EncodeToString(ed25519.Sign(privB, CanonicalManifestPayload(m)))
	if err := VerifyManifest(pubA, true, m); !errors.Is(err, ErrManifestSignatureInvalid) {
		t.Fatalf("cross-key signature accepted: got %v", err)
	}
}
