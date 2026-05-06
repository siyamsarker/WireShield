// wsmanifest is the operator's helper for signing WireShield agent
// update manifests with an offline Ed25519 release key.
//
// Two operations:
//
//   --gen-key   generate an Ed25519 keypair and write it to disk
//   --sign      sign an existing version.json in place
//
// The signing flow:
//
//	# one-time, on the air-gapped signing host:
//	wsmanifest --gen-key --out-priv release.key --out-pub release.pub
//
//	# at agent build time, embed the public half:
//	make dist RELEASE_PUBKEY=$(cat release.pub)
//
//	# every release, sign the manifest the build server publishes:
//	wsmanifest --sign --priv release.key --manifest dist/bin/version.json
//
// The signed manifest is what /api/agents/version returns. Agents built
// with the embedded public key will refuse to upgrade from an unsigned
// or tampered manifest.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/siyamsarker/wireshield/agent/internal/client"
	"github.com/siyamsarker/wireshield/agent/internal/updater"
)

func main() {
	var (
		genKey   = flag.Bool("gen-key", false, "generate a new Ed25519 keypair")
		outPriv  = flag.String("out-priv", "release.key", "path to write the private key (PEM-style hex)")
		outPub   = flag.String("out-pub", "release.pub", "path to write the public key (hex)")
		sign     = flag.Bool("sign", false, "sign a manifest in place")
		priv     = flag.String("priv", "release.key", "path to the private key to sign with")
		manifest = flag.String("manifest", "", "path to the version.json to sign")
		verify   = flag.Bool("verify", false, "verify a manifest's signature against --pub")
		pub      = flag.String("pub", "release.pub", "path to the public key (for --verify)")
	)
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wsmanifest --gen-key | --sign --manifest path | --verify --manifest path")
		flag.PrintDefaults()
	}
	flag.Parse()

	switch {
	case *genKey:
		exit(genKeyCmd(*outPriv, *outPub))
	case *sign:
		if *manifest == "" {
			die("--sign requires --manifest")
		}
		exit(signCmd(*priv, *manifest))
	case *verify:
		if *manifest == "" {
			die("--verify requires --manifest")
		}
		exit(verifyCmd(*pub, *manifest))
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func genKeyCmd(privPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	// Private key on disk: hex of the full 64-byte ed25519.PrivateKey
	// (which embeds the seed + public key) so we don't need any external
	// PEM library and the file is human-inspectable.
	if err := writeFileMode(privPath, []byte(hex.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", privPath, err)
	}
	if err := writeFileMode(pubPath, []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", pubPath, err)
	}
	fmt.Printf("Wrote %s (mode 0600) and %s (mode 0644)\n", privPath, pubPath)
	fmt.Printf("Public key (hex): %s\n", hex.EncodeToString(pub))
	return nil
}

func signCmd(privPath, manifestPath string) error {
	priv, err := readPrivateKey(privPath)
	if err != nil {
		return err
	}

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}

	var m client.VersionResponse
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("parse manifest %s: %w", manifestPath, err)
	}
	// Strip any prior signature so the canonical payload is the same on
	// signing and verification — otherwise re-signing would chain.
	m.Signature = ""
	payload := updater.CanonicalManifestPayload(&m)
	sig := ed25519.Sign(priv, payload)
	m.Signature = hex.EncodeToString(sig)

	out, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode signed manifest: %w", err)
	}
	out = append(out, '\n')
	if err := writeFileMode(manifestPath, out, 0o644); err != nil {
		return fmt.Errorf("write signed manifest: %w", err)
	}
	fmt.Printf("Signed %s\n", manifestPath)
	fmt.Printf("Public key (hex): %s\n", hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
	return nil
}

func verifyCmd(pubPath, manifestPath string) error {
	pubBytes, err := readKeyHex(pubPath, ed25519.PublicKeySize)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	var m client.VersionResponse
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}
	if err := updater.VerifyManifest(hex.EncodeToString(pubBytes), true, &m); err != nil {
		return err
	}
	fmt.Printf("Manifest %s: signature OK\n", manifestPath)
	return nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := readKeyHex(path, ed25519.PrivateKeySize)
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", path, err)
	}
	return ed25519.PrivateKey(b), nil
}

func readKeyHex(path string, expectLen int) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hexStr := ""
	for _, ch := range string(raw) {
		if ch == '\n' || ch == '\r' || ch == ' ' || ch == '\t' {
			continue
		}
		hexStr += string(ch)
	}
	out, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	if len(out) != expectLen {
		return nil, fmt.Errorf("expected %d bytes, got %d", expectLen, len(out))
	}
	return out, nil
}

// writeFileMode writes data atomically (tmp + rename) with the given mode.
// Important for the private key — we don't want a partial write to remain
// readable on disk if signing is interrupted.
func writeFileMode(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(".", "wsmanifest-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

func exit(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "wsmanifest:", err)
		os.Exit(1)
	}
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, "wsmanifest:", msg)
	os.Exit(2)
}
