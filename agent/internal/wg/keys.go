// Package wg implements WireGuard helpers needed by the agent: pure-Go key
// generation and a config-file writer. We avoid shelling out to `wg genkey` so
// the agent has one less runtime dependency during enrollment (the daemon
// still needs `wg`/`wg-quick` at run time, but not at bootstrap time).
package wg

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeyPair is a base64-encoded WireGuard keypair, matching the `wg pubkey`
// output format byte-for-byte.
type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

// GenerateKeyPair produces a new Curve25519 keypair with the WG clamping
// applied to the private scalar. Matches `wg genkey | wg pubkey`.
func GenerateKeyPair() (*KeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, fmt.Errorf("read random: %w", err)
	}
	// WireGuard applies the standard Curve25519 clamping to private keys.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	return &KeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(priv[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(pubBytes),
	}, nil
}
