package wg

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	for i := 0; i < 3; i++ {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		priv, err := base64.StdEncoding.DecodeString(kp.PrivateKey)
		if err != nil || len(priv) != 32 {
			t.Fatalf("private key not 32 bytes: %v len=%d", err, len(priv))
		}
		pub, err := base64.StdEncoding.DecodeString(kp.PublicKey)
		if err != nil || len(pub) != 32 {
			t.Fatalf("public key not 32 bytes: %v len=%d", err, len(pub))
		}
		// WG clamping bits must be set.
		if priv[0]&0x07 != 0 {
			t.Fatalf("private key low bits not clamped: %#x", priv[0])
		}
		if priv[31]&0x80 != 0 {
			t.Fatalf("private key top bit not cleared: %#x", priv[31])
		}
		if priv[31]&0x40 == 0 {
			t.Fatalf("private key bit 254 not set: %#x", priv[31])
		}
	}
}

func TestBuildAgentConfigRequiresFields(t *testing.T) {
	_, err := BuildAgentConfig(&AgentConfigInput{})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestBuildAgentConfigSkipsNATWhenNoLAN(t *testing.T) {
	cfg, err := BuildAgentConfig(&AgentConfigInput{
		PrivateKey: "priv", WGIPv4: "10.8.0.200",
		ServerPublicKey: "srv", ServerEndpoint: "vpn.example:51820",
		AgentAllowedIPs: "10.8.0.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg, "MASQUERADE") || strings.Contains(cfg, "PostUp") {
		t.Fatalf("config should not have NAT rules when LANInterface is empty:\n%s", cfg)
	}
	if !strings.Contains(cfg, "Address = 10.8.0.200/32") {
		t.Fatalf("missing Address line:\n%s", cfg)
	}
	if !strings.Contains(cfg, "AllowedIPs = 10.8.0.0/24") {
		t.Fatalf("missing AllowedIPs line:\n%s", cfg)
	}
}

func TestBuildAgentConfigEmitsNATWhenLANAndCIDRs(t *testing.T) {
	cfg, err := BuildAgentConfig(&AgentConfigInput{
		PrivateKey: "priv", WGIPv4: "10.8.0.200",
		ServerPublicKey: "srv", ServerEndpoint: "vpn:51820",
		AgentAllowedIPs: "10.8.0.0/24",
		LANInterface:    "eth0",
		AdvertisedCIDRs: []string{"10.50.0.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"PostUp = sysctl -w net.ipv4.ip_forward=1",
		"PostUp = iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE",
		"PreDown = iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("missing %q in:\n%s", want, cfg)
		}
	}
}
