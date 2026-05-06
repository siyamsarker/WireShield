package main

import (
	"testing"
)

func TestResolveTLSInsecure(t *testing.T) {
	t.Run("flag wins over everything", func(t *testing.T) {
		t.Setenv("WIRESHIELD_TLS_INSECURE", "")
		if got := resolveTLSInsecure(true, false); !got {
			t.Fatalf("flag=true should force true, got false")
		}
	})

	t.Run("env truthy variants", func(t *testing.T) {
		for _, v := range []string{"1", "true", "TRUE", "Yes", "on"} {
			t.Setenv("WIRESHIELD_TLS_INSECURE", v)
			if got := resolveTLSInsecure(false, false); !got {
				t.Fatalf("env=%q should be truthy", v)
			}
		}
	})

	t.Run("env falsy variants", func(t *testing.T) {
		for _, v := range []string{"", "0", "false", "no", "off", "garbage"} {
			t.Setenv("WIRESHIELD_TLS_INSECURE", v)
			if got := resolveTLSInsecure(false, false); got {
				t.Fatalf("env=%q should be falsy", v)
			}
		}
	})

	t.Run("legacy config falls back when flag and env unset", func(t *testing.T) {
		t.Setenv("WIRESHIELD_TLS_INSECURE", "")
		if got := resolveTLSInsecure(false, true); !got {
			t.Fatalf("legacy config=true should be honored")
		}
	})

	t.Run("default secure when nothing set", func(t *testing.T) {
		t.Setenv("WIRESHIELD_TLS_INSECURE", "")
		if got := resolveTLSInsecure(false, false); got {
			t.Fatalf("default should be secure (false), got insecure")
		}
	})
}

func TestEnvBool(t *testing.T) {
	cases := map[string]bool{
		"1": true, "true": true, "TRUE": true, "Yes": true, "ON": true,
		"":  false, "0": false, "false": false, "no": false, "garbage": false,
		"  true  ": true,
	}
	for in, want := range cases {
		if got := envBool(in); got != want {
			t.Errorf("envBool(%q)=%v, want %v", in, got, want)
		}
	}
}
