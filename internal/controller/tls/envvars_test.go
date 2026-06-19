package tls

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestToEnvVars(t *testing.T) {
	config := &ProfileConfig{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		// TODO: Uncomment when Groups support is available
		// CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}

	envs := config.ToEnvVars()

	// TODO: Change to 3 when Groups support is available
	if len(envs) != 2 {
		t.Errorf("expected 2 env vars, got %d", len(envs))
	}

	// Check MinVersion
	foundMinVersion := false
	for _, env := range envs {
		if env.Name == EnvTLSMinVersion && env.Value == "1.2" {
			foundMinVersion = true
		}
	}
	if !foundMinVersion {
		t.Error("TLS_MIN_VERSION env var not found or incorrect")
	}

	// Check CipherSuites
	foundCipherSuites := false
	for _, env := range envs {
		if env.Name == EnvTLSCipherSuites {
			if !strings.Contains(env.Value, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") {
				t.Errorf("expected cipher suite in value, got: %s", env.Value)
			}
			foundCipherSuites = true
		}
	}
	if !foundCipherSuites {
		t.Error("TLS_CIPHER_SUITES env var not found")
	}

	// TODO: Uncomment when Groups support is available
	// // Check CurvePreferences
	// foundCurvePrefs := false
	// for _, env := range envs {
	// 	if env.Name == EnvTLSCurvePrefs {
	// 		if !strings.Contains(env.Value, "X25519") || !strings.Contains(env.Value, "P-256") {
	// 			t.Errorf("expected curves in value, got: %s", env.Value)
	// 		}
	// 		foundCurvePrefs = true
	// 	}
	// }
	// if !foundCurvePrefs {
	// 	t.Error("TLS_CURVE_PREFERENCES env var not found")
	// }
}

func TestToEnvVars_TLS13(t *testing.T) {
	config := &ProfileConfig{
		MinVersion: tls.VersionTLS13,
	}

	envs := config.ToEnvVars()

	foundMinVersion := false
	for _, env := range envs {
		if env.Name == EnvTLSMinVersion && env.Value == "1.3" {
			foundMinVersion = true
		}
	}
	if !foundMinVersion {
		t.Error("TLS_MIN_VERSION=1.3 not found")
	}
}

func TestToEnvVars_Nil(t *testing.T) {
	var config *ProfileConfig = nil

	envs := config.ToEnvVars()

	if envs != nil {
		t.Errorf("expected nil, got %d env vars", len(envs))
	}
}

func TestToEnvVars_EmptyCipherSuites(t *testing.T) {
	config := &ProfileConfig{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{},
	}

	envs := config.ToEnvVars()

	// Should only have MinVersion
	if len(envs) != 1 {
		t.Errorf("expected 1 env var (MinVersion only), got %d", len(envs))
	}

	if envs[0].Name != EnvTLSMinVersion {
		t.Errorf("expected TLS_MIN_VERSION, got %s", envs[0].Name)
	}
}

func TestTLSVersionToString(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{tls.VersionTLS10, "1.0"},
		{tls.VersionTLS11, "1.1"},
		{tls.VersionTLS12, "1.2"},
		{tls.VersionTLS13, "1.3"},
		{0, "1.2"}, // default
	}

	for _, tt := range tests {
		result := tlsVersionToString(tt.version)
		if result != tt.expected {
			t.Errorf("tlsVersionToString(%v) = %s, want %s", tt.version, result, tt.expected)
		}
	}
}

func TestCurveIDToString(t *testing.T) {
	tests := []struct {
		curve    tls.CurveID
		expected string
	}{
		{tls.X25519, "X25519"},
		{tls.CurveP256, "P-256"},
		{tls.CurveP384, "P-384"},
		{tls.CurveP521, "P-521"},
	}

	for _, tt := range tests {
		result := curveIDToString(tt.curve)
		if result != tt.expected {
			t.Errorf("curveIDToString(%v) = %s, want %s", tt.curve, result, tt.expected)
		}
	}
}
