package tls

import (
	"crypto/tls"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestConvertToConfig_Modern(t *testing.T) {
	profile := &configv1.TLSSecurityProfile{
		Type: configv1.TLSProfileModernType,
	}

	config, err := ConvertToConfig(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3, got %v", config.MinVersion)
	}

	if len(config.CipherSuites) == 0 {
		t.Error("expected cipher suites to be set")
	}

	// TODO: Uncomment when Groups support is available
	// if len(config.CurvePreferences) == 0 {
	// 	t.Error("expected curve preferences to be set")
	// }
}

func TestConvertToConfig_Intermediate(t *testing.T) {
	profile := &configv1.TLSSecurityProfile{
		Type: configv1.TLSProfileIntermediateType,
	}

	config, err := ConvertToConfig(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2, got %v", config.MinVersion)
	}
}

func TestConvertToConfig_Old(t *testing.T) {
	profile := &configv1.TLSSecurityProfile{
		Type: configv1.TLSProfileOldType,
	}

	config, err := ConvertToConfig(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.MinVersion != tls.VersionTLS10 {
		t.Errorf("expected TLS 1.0, got %v", config.MinVersion)
	}
}

func TestConvertToConfig_Custom(t *testing.T) {
	profile := &configv1.TLSSecurityProfile{
		Type: configv1.TLSProfileCustomType,
		Custom: &configv1.CustomTLSProfile{
			TLSProfileSpec: configv1.TLSProfileSpec{
				MinTLSVersion: configv1.VersionTLS13,
				Ciphers: []string{
					"ECDHE-RSA-AES128-GCM-SHA256",
				},
			},
		},
	}

	config, err := ConvertToConfig(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3, got %v", config.MinVersion)
	}

	if len(config.CipherSuites) == 0 {
		t.Error("expected at least one cipher suite")
	}

	// TODO: Uncomment when Groups support is available
	// if len(config.CurvePreferences) != 2 {
	// 	t.Errorf("expected 2 curve preferences, got %d", len(config.CurvePreferences))
	// }
}

func TestConvertToConfig_Nil(t *testing.T) {
	config, err := ConvertToConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should default to Intermediate
	if config.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2 (Intermediate default), got %v", config.MinVersion)
	}
}

func TestApplyToTLSConfig(t *testing.T) {
	profileConfig := &ProfileConfig{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		// TODO: Uncomment when Groups support is available
		// CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}

	tlsCfg := &tls.Config{}
	profileConfig.ApplyToTLSConfig(tlsCfg)

	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion not applied correctly, got %v", tlsCfg.MinVersion)
	}

	if len(tlsCfg.CipherSuites) != 1 {
		t.Errorf("expected 1 cipher suite, got %d", len(tlsCfg.CipherSuites))
	}

	// TODO: Uncomment when Groups support is available
	// if len(tlsCfg.CurvePreferences) != 2 {
	// 	t.Errorf("expected 2 curve preferences, got %d", len(tlsCfg.CurvePreferences))
	// }
}

func TestApplyToTLSConfig_TLS13IgnoresCipherSuites(t *testing.T) {
	profileConfig := &ProfileConfig{
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}

	tlsCfg := &tls.Config{}
	profileConfig.ApplyToTLSConfig(tlsCfg)

	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion not applied correctly, got %v", tlsCfg.MinVersion)
	}

	// CipherSuites should NOT be set for TLS 1.3
	if len(tlsCfg.CipherSuites) != 0 {
		t.Errorf("TLS 1.3 should not have CipherSuites set, got %d", len(tlsCfg.CipherSuites))
	}
}

func TestApplyToTLSConfig_Nil(t *testing.T) {
	var profileConfig *ProfileConfig = nil

	tlsCfg := &tls.Config{}
	profileConfig.ApplyToTLSConfig(tlsCfg)

	// Should not panic, and config should remain unchanged
	if tlsCfg.MinVersion != 0 {
		t.Errorf("expected MinVersion to remain 0, got %v", tlsCfg.MinVersion)
	}
}
