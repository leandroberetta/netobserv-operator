package tls

import (
	"context"
	"crypto/tls"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/crypto"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ProfileConfig represents TLS configuration from cluster TLS profile
type ProfileConfig struct {
	MinVersion      uint16
	CipherSuites    []uint16
	CurvePreferences []tls.CurveID
}

// FetchTLSProfile fetches the TLS security profile from the OpenShift API Server configuration.
// Returns nil if not on OpenShift (resource not found) or if the profile cannot be fetched.
// Gracefully degrades to nil when config.openshift.io/apiservers resource doesn't exist (vanilla Kubernetes).
func FetchTLSProfile(ctx context.Context, c client.Client) (*configv1.TLSSecurityProfile, error) {
	log := log.FromContext(ctx)

	apiServer := &configv1.APIServer{}
	err := c.Get(ctx, types.NamespacedName{Name: "cluster"}, apiServer)
	if err != nil {
		// If the APIServer resource doesn't exist, we're not on OpenShift
		// Return nil profile (not an error) for graceful degradation
		return nil, nil
	}

	log.Info("Successfully fetched TLS profile from cluster", "type", apiServer.Spec.TLSSecurityProfile.Type)
	return apiServer.Spec.TLSSecurityProfile, nil
}

// ConvertToConfig converts an OpenShift TLS profile to ProfileConfig.
// Uses library-go's crypto package for robust conversion.
func ConvertToConfig(profile *configv1.TLSSecurityProfile) (*ProfileConfig, error) {
	if profile == nil {
		profile = &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileIntermediateType,
		}
	}

	spec := getTLSProfileSpec(profile)

	minVersion, err := crypto.TLSVersion(string(spec.MinTLSVersion))
	if err != nil {
		return nil, fmt.Errorf("failed to convert MinTLSVersion: %w", err)
	}

	cipherSuites, err := convertCipherSuites(spec.Ciphers)
	if err != nil {
		return nil, fmt.Errorf("failed to convert cipher suites: %w", err)
	}

	curvePreferences := convertCurvePreferences(spec.Groups)

	return &ProfileConfig{
		MinVersion:       minVersion,
		CipherSuites:     cipherSuites,
		CurvePreferences: curvePreferences,
	}, nil
}

// ApplyToTLSConfig applies the profile configuration to a tls.Config
func (pc *ProfileConfig) ApplyToTLSConfig(tlsConfig *tls.Config) {
	if pc == nil {
		return
	}

	if pc.MinVersion != 0 {
		tlsConfig.MinVersion = pc.MinVersion
	}

	// Only set CipherSuites for TLS < 1.3
	// TLS 1.3 cipher suites are fixed and cannot be configured
	if tlsConfig.MinVersion < tls.VersionTLS13 && len(pc.CipherSuites) > 0 {
		tlsConfig.CipherSuites = pc.CipherSuites
	}

	if len(pc.CurvePreferences) > 0 {
		tlsConfig.CurvePreferences = pc.CurvePreferences
	}
}

// AsTLSOption returns a function that can be used with controller-runtime's TLSOpts.
// This is useful for applying the TLS profile to webhook and metrics servers.
func (pc *ProfileConfig) AsTLSOption() func(*tls.Config) {
	return func(tlsConfig *tls.Config) {
		pc.ApplyToTLSConfig(tlsConfig)
	}
}

// getTLSProfileSpec resolves the actual TLS profile spec
func getTLSProfileSpec(profile *configv1.TLSSecurityProfile) *configv1.TLSProfileSpec {
	if profile == nil || profile.Type == "" {
		profile = &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType}
	}

	switch profile.Type {
	case configv1.TLSProfileOldType:
		return configv1.TLSProfiles[configv1.TLSProfileOldType]
	case configv1.TLSProfileIntermediateType:
		return configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	case configv1.TLSProfileModernType:
		return configv1.TLSProfiles[configv1.TLSProfileModernType]
	case configv1.TLSProfileCustomType:
		if profile.Custom != nil {
			return &profile.Custom.TLSProfileSpec
		}
		return configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	default:
		return configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	}
}

// convertCipherSuites converts OpenSSL cipher suite names to Go constants using library-go
func convertCipherSuites(opensslNames []string) ([]uint16, error) {
	if len(opensslNames) == 0 {
		return nil, nil
	}

	ianaNames := crypto.OpenSSLToIANACipherSuites(opensslNames)

	var suites []uint16
	for _, ianaName := range ianaNames {
		suite, err := crypto.CipherSuite(ianaName)
		if err != nil {
			// Skip unsupported cipher suites silently (expected behavior)
			continue
		}
		suites = append(suites, suite)
	}

	return suites, nil
}

// convertCurvePreferences converts TLS groups to Go CurveID constants
func convertCurvePreferences(groups []configv1.TLSGroup) []tls.CurveID {
	if len(groups) == 0 {
		return nil
	}

	var curves []tls.CurveID
	for _, group := range groups {
		curve, ok := tlsGroupToCurveID(group)
		if !ok {
			// Skip unsupported TLS groups silently (expected behavior)
			continue
		}
		curves = append(curves, curve)
	}

	return curves
}

// tlsGroupToCurveID maps OpenShift TLS group names to Go CurveID constants
func tlsGroupToCurveID(group configv1.TLSGroup) (tls.CurveID, bool) {
	switch group {
	case configv1.TLSGroupX25519:
		return tls.X25519, true
	case configv1.TLSGroupSecP256r1:
		return tls.CurveP256, true
	case configv1.TLSGroupSecP384r1:
		return tls.CurveP384, true
	case configv1.TLSGroupSecP521r1:
		return tls.CurveP521, true
	// Post-Quantum Cryptography hybrid curves (Go 1.23+)
	case configv1.TLSGroupX25519MLKEM768:
		return tls.X25519MLKEM768, true
	// Note: SecP256r1MLKEM768 and SecP384r1MLKEM1024 are not yet available in Go crypto/tls
	// They are defined in openshift/api but not yet in Go standard library
	// case configv1.TLSGroupSecP256r1MLKEM768:
	// 	return tls.SecP256r1MLKEM768, true
	// case configv1.TLSGroupSecP384r1MLKEM1024:
	// 	return tls.SecP384r1MLKEM1024, true
	default:
		return 0, false
	}
}
