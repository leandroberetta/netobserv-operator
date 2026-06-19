package tls

import (
	"crypto/tls"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

const (
	EnvTLSMinVersion   = "TLS_MIN_VERSION"
	EnvTLSCipherSuites = "TLS_CIPHER_SUITES"
	EnvTLSCurvePrefs   = "TLS_CURVE_PREFERENCES"
)

// ToEnvVars converts ProfileConfig to environment variables for injection into pods
func (pc *ProfileConfig) ToEnvVars() []corev1.EnvVar {
	if pc == nil {
		return nil
	}

	var envs []corev1.EnvVar

	// MinVersion
	if pc.MinVersion != 0 {
		envs = append(envs, corev1.EnvVar{
			Name:  EnvTLSMinVersion,
			Value: tlsVersionToString(pc.MinVersion),
		})
	}

	// CipherSuites (use IANA names for portability)
	if len(pc.CipherSuites) > 0 {
		names := make([]string, 0, len(pc.CipherSuites))
		for _, suite := range pc.CipherSuites {
			name := tls.CipherSuiteName(suite)
			if name != "" {
				names = append(names, name)
			}
		}
		if len(names) > 0 {
			envs = append(envs, corev1.EnvVar{
				Name:  EnvTLSCipherSuites,
				Value: strings.Join(names, ","),
			})
		}
	}

	// CurvePreferences
	if len(pc.CurvePreferences) > 0 {
		names := make([]string, 0, len(pc.CurvePreferences))
		for _, curve := range pc.CurvePreferences {
			names = append(names, curveIDToString(curve))
		}
		envs = append(envs, corev1.EnvVar{
			Name:  EnvTLSCurvePrefs,
			Value: strings.Join(names, ","),
		})
	}

	return envs
}

func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return "1.2"
	}
}

func curveIDToString(curve tls.CurveID) string {
	switch curve {
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case tls.CurveP521:
		return "P-521"
	// PQC curves (Go 1.23+) - uncomment when available
	// case tls.X25519MLKEM768:
	//     return "X25519Kyber768"
	// case tls.CurveP256MLKEM768:
	//     return "P256Kyber768"
	// case tls.CurveP384MLKEM1024:
	//     return "P384Kyber1024"
	default:
		return fmt.Sprintf("curve-%d", curve)
	}
}
