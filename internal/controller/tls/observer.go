package tls

import (
	"context"
	"sync"

	configv1 "github.com/openshift/api/config/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// Observer watches for changes to the cluster TLS profile and keeps ProfileConfig updated
// When the TLS profile changes:
// 1. Updates the shared ProfileConfig for new reconciles
// 2. Triggers graceful shutdown of the operator to reload TLS config
type Observer struct {
	client.Client
	mu           sync.RWMutex
	current      *ProfileConfig
	shutdownFunc context.CancelFunc
}

// NewObserver creates a new TLS profile observer with an initial profile
// shutdownFunc will be called when TLS profile changes to trigger operator restart
func NewObserver(c client.Client, initial *ProfileConfig, shutdownFunc context.CancelFunc) *Observer {
	return &Observer{
		Client:       c,
		current:      initial,
		shutdownFunc: shutdownFunc,
	}
}

// GetCurrent returns the current TLS profile configuration
// This is thread-safe and can be called from multiple goroutines
func (o *Observer) GetCurrent() *ProfileConfig {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.current
}

// Reconcile implements the reconcile.Reconciler interface
func (o *Observer) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Only handle the cluster APIServer
	if req.Name != "cluster" {
		return ctrl.Result{}, nil
	}

	log.Info("TLS profile change detected, fetching new profile")

	// Fetch the TLS profile
	profile, err := FetchTLSProfile(ctx, o.Client)
	if err != nil {
		log.Error(err, "Failed to fetch TLS profile")
		return ctrl.Result{}, err
	}

	// Convert to ProfileConfig
	var tlsConfig *ProfileConfig
	if profile != nil {
		tlsConfig, err = ConvertToConfig(profile)
		if err != nil {
			log.Error(err, "Failed to convert TLS profile")
			return ctrl.Result{}, err
		}
		log.Info("Successfully updated TLS profile", "type", profile.Type)
	} else {
		log.Info("TLS profile not available (not on OpenShift), using defaults")
	}

	// Check if profile actually changed
	o.mu.Lock()
	profileChanged := !profileConfigEqual(o.current, tlsConfig)
	o.current = tlsConfig
	o.mu.Unlock()

	if profileChanged {
		log.Info("TLS profile has changed, initiating graceful shutdown to reload configuration")
		if o.shutdownFunc != nil {
			o.shutdownFunc()
		}
	}

	return ctrl.Result{}, nil
}

// profileConfigEqual compares two ProfileConfig instances for equality
func profileConfigEqual(a, b *ProfileConfig) bool {
	// Both nil
	if a == nil && b == nil {
		return true
	}
	// One nil, one not
	if a == nil || b == nil {
		return false
	}
	// Compare MinVersion
	if a.MinVersion != b.MinVersion {
		return false
	}
	// Compare CipherSuites length
	if len(a.CipherSuites) != len(b.CipherSuites) {
		return false
	}
	// Compare CipherSuites content
	for i := range a.CipherSuites {
		if a.CipherSuites[i] != b.CipherSuites[i] {
			return false
		}
	}
	// Compare CurvePreferences length
	if len(a.CurvePreferences) != len(b.CurvePreferences) {
		return false
	}
	// Compare CurvePreferences content
	for i := range a.CurvePreferences {
		if a.CurvePreferences[i] != b.CurvePreferences[i] {
			return false
		}
	}
	return true
}

// SetupWithManager sets up the controller with the Manager
func (o *Observer) SetupWithManager(mgr ctrl.Manager) error {
	// Create a predicate that only watches the cluster APIServer resource
	clusterPredicate := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return e.Object.GetName() == "cluster"
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return e.ObjectNew.GetName() == "cluster"
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return false // We don't care about deletion
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&configv1.APIServer{}).
		WithEventFilter(clusterPredicate).
		Complete(o)
}

