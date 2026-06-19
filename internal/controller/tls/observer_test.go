package tls

import (
	"context"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestObserver_GetCurrent(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = configv1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	initialConfig := &ProfileConfig{
		MinVersion: 0x0303, // TLS 1.2
	}

	observer := NewObserver(client, initialConfig, nil)

	current := observer.GetCurrent()
	if current == nil {
		t.Fatal("Expected non-nil ProfileConfig")
	}

	if current.MinVersion != 0x0303 {
		t.Errorf("Expected MinVersion 0x0303, got %v", current.MinVersion)
	}
}

func TestObserver_Reconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = configv1.AddToScheme(scheme)

	// Create a fake APIServer with Intermediate profile
	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileIntermediateType,
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiServer).
		Build()

	// Track if shutdown was called
	shutdownCalled := false
	shutdownFunc := func() {
		shutdownCalled = true
	}

	observer := NewObserver(client, nil, shutdownFunc)

	// Reconcile should fetch and update the profile
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "cluster"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := observer.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Check that the profile was updated
	current := observer.GetCurrent()
	if current == nil {
		t.Fatal("Expected non-nil ProfileConfig after reconcile")
	}

	// Intermediate profile should have TLS 1.2
	if current.MinVersion != 0x0303 {
		t.Errorf("Expected TLS 1.2 (0x0303), got %v", current.MinVersion)
	}

	// Shutdown should have been called since profile changed from nil
	if !shutdownCalled {
		t.Error("Expected shutdown to be called when profile changes from nil")
	}
}

func TestObserver_ReconcileNoChange(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = configv1.AddToScheme(scheme)

	// Create a fake APIServer with Intermediate profile
	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileIntermediateType,
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiServer).
		Build()

	shutdownCalled := false
	shutdownFunc := func() {
		shutdownCalled = true
	}

	// First reconcile to populate initial config
	observer := NewObserver(client, nil, shutdownFunc)
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "cluster"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := observer.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("First reconcile failed: %v", err)
	}

	// Shutdown should have been called on first change from nil
	if !shutdownCalled {
		t.Error("Expected shutdown on first reconcile (change from nil)")
	}

	// Reset shutdown flag
	shutdownCalled = false

	// Second reconcile with same profile should NOT trigger shutdown
	_, err = observer.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Second reconcile failed: %v", err)
	}

	// Shutdown should NOT have been called since profile didn't change
	if shutdownCalled {
		t.Error("Shutdown should not be called when profile doesn't change")
	}
}

func TestObserver_ReconcileProfileChange(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = configv1.AddToScheme(scheme)

	// Create a fake APIServer with Intermediate profile
	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileIntermediateType,
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiServer).
		Build()

	shutdownCalled := 0
	shutdownFunc := func() {
		shutdownCalled++
	}

	// First reconcile with Intermediate profile
	observer := NewObserver(client, nil, shutdownFunc)
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "cluster"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := observer.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("First reconcile failed: %v", err)
	}

	if shutdownCalled != 1 {
		t.Errorf("Expected shutdown to be called once, got %d", shutdownCalled)
	}

	// Update APIServer to Modern profile
	apiServer.Spec.TLSSecurityProfile.Type = configv1.TLSProfileModernType
	err = client.Update(ctx, apiServer)
	if err != nil {
		t.Fatalf("Failed to update APIServer: %v", err)
	}

	// Second reconcile with Modern profile should trigger shutdown
	_, err = observer.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Second reconcile failed: %v", err)
	}

	if shutdownCalled != 2 {
		t.Errorf("Expected shutdown to be called twice (profile changed), got %d", shutdownCalled)
	}

	// Verify profile was updated to TLS 1.3 (Modern)
	current := observer.GetCurrent()
	if current == nil {
		t.Fatal("Expected non-nil ProfileConfig")
	}

	if current.MinVersion != 0x0304 {
		t.Errorf("Expected TLS 1.3 (0x0304) for Modern profile, got %v", current.MinVersion)
	}
}

func TestObserver_ReconcileNonCluster(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = configv1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	initialConfig := &ProfileConfig{
		MinVersion: 0x0303,
	}

	shutdownCalled := false
	shutdownFunc := func() {
		shutdownCalled = true
	}

	observer := NewObserver(client, initialConfig, shutdownFunc)

	// Reconcile with a different name should be a no-op
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "not-cluster"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := observer.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Profile should be unchanged
	current := observer.GetCurrent()
	if current.MinVersion != 0x0303 {
		t.Errorf("Profile should not have changed, got MinVersion %v", current.MinVersion)
	}

	// Shutdown should NOT have been called
	if shutdownCalled {
		t.Error("Shutdown should not be called for non-cluster APIServer")
	}
}
