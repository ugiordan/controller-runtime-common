/*
Copyright 2026 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package tls provides utilities for working with OpenShift TLS profiles.
package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// APIServerName is the name of the APIServer resource in the cluster.
	APIServerName = "cluster"
)

var (
	// ErrCustomProfileNil is returned when a custom TLS profile is specified but the Custom field is nil.
	ErrCustomProfileNil = errors.New("custom TLS profile specified but Custom field is nil")

	// DefaultTLSCiphers are the default TLS ciphers for API servers.
	DefaultTLSCiphers = configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers //nolint:gochecknoglobals
	// DefaultMinTLSVersion is the default minimum TLS version for API servers.
	DefaultMinTLSVersion = configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion //nolint:gochecknoglobals
)

// FetchAPIServerTLSProfile fetches the TLS profile spec configured in APIServer.
// If no profile is configured, the default profile is returned.
func FetchAPIServerTLSProfile(ctx context.Context, k8sClient client.Client) (configv1.TLSProfileSpec, error) {
	apiServer, err := fetchAPIServer(ctx, k8sClient)
	if err != nil {
		key := client.ObjectKey{Name: APIServerName}
		return configv1.TLSProfileSpec{}, fmt.Errorf("failed to get APIServer %q: %w", key.String(), err)
	}

	profile, err := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
	if err != nil {
		key := client.ObjectKey{Name: APIServerName}
		return configv1.TLSProfileSpec{}, fmt.Errorf("failed to get TLS profile from APIServer %q: %w", key.String(), err)
	}

	return profile, nil
}

// FetchAPIServerTLSAdherencePolicy fetches the TLS adherence policy configured in APIServer.
// If no policy is configured, the default policy is returned.
func FetchAPIServerTLSAdherencePolicy(ctx context.Context, k8sClient client.Client) (configv1.TLSAdherencePolicy, error) {
	apiServer, err := fetchAPIServer(ctx, k8sClient)
	if err != nil {
		key := client.ObjectKey{Name: APIServerName}
		return configv1.TLSAdherencePolicyNoOpinion, fmt.Errorf("failed to get APIServer %q: %w", key.String(), err)
	}

	return apiServer.Spec.TLSAdherence, nil
}

func fetchAPIServer(ctx context.Context, k8sClient client.Client) (*configv1.APIServer, error) {
	apiServer := &configv1.APIServer{}

	if err := k8sClient.Get(ctx, client.ObjectKey{Name: APIServerName}, apiServer); err != nil {
		return nil, err
	}

	return apiServer, nil
}

// GetTLSProfileSpec returns TLSProfileSpec for the given profile.
// If no profile is configured, the default profile is returned.
func GetTLSProfileSpec(profile *configv1.TLSSecurityProfile) (configv1.TLSProfileSpec, error) {
	// Define the default profile (at the time of writing, this is the intermediate profile).
	defaultProfile := *configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	// If the profile is nil or the type is empty, return the default profile.
	if profile == nil || profile.Type == "" {
		return defaultProfile, nil
	}

	// Get the profile type.
	profileType := profile.Type

	// If the profile type is not custom, return the profile from the map.
	if profileType != configv1.TLSProfileCustomType {
		if tlsConfig, ok := configv1.TLSProfiles[profileType]; ok {
			return *tlsConfig, nil
		}

		// If the profile type is not found, return the default profile.
		return defaultProfile, nil
	}

	if profile.Custom == nil {
		// If the custom profile is nil, return an error.
		return configv1.TLSProfileSpec{}, ErrCustomProfileNil
	}

	// Return the custom profile spec.
	return profile.Custom.TLSProfileSpec, nil
}

// ConfigResult holds the results of ResolveTLSConfig.
type ConfigResult struct {
	// TLSConfig is a function that configures a tls.Config based on the resolved profile.
	TLSConfig func(*tls.Config)

	// ProfileSpec is the profile specification observed in APIServer. It remains
	// unchanged when TLSConfig uses the default because the observed profile is
	// also used to initialize SecurityProfileWatcher.
	ProfileSpec configv1.TLSProfileSpec

	// AdherencePolicy is the resolved TLS adherence policy.
	AdherencePolicy configv1.TLSAdherencePolicy

	// APIServerAvailable reports whether the APIServer API is available for a
	// SecurityProfileWatcher. It is false when the API is absent, and true when
	// the resource was read, is temporarily absent, or a transient read error occurred.
	APIServerAvailable bool
}

// ResolveTLSConfig resolves TLS configuration for an operator.
// It fetches the cluster TLS profile and adherence policy, applies the appropriate
// configuration, and returns a ConfigResult that can be used with the SecurityProfileWatcher.
//
// If the OpenShift API is absent or temporarily unavailable, this function falls back to
// default configurations. Permission and unexpected API errors are returned to the caller.
func ResolveTLSConfig(ctx context.Context, restConfig *rest.Config) (*ConfigResult, error) {
	// The default controller-runtime scheme does not include OpenShift API types.
	scheme := runtime.NewScheme()
	if err := configv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add OpenShift config API to scheme: %w", err)
	}

	kubeClient, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return resolveTLSConfig(ctx, kubeClient)
}

func resolveTLSConfig(ctx context.Context, kubeClient client.Client) (*ConfigResult, error) {
	logger := log.FromContext(ctx)

	defaultProfile := *configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	profileSpec := defaultProfile

	// Read the APIServer resource once so the profile and adherence policy come from
	// the same resource version.
	adherencePolicy := configv1.TLSAdherencePolicyNoOpinion
	apiServerAvailable := true
	apiServer, fetchErr := fetchAPIServer(ctx, kubeClient)
	if fetchErr != nil {
		shouldFallback, available := classifyAPIServerFetchError(fetchErr)
		if !shouldFallback {
			key := client.ObjectKey{Name: APIServerName}
			return nil, fmt.Errorf("failed to get APIServer %q: %w", key.String(), fetchErr)
		}

		apiServerAvailable = available
		logger.Info("APIServer TLS configuration unavailable, using default TLS settings")
	} else {
		adherencePolicy = apiServer.Spec.TLSAdherence
		fetchedProfile, profileErr := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
		if profileErr != nil {
			logger.Info("APIServer TLS profile is invalid, using the default profile")
		} else {
			profileSpec = fetchedProfile
		}
	}

	// NoOpinion and LegacyAdheringComponentsOnly preserve the legacy behavior of
	// using the component default. Unknown values honor the cluster profile for
	// forward-compatible, more secure behavior, matching library-go's helper.
	profileToApply := defaultProfile
	if adherencePolicy != configv1.TLSAdherencePolicyNoOpinion &&
		adherencePolicy != configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly {
		// The cluster profile is authoritative when strict adherence is requested.
		profileToApply = profileSpec
	}

	// NewTLSConfigFromProfile uses TLSVersionOrDie, so only reject an invalid
	// version that would otherwise panic. Valid legacy versions remain supported.
	if _, err := libgocrypto.TLSVersion(string(profileToApply.MinTLSVersion)); err != nil {
		logger.Info("APIServer TLS profile has an invalid minimum TLS version, using the default profile")
		profileToApply = defaultProfile
	}

	tlsConfigFn, unsupportedCiphers := NewTLSConfigFromProfile(profileToApply)
	if len(unsupportedCiphers) > 0 {
		logger.Info("TLS profile contains unsupported ciphers that will be ignored", "count", len(unsupportedCiphers))
	}

	return &ConfigResult{
		TLSConfig:          tlsConfigFn,
		ProfileSpec:        profileSpec,
		AdherencePolicy:    adherencePolicy,
		APIServerAvailable: apiServerAvailable,
	}, nil
}

func classifyAPIServerFetchError(err error) (shouldFallback, apiServerAvailable bool) {
	if meta.IsNoMatchError(err) {
		return true, false
	}
	if apierrors.IsNotFound(err) {
		return true, true
	}

	if apierrors.IsServiceUnavailable(err) ||
		apierrors.IsTimeout(err) ||
		apierrors.IsServerTimeout(err) ||
		apierrors.IsTooManyRequests(err) ||
		errors.Is(err, context.DeadlineExceeded) {
		return true, true
	}

	return false, false
}

// NewTLSConfigFromProfile returns a function that configures a tls.Config based on the provided TLSProfileSpec,
// along with any cipher names from the profile that are not supported by the library-go crypto package.
// The returned function is intended to be used with controller-runtime's TLSOpts.
//
// Note: CipherSuites are only set when MinVersion is below TLS 1.3, as Go's TLS 1.3 implementation
// does not allow configuring cipher suites - all TLS 1.3 ciphers are always enabled.
// See: https://github.com/golang/go/issues/29349
func NewTLSConfigFromProfile(profile configv1.TLSProfileSpec) (tlsConfig func(*tls.Config), unsupportedCiphers []string) {
	minVersion := libgocrypto.TLSVersionOrDie(string(profile.MinTLSVersion))
	cipherSuites, unsupportedCiphers := cipherCodes(profile.Ciphers)

	return func(tlsConf *tls.Config) {
		tlsConf.MinVersion = minVersion
		// TODO: add curve preferences from profile once https://github.com/openshift/api/pull/2583 merges.
		// tlsConf.CurvePreferences <<<<<< profile.Curves

		// TLS 1.3 cipher suites are not configurable in Go (https://github.com/golang/go/issues/29349), so only set CipherSuites accordingly.
		// TODO: revisit this once we get an answer on the best way to handle this here:
		// https://docs.google.com/document/d/1cMc9E8psHfnoK06ntR8kHSWB8d3rMtmldhnmM4nImjs/edit?disco=AAABu_nPcYg
		if minVersion != tls.VersionTLS13 {
			tlsConf.CipherSuites = cipherSuites
		}
	}, unsupportedCiphers
}

// cipherCode returns the TLS cipher code for an OpenSSL or IANA cipher name.
// Returns 0 if the cipher is not supported.
func cipherCode(cipher string) uint16 {
	// First try as IANA name directly.
	if code, err := libgocrypto.CipherSuite(cipher); err == nil {
		return code
	}

	// Try converting from OpenSSL name to IANA name.
	ianaCiphers := libgocrypto.OpenSSLToIANACipherSuites([]string{cipher})
	if len(ianaCiphers) == 1 {
		if code, err := libgocrypto.CipherSuite(ianaCiphers[0]); err == nil {
			return code
		}
	}

	// Return 0 if the cipher is not supported.
	return 0
}

// cipherCodes converts a list of cipher names (OpenSSL or IANA format) to their uint16 codes.
// Returns the converted codes and a list of any unsupported cipher names.
func cipherCodes(ciphers []string) (codes []uint16, unsupportedCiphers []string) {
	for _, cipher := range ciphers {
		code := cipherCode(cipher)
		if code == 0 {
			unsupportedCiphers = append(unsupportedCiphers, cipher)
			continue
		}

		codes = append(codes, code)
	}

	return codes, unsupportedCiphers
}
