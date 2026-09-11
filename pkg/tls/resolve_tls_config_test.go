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

package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	configv1 "github.com/openshift/api/config/v1"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type getErrorClient struct {
	client.Client
	err error
}

func (c getErrorClient) Get(_ context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	return c.err
}

var _ = Describe("ResolveTLSConfig", Label("apigroup:config.openshift.io"), func() {
	var (
		testCtx       context.Context
		cancelTestCtx context.CancelFunc
	)

	BeforeEach(func() {
		testCtx, cancelTestCtx = context.WithTimeout(ctx, 10*time.Second)
		deleteAPIServer := &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: APIServerName},
		}
		err := k8sClient.Delete(testCtx, deleteAPIServer)
		Expect(err == nil || apierrors.IsNotFound(err)).To(BeTrue(), "deleting APIServer %q before the test", APIServerName)
	})

	AfterEach(func() {
		defer cancelTestCtx()
		cleanupCtx, cancelCleanupCtx := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelCleanupCtx()

		deleteAPIServer := &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: APIServerName},
		}
		err := k8sClient.Delete(cleanupCtx, deleteAPIServer)
		Expect(err == nil || apierrors.IsNotFound(err)).To(BeTrue(), "deleting APIServer %q after the test", APIServerName)
	})

	It("falls back to the default profile when the APIServer resource is unavailable", func() {
		result, err := ResolveTLSConfig(testCtx, cfg)

		Expect(err).NotTo(HaveOccurred(), "resolving TLS configuration without an APIServer resource")
		Expect(result).NotTo(BeNil(), "resolver should return a result when the APIServer resource is unavailable")
		Expect(result.TLSConfig).NotTo(BeNil(), "resolver should return a TLS configuration function")
		Expect(result.ProfileSpec).To(Equal(*configv1.TLSProfiles[configv1.TLSProfileIntermediateType]), "fallback profile should be the Intermediate profile")
		Expect(result.AdherencePolicy).To(Equal(configv1.TLSAdherencePolicyNoOpinion), "fallback adherence policy should be NoOpinion")
		Expect(result.APIServerAvailable).To(BeTrue(), "a missing APIServer singleton should still register a watcher for recovery")

		tlsConfig := &tls.Config{}
		result.TLSConfig(tlsConfig)
		Expect(tlsConfig.MinVersion).To(Equal(libgocrypto.TLSVersionOrDie(string(configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion))), "fallback should apply the Intermediate minimum TLS version")
	})

	It("uses the Old cluster profile under strict adherence", func() {
		apiServer := &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: APIServerName},
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType},
				TLSAdherence:       configv1.TLSAdherencePolicyStrictAllComponents,
			},
		}
		Expect(k8sClient.Create(testCtx, apiServer)).To(Succeed(), "creating an APIServer with strict Old TLS adherence")

		result, err := ResolveTLSConfig(testCtx, cfg)
		Expect(err).NotTo(HaveOccurred(), "resolving TLS configuration with strict adherence")
		Expect(result.ProfileSpec).To(Equal(*configv1.TLSProfiles[configv1.TLSProfileOldType]), "resolved profile should be the cluster Old profile")
		Expect(result.AdherencePolicy).To(Equal(configv1.TLSAdherencePolicyStrictAllComponents), "resolved adherence policy should be StrictAllComponents")
		Expect(result.APIServerAvailable).To(BeTrue(), "the available APIServer should register a watcher")

		tlsConfig := &tls.Config{}
		result.TLSConfig(tlsConfig)
		Expect(tlsConfig.MinVersion).To(Equal(libgocrypto.TLSVersionOrDie(string(configv1.TLSProfiles[configv1.TLSProfileOldType].MinTLSVersion))), "strict adherence should preserve the Old minimum TLS version")
	})

	It("uses a custom profile with a legacy TLS version under strict adherence", func() {
		customProfile := configv1.TLSProfileSpec{
			Ciphers:       []string{"AES128-SHA"},
			MinTLSVersion: configv1.VersionTLS11,
		}
		apiServer := &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: APIServerName},
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{
					Type: configv1.TLSProfileCustomType,
					Custom: &configv1.CustomTLSProfile{
						TLSProfileSpec: customProfile,
					},
				},
				TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
			},
		}
		Expect(k8sClient.Create(testCtx, apiServer)).To(Succeed(), "creating an APIServer with a legacy custom TLS profile")

		result, err := ResolveTLSConfig(testCtx, cfg)
		Expect(err).NotTo(HaveOccurred(), "resolving TLS configuration with a legacy custom profile")
		Expect(result.ProfileSpec).To(Equal(customProfile), "resolved profile should match the cluster custom profile")
		Expect(result.APIServerAvailable).To(BeTrue(), "the available APIServer should register a watcher")

		tlsConfig := &tls.Config{}
		result.TLSConfig(tlsConfig)
		Expect(tlsConfig.MinVersion).To(Equal(libgocrypto.TLSVersionOrDie(string(customProfile.MinTLSVersion))), "strict adherence should preserve the custom minimum TLS version")
		Expect(tlsConfig.CipherSuites).To(ContainElement(tls.TLS_RSA_WITH_AES_128_CBC_SHA), "strict adherence should preserve the configured legacy cipher")
	})

	It("uses the default profile when adherence is NoOpinion", func() {
		apiServer := &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: APIServerName},
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType},
			},
		}
		Expect(k8sClient.Create(testCtx, apiServer)).To(Succeed(), "creating an APIServer with NoOpinion TLS adherence")

		result, err := ResolveTLSConfig(testCtx, cfg)
		Expect(err).NotTo(HaveOccurred(), "resolving TLS configuration with NoOpinion adherence")
		Expect(result.ProfileSpec).To(Equal(*configv1.TLSProfiles[configv1.TLSProfileOldType]), "resolved metadata should preserve the cluster profile")
		Expect(result.AdherencePolicy).To(Equal(configv1.TLSAdherencePolicyNoOpinion), "resolved adherence policy should be NoOpinion")
		Expect(result.APIServerAvailable).To(BeTrue(), "the available APIServer should register a watcher")

		tlsConfig := &tls.Config{}
		result.TLSConfig(tlsConfig)
		Expect(tlsConfig.MinVersion).To(Equal(libgocrypto.TLSVersionOrDie(string(configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion))), "NoOpinion adherence should apply the Intermediate minimum TLS version")
	})

	It("uses the default profile when adherence is LegacyAdheringComponentsOnly", func() {
		apiServer := &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: APIServerName},
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType},
				TLSAdherence:       configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly,
			},
		}
		Expect(k8sClient.Create(testCtx, apiServer)).To(Succeed(), "creating an APIServer with legacy TLS adherence")

		result, err := ResolveTLSConfig(testCtx, cfg)
		Expect(err).NotTo(HaveOccurred(), "resolving TLS configuration with legacy adherence")
		Expect(result.AdherencePolicy).To(Equal(configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly), "resolved adherence policy should be LegacyAdheringComponentsOnly")
		Expect(result.APIServerAvailable).To(BeTrue(), "the available APIServer should register a watcher")

		tlsConfig := &tls.Config{}
		result.TLSConfig(tlsConfig)
		Expect(tlsConfig.MinVersion).To(Equal(libgocrypto.TLSVersionOrDie(string(configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion))), "legacy adherence should apply the Intermediate minimum TLS version")
	})

	It("uses a custom profile when adherence is StrictAllComponents", func() {
		customProfile := configv1.TLSProfileSpec{
			Ciphers:       []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			MinTLSVersion: configv1.VersionTLS13,
		}
		apiServer := &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: APIServerName},
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{
					Type: configv1.TLSProfileCustomType,
					Custom: &configv1.CustomTLSProfile{
						TLSProfileSpec: customProfile,
					},
				},
				TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
			},
		}
		Expect(k8sClient.Create(testCtx, apiServer)).To(Succeed(), "creating an APIServer with a strict custom TLS profile")

		result, err := ResolveTLSConfig(testCtx, cfg)
		Expect(err).NotTo(HaveOccurred(), "resolving TLS configuration with a strict custom profile")
		Expect(result.ProfileSpec).To(Equal(customProfile), "resolved profile should match the cluster custom profile")
		Expect(result.APIServerAvailable).To(BeTrue(), "the available APIServer should register a watcher")

		tlsConfig := &tls.Config{}
		result.TLSConfig(tlsConfig)
		Expect(tlsConfig.MinVersion).To(Equal(uint16(tls.VersionTLS13)), "custom profile should set the configured TLS 1.3 minimum")
		Expect(tlsConfig.CipherSuites).To(BeNil(), "TLS 1.3 cipher suites should remain managed by Go")
	})

	It("preserves an observed malformed profile while applying the default profile", func() {
		malformedProfile := configv1.TLSProfileSpec{
			Ciphers:       []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			MinTLSVersion: configv1.TLSProtocolVersion("VersionTLS99"),
		}
		apiServer := &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: APIServerName},
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{
					Type: configv1.TLSProfileCustomType,
					Custom: &configv1.CustomTLSProfile{
						TLSProfileSpec: malformedProfile,
					},
				},
				TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
			},
		}
		fakeClient := clientfake.NewClientBuilder().WithScheme(testScheme).WithObjects(apiServer).Build()

		result, err := resolveTLSConfig(testCtx, fakeClient)
		Expect(err).NotTo(HaveOccurred(), "resolving TLS configuration with a malformed minimum version")
		Expect(result.ProfileSpec).To(Equal(malformedProfile), "watcher state should preserve the observed malformed profile")
		Expect(result.APIServerAvailable).To(BeTrue(), "the APIServer object was available")

		tlsConfig := &tls.Config{}
		result.TLSConfig(tlsConfig)
		Expect(tlsConfig.MinVersion).To(Equal(libgocrypto.TLSVersionOrDie(string(configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion))), "malformed profile should use the default minimum TLS version")
	})
})

var _ = Describe("ResolveTLSConfig APIServer errors", func() {
	newErrorClient := func(err error) client.Client {
		return getErrorClient{
			Client: clientfake.NewClientBuilder().WithScheme(testScheme).Build(),
			err:    err,
		}
	}

	It("falls back for missing and transient APIServer errors", func() {
		resource := schema.GroupVersionResource{
			Group: "config.openshift.io", Version: "v1", Resource: "apiservers",
		}
		testCases := []struct {
			name      string
			err       error
			available bool
		}{
			{name: "no match", err: &meta.NoResourceMatchError{PartialResource: resource}},
			{name: "not found", err: apierrors.NewNotFound(schema.GroupResource{Group: resource.Group, Resource: resource.Resource}, APIServerName), available: true},
			{name: "service unavailable", err: apierrors.NewServiceUnavailable("unavailable"), available: true},
			{name: "timeout", err: apierrors.NewTimeoutError("timeout", 1), available: true},
			{name: "too many requests", err: apierrors.NewTooManyRequests("busy", 1), available: true},
			{name: "deadline exceeded", err: context.DeadlineExceeded, available: true},
		}

		for _, testCase := range testCases {
			result, err := resolveTLSConfig(context.Background(), newErrorClient(testCase.err))
			Expect(err).NotTo(HaveOccurred(), testCase.name)
			Expect(result).NotTo(BeNil(), testCase.name)
			Expect(result.APIServerAvailable).To(Equal(testCase.available), testCase.name)
		}
	})

	It("returns errors for forbidden and unexpected APIServer failures", func() {
		resource := schema.GroupResource{Group: "config.openshift.io", Resource: "apiservers"}
		testCases := []struct {
			name string
			err  error
		}{
			{name: "forbidden", err: apierrors.NewForbidden(resource, APIServerName, errors.New("forbidden"))},
			{name: "unauthorized", err: apierrors.NewUnauthorized("unauthorized")},
			{name: "internal error", err: apierrors.NewInternalError(errors.New("internal error"))},
		}

		for _, testCase := range testCases {
			result, err := resolveTLSConfig(context.Background(), newErrorClient(testCase.err))
			Expect(err).To(HaveOccurred(), testCase.name)
			Expect(result).To(BeNil(), testCase.name)
		}
	})
})
