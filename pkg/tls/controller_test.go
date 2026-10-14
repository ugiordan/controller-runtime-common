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
	"errors"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	configv1 "github.com/openshift/api/config/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// The fake clients used by the direct Reconcile tests share the suite's
// testScheme, which already has configv1 installed.

// atomicSlice provides thread-safe slice operations.
type atomicSlice[T any] struct {
	mu    sync.RWMutex
	items []T
}

func (s *atomicSlice[T]) Append(item T) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, item)
}

func (s *atomicSlice[T]) Index(i int) T {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.items[i]
}

func (s *atomicSlice[T]) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}

var _ = Describe("SecurityProfileWatcher controller", func() {
	type profileChange struct {
		old configv1.TLSProfileSpec
		new configv1.TLSProfileSpec
	}

	type adherencePolicyChange struct {
		old configv1.TLSAdherencePolicy
		new configv1.TLSAdherencePolicy
	}

	var (
		mgrCancel              context.CancelFunc
		mgrDone                chan struct{}
		mgr                    manager.Manager
		apiServer              *configv1.APIServer
		profileChanges         *atomicSlice[profileChange]
		adherencePolicyChanges *atomicSlice[adherencePolicyChange]
	)

	BeforeEach(func() {
		var err error

		// Create the APIServer object.
		apiServer = &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{
				Name: APIServerName,
			},
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{
					Type: configv1.TLSProfileIntermediateType,
				},
			},
		}
		Expect(k8sClient.Create(ctx, apiServer)).To(Succeed())

		// Create a new manager for each test.
		mgr, err = ctrl.NewManager(cfg, managerOptions)
		Expect(err).NotTo(HaveOccurred())

		// Reset callback tracking.
		profileChanges = &atomicSlice[profileChange]{}
		adherencePolicyChanges = &atomicSlice[adherencePolicyChange]{}
	})

	AfterEach(func() {
		// Stop the manager if it's running.
		if mgrCancel != nil {
			mgrCancel()
			<-mgrDone
		}

		// Clean up the APIServer object.
		Expect(k8sClient.Delete(ctx, apiServer)).To(Succeed())
	})

	startManager := func(initialProfile configv1.TLSProfileSpec, initialAdherencePolicy configv1.TLSAdherencePolicy) {
		var mgrCtx context.Context
		mgrCtx, mgrCancel = context.WithCancel(ctx)
		mgrDone = make(chan struct{})

		// Set up the TLS security profile watcher controller.
		watcher := &SecurityProfileWatcher{
			Client:                    mgr.GetClient(),
			InitialTLSProfileSpec:     initialProfile,
			InitialTLSAdherencePolicy: initialAdherencePolicy,
			OnProfileChange: func(_ context.Context, oldSpec, newSpec configv1.TLSProfileSpec) {
				profileChanges.Append(profileChange{old: oldSpec, new: newSpec})
			},
			OnAdherencePolicyChange: func(_ context.Context, oldPolicy, newPolicy configv1.TLSAdherencePolicy) {
				adherencePolicyChanges.Append(adherencePolicyChange{old: oldPolicy, new: newPolicy})
			},
		}
		Expect(watcher.SetupWithManager(mgr)).To(Succeed())

		// Start the manager in a goroutine.
		go func() {
			defer GinkgoRecover()
			defer close(mgrDone)
			err := mgr.Start(mgrCtx)
			Expect(err).NotTo(HaveOccurred())
		}()

		// Wait for the manager to be ready.
		Eventually(func() bool {
			return mgr.GetCache().WaitForCacheSync(mgrCtx)
		}).Should(BeTrue())
	}

	Context("when the TLS profile does not change", func() {
		It("should not invoke the callback", func() {
			// Start with the intermediate profile (same as what's configured).
			initialProfile, err := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
			Expect(err).NotTo(HaveOccurred())
			startManager(initialProfile, apiServer.Spec.TLSAdherence)

			// Wait a bit and verify callback was not invoked.
			Consistently(profileChanges.Len).Should(Equal(0), "callback should not be invoked")
		})

		It("should not invoke the callback when switching to custom profile with identical settings", func() {
			// Start with the intermediate profile.
			initialProfile, err := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
			Expect(err).NotTo(HaveOccurred())
			startManager(initialProfile, apiServer.Spec.TLSAdherence)

			// Get the intermediate profile spec to replicate it exactly.
			intermediateSpec := *configv1.TLSProfiles[configv1.TLSProfileIntermediateType]

			// Update the APIServer to use a custom profile with identical settings.
			apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: intermediateSpec,
				},
			}
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Verify callback was NOT invoked since settings are identical.
			Consistently(profileChanges.Len).Should(Equal(0), "callback should not be invoked for identical settings")
		})

		It("should not invoke the callback when switching from custom profile to predefined profile with identical settings", func() {
			// Get the intermediate profile spec to replicate it exactly.
			intermediateSpec := *configv1.TLSProfiles[configv1.TLSProfileIntermediateType]

			// Update the APIServer to use a custom profile with identical settings to intermediate.
			apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: intermediateSpec,
				},
			}
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Start with the custom profile.
			initialProfile, err := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
			Expect(err).NotTo(HaveOccurred())
			startManager(initialProfile, apiServer.Spec.TLSAdherence)

			// Switch to the intermediate profile (which has identical settings).
			apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileIntermediateType,
			}
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Verify callback was NOT invoked since settings are identical.
			Consistently(profileChanges.Len).Should(Equal(0), "callback should not be invoked for identical settings")
		})
	})

	Context("when the TLS profile changes", func() {
		It("should invoke the callback when MinTLSVersion changes", func() {
			// Start with the intermediate profile.
			initialProfile, err := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
			Expect(err).NotTo(HaveOccurred())
			startManager(initialProfile, apiServer.Spec.TLSAdherence)

			// Update the APIServer to use the Modern profile (which has TLS 1.3).
			apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			}
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Verify callback was invoked.
			Eventually(profileChanges.Len).Should(Equal(1), "callback should be invoked once")

			// Verify the callback received the correct profiles.
			change := profileChanges.Index(0)
			Expect(change.old).To(Equal(initialProfile), "callback should receive the initial profile as old")
			modernProfile, err := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
			Expect(err).NotTo(HaveOccurred())
			Expect(change.new).To(Equal(modernProfile), "callback should receive the current profile as new")
		})

		It("should invoke the callback when switching to custom profile with different TLS settings", func() {
			// Start with the intermediate profile.
			initialProfile, err := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
			Expect(err).NotTo(HaveOccurred())
			startManager(initialProfile, apiServer.Spec.TLSAdherence)

			// Define the custom profile we'll switch to.
			customSpec := configv1.TLSProfileSpec{
				Ciphers:       []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
				MinTLSVersion: configv1.VersionTLS13,
			}

			// Update the APIServer to use a custom profile.
			apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: customSpec,
				},
			}
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Verify callback was invoked.
			Eventually(profileChanges.Len).Should(Equal(1), "callback should be invoked once")

			// Verify the callback received the correct profiles.
			change := profileChanges.Index(0)
			Expect(change.old).To(Equal(initialProfile), "callback should receive the initial profile as old")
			Expect(change.new).To(Equal(customSpec), "callback should receive the custom profile as new")
		})

		It("should invoke the callback when switching from custom to predefined profile with different TLS settings", func() {
			// Update the APIServer to use a custom profile first.
			apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers:       []string{"TLS_AES_128_GCM_SHA256"},
						MinTLSVersion: configv1.VersionTLS13,
					},
				},
			}
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Start with the custom profile.
			initialProfile, err := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
			Expect(err).NotTo(HaveOccurred())
			startManager(initialProfile, apiServer.Spec.TLSAdherence)

			// Switch back to the intermediate profile.
			apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileIntermediateType,
			}
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Verify callback was invoked.
			Eventually(profileChanges.Len).Should(Equal(1), "callback should be invoked once")
		})

		It("should invoke the callback twice when profile changes from A to B and back to A", func() {
			// Start with the intermediate profile (profile A).
			initialProfile, err := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
			Expect(err).NotTo(HaveOccurred())
			startManager(initialProfile, apiServer.Spec.TLSAdherence)

			// Change from A (Intermediate) to B (Modern).
			apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			}
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Wait for the first callback.
			Eventually(profileChanges.Len).Should(Equal(1), "callback should be invoked once after A -> B")

			// Change from B (Modern) back to A (Intermediate).
			apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileIntermediateType,
			}
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Wait for the second callback.
			Eventually(profileChanges.Len).Should(Equal(2), "callback should be invoked twice after A -> B -> A")

			// Verify the captured changes are correct.
			intermediateProfile, err := GetTLSProfileSpec(&configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType})
			Expect(err).NotTo(HaveOccurred())
			modernProfile, err := GetTLSProfileSpec(&configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType})
			Expect(err).NotTo(HaveOccurred())

			// First change: Intermediate -> Modern.
			firstChange := profileChanges.Index(0)
			Expect(firstChange.old).To(Equal(intermediateProfile), "first change should have Intermediate as old")
			Expect(firstChange.new).To(Equal(modernProfile), "first change should have Modern as new")

			// Second change: Modern -> Intermediate.
			secondChange := profileChanges.Index(1)
			Expect(secondChange.old).To(Equal(modernProfile), "second change should have Modern as old")
			Expect(secondChange.new).To(Equal(intermediateProfile), "second change should have Intermediate as new")
		})
	})

	Context("when the profile is nil initially", func() {
		It("should use the default profile and invoke the callback when changes are detected", func() {
			// Update APIServer to have nil profile.
			apiServer.Spec.TLSSecurityProfile = nil
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Start with the default (nil -> intermediate) profile.
			initialProfile, err := GetTLSProfileSpec(nil)
			Expect(err).NotTo(HaveOccurred())
			startManager(initialProfile, apiServer.Spec.TLSAdherence)

			// Update the APIServer to use the Modern profile.
			apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			}
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Verify callback was invoked.
			Eventually(profileChanges.Len).Should(Equal(1), "callback should be invoked once")
		})
	})

	Context("when the TLS adherence policy changes", func() {
		It("should invoke the callback when policy changes", func() {
			// Start with the intermediate profile.
			initialProfile, err := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
			Expect(err).NotTo(HaveOccurred())
			startManager(initialProfile, apiServer.Spec.TLSAdherence)

			// Update the APIServer to use a different adherence policy.
			apiServer.Spec.TLSAdherence = configv1.TLSAdherencePolicyStrictAllComponents
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Verify callback was invoked.
			Eventually(adherencePolicyChanges.Len).Should(Equal(1), "callback should be invoked once")

			// Verify the callback received the correct policies.
			change := adherencePolicyChanges.Index(0)
			Expect(change.old).To(Equal(configv1.TLSAdherencePolicyNoOpinion), "callback should receive the initial policy as old")
			Expect(change.new).To(Equal(configv1.TLSAdherencePolicyStrictAllComponents), "callback should receive the current policy as new")
		})
	})

	Context("when the APIServer read fails", func() {
		type readErrorCase struct {
			readErr          error
			expectRetryError bool
		}

		DescribeTable("handling read errors with a fatal callback set",
			func(c readErrorCase) {
				fatalCalls := &atomicSlice[error]{}
				watcher := &SecurityProfileWatcher{
					Client: fake.NewClientBuilder().WithScheme(testScheme).WithInterceptorFuncs(interceptor.Funcs{
						Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
							return c.readErr
						},
					}).Build(),
					OnFatalReadError: func(_ context.Context, readErr error) {
						fatalCalls.Append(readErr)
					},
				}

				_, err := watcher.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: APIServerName}})

				if c.expectRetryError {
					Expect(err).To(HaveOccurred(), "non-authorization errors must stay retryable")
					Expect(fatalCalls.Len()).To(Equal(0), "fatal callback must not run for retryable errors")
					return
				}
				Expect(err).NotTo(HaveOccurred(), "authorization errors with a fatal callback must not be retried")
				Expect(fatalCalls.Len()).To(Equal(1), "fatal callback must run exactly once")
				Expect(fatalCalls.Index(0)).To(MatchError(c.readErr))
			},
			Entry("forbidden invokes the fatal callback", readErrorCase{
				readErr: apierrors.NewForbidden(
					schema.GroupResource{Group: "config.openshift.io", Resource: "apiservers"}, "cluster", errors.New("denied")),
			}),
			Entry("unauthorized invokes the fatal callback", readErrorCase{
				readErr: apierrors.NewUnauthorized("denied"),
			}),
			Entry("server timeout stays retryable", readErrorCase{
				readErr: apierrors.NewServerTimeout(
					schema.GroupResource{Group: "config.openshift.io", Resource: "apiservers"}, "get", 1),
				expectRetryError: true,
			}),
			Entry("service unavailable stays retryable", readErrorCase{
				readErr:          apierrors.NewServiceUnavailable("temporarily unavailable"),
				expectRetryError: true,
			}),
		)

		It("should keep returning authorization errors for retry when no fatal callback is set", func() {
			watcher := &SecurityProfileWatcher{
				Client: fake.NewClientBuilder().WithScheme(testScheme).WithInterceptorFuncs(interceptor.Funcs{
					Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
						return apierrors.NewForbidden(
							schema.GroupResource{Group: "config.openshift.io", Resource: "apiservers"}, "cluster", errors.New("denied"))
					},
				}).Build(),
			}

			_, err := watcher.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: APIServerName}})
			Expect(err).To(HaveOccurred(), "default behavior without a callback is retry")
		})
	})
})
